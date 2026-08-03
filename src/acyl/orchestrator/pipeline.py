"""Stage handlers and DAG advancement for the multi-agent scan pipeline."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acyl.cartographer import write_security_map
from acyl.detectors.antares import run_antares_localization
from acyl.detectors.codeguard import detect_codeguard_presence
from acyl.detectors.sca import detect_sca
from acyl.detectors.sca_goals import synthesize_sca_antares_goals
from acyl.detectors.secrets import detect_secrets
from acyl.indexer import build_index
from acyl.orchestrator.config import (
    DETECTOR_ROLES,
    PRIORITY,
    ROLE_CARTOGRAPHER,
    ROLE_DETECTOR_ANTARES,
    ROLE_DETECTOR_CODEGUARD,
    ROLE_DETECTOR_CODEGUARD_LLM,
    ROLE_DETECTOR_SCA,
    ROLE_DETECTOR_SECRETS,
    ROLE_INDEXER,
    ROLE_REPORTER,
    ROLE_TRIAGER,
)
from acyl.paths import runs_dir
from acyl.reporter import write_reports
from acyl.scan_control import ScanCancelled
from acyl.substrate import Store
from acyl.target import Target
from acyl.triager import triage_run
from acyl.triager.triage import llm_codeguard_sweep

ProgressFn = Callable[..., None]


@dataclass
class PipelineContext:
    store: Store
    run_id: str
    target: Target
    artifacts: Path
    report_dir: Path
    enable_antares: bool
    enable_llm_codeguard: bool
    use_docker: bool | None
    include_candidates: bool
    cancel_check: Callable[[], None]
    on_progress: ProgressFn | None = None
    counts: dict[str, Any] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    index_files: list[dict[str, Any]] = field(default_factory=list)

    def progress(self, phase: str, message: str, **extra: Any) -> None:
        if self.on_progress is None:
            return
        self.on_progress(phase, message, **extra)

    def set_count(self, key: str, value: Any) -> None:
        with self.lock:
            self.counts[key] = value

    def add_count(self, key: str, value: int) -> None:
        with self.lock:
            self.counts[key] = int(self.counts.get(key) or 0) + value


def seed_pipeline(ctx: PipelineContext) -> None:
    """Enqueue the indexer; later stages are advanced as prior work closes."""
    with ctx.lock:
        ctx.counts.update(
            {
                "goals_source": ctx.target.goals_source,
                "goals_count": len(ctx.target.goals),
                "secrets": 0,
                "sca": 0,
                "sca_antares": 0,
                "codeguard": 0,
                "antares": 0,
                "codeguard_llm": 0,
            }
        )
    ctx.store.add_task(
        ctx.run_id,
        ROLE_INDEXER,
        payload={},
        priority=PRIORITY[ROLE_INDEXER],
    )


def advance_after(ctx: PipelineContext, completed_role: str) -> None:
    """Enqueue dependent stages when barriers clear.

    Uses DB-level ``add_task_if_absent`` so concurrent detector workers cannot
    double-enqueue triage/reporter without holding ``ctx.lock`` across store I/O
    (avoids lock-order deadlocks with Store._lock).
    """
    store = ctx.store
    run_id = ctx.run_id

    if completed_role == ROLE_INDEXER:
        store.add_task_if_absent(
            run_id,
            ROLE_CARTOGRAPHER,
            payload={},
            priority=PRIORITY[ROLE_CARTOGRAPHER],
        )
        return

    if completed_role == ROLE_CARTOGRAPHER:
        _enqueue_detectors(ctx)
        return

    if completed_role.startswith("detector."):
        if not store.has_incomplete_tasks(run_id, roles=list(DETECTOR_ROLES)):
            store.add_task_if_absent(
                run_id,
                ROLE_TRIAGER,
                payload={},
                priority=PRIORITY[ROLE_TRIAGER],
            )
        return

    if completed_role == ROLE_TRIAGER:
        store.add_task_if_absent(
            run_id,
            ROLE_REPORTER,
            payload={},
            priority=PRIORITY[ROLE_REPORTER],
        )


def _role_enqueued(store: Store, run_id: str, role: str) -> bool:
    return any(t["role"] == role for t in store.list_tasks(run_id))


def _enqueue_detectors(ctx: PipelineContext) -> None:
    store = ctx.store
    run_id = ctx.run_id
    # Seed once (cartographer is single-worker); secrets row is the sentinel.
    if _role_enqueued(store, run_id, ROLE_DETECTOR_SECRETS):
        return
    store.add_task(
        run_id,
        ROLE_DETECTOR_SECRETS,
        payload={},
        priority=PRIORITY[ROLE_DETECTOR_SECRETS],
    )
    store.add_task(
        run_id,
        ROLE_DETECTOR_SCA,
        payload={},
        priority=PRIORITY[ROLE_DETECTOR_SCA],
    )
    store.add_task(
        run_id,
        ROLE_DETECTOR_CODEGUARD,
        payload={},
        priority=PRIORITY[ROLE_DETECTOR_CODEGUARD],
    )
    if ctx.enable_antares:
        goals = [
            g
            for g in ctx.target.goals
            if g.get("cwe") or "cwe" in (g.get("title") or "").lower() or g.get("body")
        ]
        total = len(goals)
        for idx, goal in enumerate(goals, start=1):
            store.add_task(
                run_id,
                ROLE_DETECTOR_ANTARES,
                payload={"goal": goal, "index": idx, "total": total},
                priority=PRIORITY[ROLE_DETECTOR_ANTARES],
            )
    if ctx.enable_llm_codeguard:
        store.add_task(
            run_id,
            ROLE_DETECTOR_CODEGUARD_LLM,
            payload={},
            priority=PRIORITY[ROLE_DETECTOR_CODEGUARD_LLM],
        )


def handle_task(ctx: PipelineContext, task: dict[str, Any]) -> None:
    role = task["role"]
    payload = task.get("payload") or {}
    ctx.cancel_check()

    if role == ROLE_INDEXER:
        ctx.progress("index", "Indexing repository…")
        index = build_index(ctx.target.path, ctx.target.scope)
        (ctx.artifacts / "index.json").write_text(
            json.dumps(index.to_dict(), indent=2), encoding="utf-8"
        )
        with ctx.lock:
            ctx.index_files = list(index.to_dict()["files"])
        return

    if role == ROLE_CARTOGRAPHER:
        ctx.progress("cartographer", "Writing security map…")
        index_path = ctx.artifacts / "index.json"
        data = json.loads(index_path.read_text(encoding="utf-8"))
        from acyl.indexer.index import FileInfo, Index

        index = Index(
            root=Path(data["root"]),
            files=[
                FileInfo(
                    path=f["path"],
                    language=f["language"],
                    size=int(f["size"]),
                    symbols=list(f.get("symbols") or []),
                )
                for f in data["files"]
            ],
            languages=data.get("languages") or {},
        )
        write_security_map(index, ctx.artifacts / "security-map.md")
        with ctx.lock:
            ctx.index_files = list(data["files"])
        return

    if role == ROLE_DETECTOR_SECRETS:
        ctx.progress("secrets", "Scanning for secrets…")
        n = detect_secrets(ctx.store, ctx.run_id, ctx.target.path)
        ctx.set_count("secrets", n)
        return

    if role == ROLE_DETECTOR_SCA:
        ctx.progress("sca", "Scanning dependencies (SCA)…")
        n = detect_sca(ctx.store, ctx.run_id, ctx.target.path)
        ctx.set_count("sca", n)
        # Additive CVE→Antares: enqueue high/critical advisory goals before
        # this task closes so the detector barrier includes them.
        if ctx.enable_antares:
            goals = synthesize_sca_antares_goals(ctx.store.list_findings(ctx.run_id))
            total = len(goals)
            for idx, goal in enumerate(goals, start=1):
                ctx.store.add_task(
                    ctx.run_id,
                    ROLE_DETECTOR_ANTARES,
                    payload={"goal": goal, "index": idx, "total": total, "origin": "sca"},
                    priority=PRIORITY[ROLE_DETECTOR_ANTARES],
                )
            ctx.set_count("sca_antares", total)
            if total:
                ctx.progress(
                    "sca_antares",
                    f"Enqueued {total} high/critical SCA Antares goal(s)…",
                    current=total,
                    total=total,
                )
        return

    if role == ROLE_DETECTOR_CODEGUARD:
        ctx.progress("codeguard", "Running CodeGuard presence sweep…")
        n = detect_codeguard_presence(ctx.store, ctx.run_id, ctx.target.path)
        ctx.set_count("codeguard", n)
        return

    if role == ROLE_DETECTOR_ANTARES:
        goal = payload.get("goal") or {}
        idx = int(payload.get("index") or 1)
        total = int(payload.get("total") or 1)
        goal_label = str(goal.get("id") or goal.get("cwe") or goal.get("title") or idx)
        ctx.progress(
            "antares",
            f"Antares localizing {goal_label} ({idx}/{total})…",
            current=idx,
            total=total,
            goal=goal_label,
        )
        n = run_antares_localization(
            ctx.store,
            ctx.run_id,
            ctx.target.path,
            goal,
            artifacts=ctx.artifacts,
            use_docker=ctx.use_docker,
            cancel_check=ctx.cancel_check,
        )
        ctx.add_count("antares", n)
        return

    if role == ROLE_DETECTOR_CODEGUARD_LLM:
        ctx.progress("codeguard_llm", "Running CodeGuard LLM sweep…")
        with ctx.lock:
            files = list(ctx.index_files)
        if not files:
            index_path = ctx.artifacts / "index.json"
            if index_path.is_file():
                files = json.loads(index_path.read_text(encoding="utf-8")).get("files") or []
        n = llm_codeguard_sweep(ctx.store, ctx.run_id, ctx.target.path, files)
        ctx.set_count("codeguard_llm", n)
        return

    if role == ROLE_TRIAGER:
        ctx.progress("triage", "Triaging findings…")
        counts = triage_run(ctx.store, ctx.run_id, ctx.target.path)
        ctx.set_count("triage", counts)
        return

    if role == ROLE_REPORTER:
        ctx.progress("report", "Writing reports…")
        paths = write_reports(
            ctx.store,
            ctx.run_id,
            ctx.report_dir,
            include_candidates=ctx.include_candidates,
        )
        ctx.set_count("report", {k: str(v) for k, v in paths.items()})
        with ctx.lock:
            counts_snap = dict(ctx.counts)
        (runs_dir() / ctx.run_id / "manifest.json").write_text(
            json.dumps(
                {
                    "run_id": ctx.run_id,
                    "target": str(ctx.target.path),
                    "revision": ctx.target.pinned_revision,
                    "goals_source": ctx.target.goals_source,
                    "counts": counts_snap,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        ctx.progress("done", "Scan complete")
        return

    raise ValueError(f"Unknown pipeline role: {role}")


def run_task_safely(ctx: PipelineContext, task: dict[str, Any]) -> None:
    """Execute a claimed task, then complete/release and advance the DAG."""
    task_id = task["id"]
    role = task["role"]
    try:
        handle_task(ctx, task)
        ctx.store.complete_task(task_id)
        advance_after(ctx, role)
    except ScanCancelled:
        ctx.store.release_task(task_id, reason="cancelled")
        raise
    except Exception:
        ctx.store.release_task(task_id, reason="handler-error")
        raise
