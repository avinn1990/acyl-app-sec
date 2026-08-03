"""Orchestrator: multi-agent scan pipeline over the Foundry task queue."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from acyl.autofix.fix import autofix_finding
from acyl.orchestrator.pipeline import PipelineContext, seed_pipeline
from acyl.orchestrator.workers import run_worker_pool
from acyl.paths import runs_dir
from acyl.scan_control import ScanCancelled, make_cancel_check
from acyl.substrate import Store
from acyl.target import Target, prepare_target


@dataclass
class ScanResult:
    run_id: str
    db_path: Path
    report_dir: Path
    counts: dict[str, Any]
    goals_source: str = ""


def run_scan(
    *,
    path: Path | None = None,
    git_url: str | None = None,
    goals_file: Path | None = None,
    revision: str | None = None,
    enable_antares: bool = True,
    enable_llm_codeguard: bool = False,
    use_docker: bool | None = None,
    include_candidates: bool = False,
    cancel_event: threading.Event | None = None,
    on_run_created: Callable[[str], None] | None = None,
    on_progress: Callable[[dict[str, Any]], None] | None = None,
) -> ScanResult:
    def progress(phase: str, message: str, **extra: Any) -> None:
        if on_progress is None:
            return
        payload: dict[str, Any] = {"phase": phase, "message": message, **extra}
        on_progress(payload)

    target: Target = prepare_target(
        path=path,
        git_url=git_url,
        goals_file=goals_file,
        revision=revision,
    )
    run_id_holder: list[str | None] = [None]
    check = make_cancel_check(cancel_event, run_id_holder)
    check()

    tmp_store_path = runs_dir() / "_tmp.db"
    if tmp_store_path.exists():
        tmp_store_path.unlink()
    store = Store(tmp_store_path)
    run_id = store.create_run(
        target_path=str(target.path),
        pinned_revision=target.pinned_revision,
        scope=target.scope,
        goals=target.goals,
        git_url=target.git_url,
    )
    run_id_holder[0] = run_id
    if on_run_created is not None:
        on_run_created(run_id)
    report_dir = runs_dir() / run_id / "reports"
    artifacts = runs_dir() / run_id / "artifacts"
    db_path = runs_dir() / run_id / "acyl.db"
    report_dir.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    store.close()
    tmp_store_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_store_path.replace(db_path)
    store = Store(db_path)

    try:
        check()
        ctx = PipelineContext(
            store=store,
            run_id=run_id,
            target=target,
            artifacts=artifacts,
            report_dir=report_dir,
            enable_antares=enable_antares,
            enable_llm_codeguard=enable_llm_codeguard,
            use_docker=use_docker,
            include_candidates=include_candidates,
            cancel_check=check,
            on_progress=progress,
        )
        seed_pipeline(ctx)
        counts = run_worker_pool(ctx)
        return ScanResult(
            run_id=run_id,
            db_path=db_path,
            report_dir=report_dir,
            counts=counts,
            goals_source=target.goals_source,
        )
    except ScanCancelled:
        store.set_run_state(run_id, "cancelled")
        raise
    finally:
        store.close()


def fix_from_run(run_id: str, finding_id: str, *, offline: bool = False) -> Any:
    db_path = runs_dir() / run_id / "acyl.db"
    store = Store(db_path)
    try:
        return autofix_finding(store, finding_id, offline=offline)
    finally:
        store.close()
