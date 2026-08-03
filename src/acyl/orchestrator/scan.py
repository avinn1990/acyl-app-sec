"""Orchestrator: end-to-end scan pipeline."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from acyl.autofix.fix import autofix_finding
from acyl.cartographer import write_security_map
from acyl.detectors.antares import run_antares_localization
from acyl.detectors.codeguard import detect_codeguard_presence
from acyl.detectors.sca import detect_sca
from acyl.detectors.secrets import detect_secrets
from acyl.indexer import build_index
from acyl.paths import runs_dir
from acyl.reporter import write_reports
from acyl.scan_control import ScanCancelled, make_cancel_check
from acyl.substrate import Store
from acyl.target import Target, prepare_target
from acyl.triager import triage_run
from acyl.triager.triage import llm_codeguard_sweep


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
) -> ScanResult:
    target: Target = prepare_target(
        path=path,
        git_url=git_url,
        goals_file=goals_file,
        revision=revision,
    )
    run_id_holder: list[str | None] = [None]
    check = make_cancel_check(cancel_event, run_id_holder)
    check()

    # create store first with temp then move under run id
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
        index = build_index(target.path, target.scope)
        (artifacts / "index.json").write_text(json.dumps(index.to_dict(), indent=2), encoding="utf-8")
        write_security_map(index, artifacts / "security-map.md")

        counts: dict[str, Any] = {
            "goals_source": target.goals_source,
            "goals_count": len(target.goals),
        }
        check()
        counts["secrets"] = detect_secrets(store, run_id, target.path)
        check()
        counts["sca"] = detect_sca(store, run_id, target.path)
        check()
        counts["codeguard"] = detect_codeguard_presence(store, run_id, target.path)

        if enable_antares:
            antares_hits = 0
            for goal in target.goals:
                check()
                if goal.get("cwe") or "cwe" in (goal.get("title") or "").lower() or goal.get("body"):
                    antares_hits += run_antares_localization(
                        store,
                        run_id,
                        target.path,
                        goal,
                        artifacts=artifacts,
                        use_docker=use_docker,
                        cancel_check=check,
                    )
            counts["antares"] = antares_hits
        else:
            counts["antares"] = 0

        check()
        if enable_llm_codeguard:
            counts["codeguard_llm"] = llm_codeguard_sweep(
                store,
                run_id,
                target.path,
                index.to_dict()["files"],
            )
        else:
            counts["codeguard_llm"] = 0

        check()
        counts["triage"] = triage_run(store, run_id, target.path)
        check()
        paths = write_reports(
            store,
            run_id,
            report_dir,
            include_candidates=include_candidates,
        )
        counts["report"] = {k: str(v) for k, v in paths.items()}
        # Persist a small run manifest
        (runs_dir() / run_id / "manifest.json").write_text(
            json.dumps(
                {
                    "run_id": run_id,
                    "target": str(target.path),
                    "revision": target.pinned_revision,
                    "goals_source": target.goals_source,
                    "counts": counts,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
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
