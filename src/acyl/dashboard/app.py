"""Local web dashboard for acyl (binds to localhost by default)."""

from __future__ import annotations

import json
import threading
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from acyl.autofix.fix import autofix_finding
from acyl.orchestrator.scan import run_scan
from acyl.paths import runs_dir
from acyl.substrate import Store

STATIC_DIR = Path(__file__).with_name("static")

# In-memory scan job tracker (single-operator local tool)
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()


class ScanRequest(BaseModel):
    path: str | None = None
    git_url: str | None = None
    goals: str | None = None
    revision: str | None = None
    no_antares: bool = False
    no_docker: bool = True
    llm_codeguard: bool = False


class FixRequest(BaseModel):
    run_id: str
    offline: bool = True


def _list_run_dirs() -> list[Path]:
    root = runs_dir()
    if not root.is_dir():
        return []
    return sorted(
        [p for p in root.glob("run_*") if (p / "acyl.db").is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )


def _run_summary(run_dir: Path) -> dict[str, Any]:
    store = Store(run_dir / "acyl.db")
    try:
        run = store.get_run(run_dir.name) or {}
        findings = store.list_findings(run_dir.name)
        by_state = Counter(f["state"] for f in findings)
        by_sev = Counter((f.get("severity") or "unknown") for f in findings if f["state"] == "confirmed")
        manifest = {}
        man_path = run_dir / "manifest.json"
        if man_path.is_file():
            try:
                manifest = json.loads(man_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                manifest = {}
        return {
            "id": run_dir.name,
            "target_path": run.get("target_path"),
            "pinned_revision": run.get("pinned_revision"),
            "git_url": run.get("git_url"),
            "state": run.get("state"),
            "created_at": run.get("created_at"),
            "updated_at": run.get("updated_at"),
            "finding_counts": dict(by_state),
            "confirmed_by_severity": dict(by_sev),
            "total_findings": len(findings),
            "confirmed": by_state.get("confirmed", 0),
            "needs_review": by_state.get("needs-review", 0),
            "has_report": (run_dir / "reports" / "summary.md").is_file(),
            "manifest_counts": manifest.get("counts"),
        }
    finally:
        store.close()


def build_dashboard_app() -> FastAPI:
    app = FastAPI(title="acyl dashboard", version="0.1.0")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"ok": "true", "service": "acyl-dashboard"}

    @app.get("/api/runs")
    def api_runs() -> list[dict[str, Any]]:
        return [_run_summary(p) for p in _list_run_dirs()]

    @app.get("/api/runs/{run_id}")
    def api_run(run_id: str) -> dict[str, Any]:
        run_dir = runs_dir() / run_id
        if not (run_dir / "acyl.db").is_file():
            raise HTTPException(404, "run not found")
        summary = _run_summary(run_dir)
        store = Store(run_dir / "acyl.db")
        try:
            summary["coverage"] = store.list_coverage(run_id)
            summary["rule_gaps"] = store.list_rule_gaps(run_id)
            goals = []
            run = store.get_run(run_id)
            if run:
                try:
                    goals = json.loads(run.get("goals_json") or "[]")
                except json.JSONDecodeError:
                    goals = []
            summary["goals"] = goals
        finally:
            store.close()
        return summary

    @app.get("/api/runs/{run_id}/findings")
    def api_findings(run_id: str, state: str | None = None) -> list[dict[str, Any]]:
        db = runs_dir() / run_id / "acyl.db"
        if not db.is_file():
            raise HTTPException(404, "run not found")
        store = Store(db)
        try:
            rows = store.list_findings(run_id, state=state)
            out = []
            for f in rows:
                item = dict(f)
                try:
                    item["metadata"] = json.loads(item.get("metadata_json") or "{}")
                except json.JSONDecodeError:
                    item["metadata"] = {}
                item["evidence"] = store.list_evidence(f["id"])
                out.append(item)
            return out
        finally:
            store.close()

    @app.get("/api/runs/{run_id}/report")
    def api_report(run_id: str) -> PlainTextResponse:
        path = runs_dir() / run_id / "reports" / "summary.md"
        if not path.is_file():
            raise HTTPException(404, "report not found")
        return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")

    @app.get("/api/jobs")
    def api_jobs() -> list[dict[str, Any]]:
        with _JOBS_LOCK:
            return sorted(_JOBS.values(), key=lambda j: j.get("started_at") or "", reverse=True)

    @app.get("/api/jobs/{job_id}")
    def api_job(job_id: str) -> dict[str, Any]:
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(404, "job not found")
        return job

    def _execute_scan(job_id: str, req: ScanRequest) -> None:
        with _JOBS_LOCK:
            _JOBS[job_id]["status"] = "running"
        try:
            result = run_scan(
                path=Path(req.path).expanduser() if req.path else None,
                git_url=req.git_url,
                goals_file=Path(req.goals).expanduser() if req.goals else None,
                revision=req.revision,
                enable_antares=not req.no_antares,
                enable_llm_codeguard=req.llm_codeguard,
                use_docker=False if req.no_docker else None,
            )
            with _JOBS_LOCK:
                _JOBS[job_id].update(
                    {
                        "status": "completed",
                        "run_id": result.run_id,
                        "counts": result.counts,
                        "report_dir": str(result.report_dir),
                    }
                )
        except Exception as exc:
            with _JOBS_LOCK:
                _JOBS[job_id].update({"status": "failed", "error": str(exc)})

    @app.post("/api/scans")
    def api_scan(req: ScanRequest, background: BackgroundTasks) -> dict[str, Any]:
        if not req.path and not req.git_url:
            raise HTTPException(400, "Provide path or git_url")
        from acyl.substrate.db import new_id, utcnow

        job_id = new_id("job_")
        job = {
            "id": job_id,
            "status": "queued",
            "request": req.model_dump(),
            "started_at": utcnow(),
            "run_id": None,
            "error": None,
        }
        with _JOBS_LOCK:
            _JOBS[job_id] = job
        background.add_task(_execute_scan, job_id, req)
        return job

    @app.post("/api/findings/{finding_id}/fix")
    def api_fix(finding_id: str, req: FixRequest) -> dict[str, Any]:
        db = runs_dir() / req.run_id / "acyl.db"
        if not db.is_file():
            raise HTTPException(404, "run not found")
        store = Store(db)
        try:
            result = autofix_finding(store, finding_id, offline=req.offline)
            return {
                "finding_id": result.finding_id,
                "mode": result.mode,
                "branch": result.branch,
                "patch_path": str(result.patch_path) if result.patch_path else None,
                "pr_url": result.pr_url,
                "message": result.message,
            }
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        finally:
            store.close()

    @app.get("/", response_class=HTMLResponse)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app


def run_dashboard(host: str = "127.0.0.1", port: int = 8787) -> None:
    import uvicorn

    app = build_dashboard_app()
    uvicorn.run(app, host=host, port=port, log_level="info")
