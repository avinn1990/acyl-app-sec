"""Local web dashboard for acyl (binds to localhost by default)."""

from __future__ import annotations

import json
import re
import shutil
import threading
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from acyl import __version__
from acyl.autofix.fix import autofix_finding
from acyl.orchestrator.scan import run_scan
from acyl.paths import runs_dir
from acyl.scan_control import ScanCancelled
from acyl.substrate import Store

STATIC_DIR = Path(__file__).with_name("static")
_RUN_ID_RE = re.compile(r"^run_[0-9a-f]{32}$")
_JOB_ID_RE = re.compile(r"^job_[0-9a-f]{32}$")

# In-memory scan job tracker (single-operator local tool)
_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()


def _asset_version() -> str:
    """Bust browser cache when dashboard static files change."""
    stamp = __version__
    try:
        js = STATIC_DIR / "app.js"
        css = STATIC_DIR / "styles.css"
        mtime = int(max(js.stat().st_mtime, css.stat().st_mtime))
        stamp = f"{__version__}.{mtime}"
    except OSError:
        pass
    return stamp


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


def _safe_run_dir(run_id: str) -> Path:
    if not _RUN_ID_RE.fullmatch(run_id):
        raise HTTPException(400, "invalid run id")
    root = runs_dir().resolve()
    run_dir = (root / run_id).resolve()
    try:
        run_dir.relative_to(root)
    except ValueError as exc:
        raise HTTPException(400, "invalid run id") from exc
    return run_dir


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
        active_job = None
        with _JOBS_LOCK:
            for job in _JOBS.values():
                if job.get("run_id") == run_dir.name and job.get("status") in {
                    "queued",
                    "running",
                    "stopping",
                }:
                    active_job = {"id": job["id"], "status": job["status"]}
                    break
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
            "active_job": active_job,
        }
    finally:
        store.close()


def _public_job(job: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in job.items() if k != "cancel_event"}


def _stop_job_locked(job: dict[str, Any]) -> dict[str, Any]:
    """Mark a job for cooperative cancel. Caller must hold _JOBS_LOCK."""
    status = job.get("status")
    if status in {"completed", "failed", "cancelled"}:
        raise HTTPException(409, f"job already {status}")
    event = job.get("cancel_event")
    if isinstance(event, threading.Event):
        event.set()
    job["status"] = "stopping"
    return _public_job(job)


def _delete_run_dir(run_dir: Path) -> None:
    if not run_dir.exists():
        raise HTTPException(404, "run not found")
    shutil.rmtree(run_dir)


def build_dashboard_app() -> FastAPI:
    app = FastAPI(title="acyl dashboard", version="0.1.0")

    @app.middleware("http")
    async def disable_static_cache(request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path == "/" or path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"ok": "true", "service": "acyl-dashboard"}

    @app.get("/api/runs")
    def api_runs() -> list[dict[str, Any]]:
        return [_run_summary(p) for p in _list_run_dirs()]

    @app.get("/api/runs/{run_id}")
    def api_run(run_id: str) -> dict[str, Any]:
        run_dir = _safe_run_dir(run_id)
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

    @app.post("/api/runs/{run_id}/stop")
    def api_stop_run(run_id: str) -> dict[str, Any]:
        """Force-stop any in-flight job attached to this run."""
        _safe_run_dir(run_id)
        with _JOBS_LOCK:
            matches = [
                j
                for j in _JOBS.values()
                if j.get("run_id") == run_id and j.get("status") in {"queued", "running", "stopping"}
            ]
            if not matches:
                # Also stop jobs that are still running but have not published run_id yet
                # is handled via job-level stop; here we require association.
                raise HTTPException(404, "no active job for this run")
            stopped = [_stop_job_locked(j) for j in matches]
        return {"ok": True, "stopped": stopped}

    @app.delete("/api/runs/{run_id}")
    def api_delete_run(run_id: str) -> dict[str, Any]:
        """Stop any active job for the run, then delete its on-disk artifacts."""
        run_dir = _safe_run_dir(run_id)
        if not run_dir.exists():
            raise HTTPException(404, "run not found")
        with _JOBS_LOCK:
            for job in _JOBS.values():
                if job.get("run_id") == run_id and job.get("status") in {
                    "queued",
                    "running",
                    "stopping",
                }:
                    try:
                        _stop_job_locked(job)
                    except HTTPException:
                        pass
        # Best-effort wait for cooperative cancel to release DB handles
        import time

        for _ in range(20):
            active = False
            with _JOBS_LOCK:
                for job in _JOBS.values():
                    if job.get("run_id") == run_id and job.get("status") in {
                        "queued",
                        "running",
                        "stopping",
                    }:
                        active = True
                        break
            if not active:
                break
            time.sleep(0.1)
        try:
            _delete_run_dir(run_dir)
        except HTTPException:
            raise
        except OSError as exc:
            raise HTTPException(500, f"failed to delete run: {exc}") from exc
        with _JOBS_LOCK:
            for job in _JOBS.values():
                if job.get("run_id") == run_id and job.get("status") not in {
                    "completed",
                    "failed",
                    "cancelled",
                }:
                    job["status"] = "cancelled"
                    job["error"] = "run deleted"
        return {"ok": True, "deleted": run_id}

    @app.get("/api/runs/{run_id}/findings")
    def api_findings(run_id: str, state: str | None = None) -> list[dict[str, Any]]:
        db = _safe_run_dir(run_id) / "acyl.db"
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
        path = _safe_run_dir(run_id) / "reports" / "summary.md"
        if not path.is_file():
            raise HTTPException(404, "report not found")
        return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")

    @app.get("/api/jobs")
    def api_jobs() -> list[dict[str, Any]]:
        with _JOBS_LOCK:
            return sorted(
                (_public_job(j) for j in _JOBS.values()),
                key=lambda j: j.get("started_at") or "",
                reverse=True,
            )

    @app.get("/api/jobs/{job_id}")
    def api_job(job_id: str) -> dict[str, Any]:
        if not _JOB_ID_RE.fullmatch(job_id):
            raise HTTPException(400, "invalid job id")
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(404, "job not found")
        return _public_job(job)

    @app.post("/api/jobs/{job_id}/stop")
    def api_stop_job(job_id: str) -> dict[str, Any]:
        if not _JOB_ID_RE.fullmatch(job_id):
            raise HTTPException(400, "invalid job id")
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if not job:
                raise HTTPException(404, "job not found")
            return _stop_job_locked(job)

    def _execute_scan(job_id: str, req: ScanRequest, cancel_event: threading.Event) -> None:
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if not job:
                return
            if cancel_event.is_set():
                job["status"] = "cancelled"
                job["error"] = "stopped by operator"
                return
            job["status"] = "running"

        def on_run_created(run_id: str) -> None:
            with _JOBS_LOCK:
                if job_id in _JOBS:
                    _JOBS[job_id]["run_id"] = run_id

        try:
            result = run_scan(
                path=Path(req.path).expanduser() if req.path else None,
                git_url=req.git_url,
                goals_file=Path(req.goals).expanduser() if req.goals else None,
                revision=req.revision,
                enable_antares=not req.no_antares,
                enable_llm_codeguard=req.llm_codeguard,
                use_docker=False if req.no_docker else None,
                cancel_event=cancel_event,
                on_run_created=on_run_created,
            )
            with _JOBS_LOCK:
                job = _JOBS.get(job_id)
                if not job:
                    return
                if cancel_event.is_set():
                    job.update(
                        {
                            "status": "cancelled",
                            "run_id": result.run_id,
                            "error": "stopped by operator",
                        }
                    )
                else:
                    job.update(
                        {
                            "status": "completed",
                            "run_id": result.run_id,
                            "counts": result.counts,
                            "report_dir": str(result.report_dir),
                        }
                    )
        except ScanCancelled as exc:
            with _JOBS_LOCK:
                if job_id in _JOBS:
                    _JOBS[job_id].update(
                        {
                            "status": "cancelled",
                            "run_id": exc.run_id or _JOBS[job_id].get("run_id"),
                            "error": "stopped by operator",
                        }
                    )
        except Exception as exc:
            with _JOBS_LOCK:
                if job_id in _JOBS:
                    status = "cancelled" if cancel_event.is_set() else "failed"
                    _JOBS[job_id].update(
                        {
                            "status": status,
                            "error": "stopped by operator" if status == "cancelled" else str(exc),
                        }
                    )

    @app.post("/api/scans")
    def api_scan(req: ScanRequest, background: BackgroundTasks) -> dict[str, Any]:
        if not req.path and not req.git_url:
            raise HTTPException(400, "Provide path or git_url")
        from acyl.substrate.db import new_id, utcnow

        job_id = new_id("job_")
        cancel_event = threading.Event()
        job = {
            "id": job_id,
            "status": "queued",
            "request": req.model_dump(),
            "started_at": utcnow(),
            "run_id": None,
            "error": None,
            "cancel_event": cancel_event,
        }
        with _JOBS_LOCK:
            _JOBS[job_id] = job
        background.add_task(_execute_scan, job_id, req, cancel_event)
        return _public_job(job)

    @app.post("/api/findings/{finding_id}/fix")
    def api_fix(finding_id: str, req: FixRequest) -> dict[str, Any]:
        db = _safe_run_dir(req.run_id) / "acyl.db"
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
    def index() -> HTMLResponse:
        html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        html = html.replace("__ACYL_ASSET_VERSION__", _asset_version())
        return HTMLResponse(
            html,
            headers={"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"},
        )

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app


def run_dashboard(host: str = "127.0.0.1", port: int = 8888) -> None:
    import uvicorn

    app = build_dashboard_app()
    uvicorn.run(app, host=host, port=port, log_level="info")
