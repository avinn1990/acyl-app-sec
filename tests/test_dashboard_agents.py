"""Tests for dashboard agent / pipeline status."""

from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from acyl.dashboard.agents import build_agent_status
from acyl.dashboard.app import build_dashboard_app
from acyl.orchestrator.scan import run_scan
from acyl.substrate import Store


def test_build_agent_status_from_tasks():
    tasks = [
        {
            "task_id": "t1",
            "role": "indexer",
            "state": "closed",
            "payload": {},
            "agent_id": None,
        },
        {
            "task_id": "t2",
            "role": "cartographer",
            "state": "closed",
            "payload": {},
            "agent_id": None,
        },
        {
            "task_id": "t3",
            "role": "detector.secrets",
            "state": "claimed",
            "payload": {},
            "agent_id": "detector-0-abc12345",
            "heartbeat_at": "2026-08-03T09:00:00Z",
            "claimed_at": "2026-08-03T08:59:00Z",
        },
        {
            "task_id": "t4",
            "role": "detector.sca",
            "state": "open",
            "payload": {},
            "agent_id": None,
        },
    ]
    status = build_agent_status(tasks, phase="secrets", job_status="running")
    assert status["active_count"] == 1
    by_fam = {p["family"]: p for p in status["pipeline"]}
    assert by_fam["indexer"]["state"] == "done"
    assert by_fam["cartographer"]["state"] == "done"
    assert by_fam["detector"]["state"] == "running"
    assert by_fam["detector"]["agents"] == ["detector-0-abc12345"]
    secrets = next(a for a in status["agents"] if a["role"] == "detector.secrets")
    assert secrets["state"] == "running"
    assert secrets["agent_id"] == "detector-0-abc12345"
    # Core roles not yet enqueued still appear as pending
    assert any(a["role"] == "triager" and a["state"] == "pending" for a in status["agents"])


def test_build_agent_status_phase_fallback():
    status = build_agent_status([], phase="triage", job_status="running")
    by_fam = {p["family"]: p for p in status["pipeline"]}
    assert by_fam["indexer"]["state"] == "done"
    assert by_fam["cartographer"]["state"] == "done"
    assert by_fam["detector"]["state"] == "done"
    assert by_fam["triager"]["state"] == "running"
    assert by_fam["reporter"]["state"] == "pending"


def test_dashboard_agents_endpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_scan(
        path=Path("fixtures/vulnerable-app").resolve(),
        enable_antares=False,
        use_docker=False,
    )
    client = TestClient(build_dashboard_app())
    resp = client.get(f"/api/runs/{result.run_id}/agents")
    assert resp.status_code == 200
    body = resp.json()
    assert "pipeline" in body
    assert "agents" in body
    by_fam = {p["family"]: p for p in body["pipeline"]}
    assert by_fam["reporter"]["state"] == "done"
    assert by_fam["indexer"]["state"] == "done"
    roles = {a["role"] for a in body["agents"] if a["task_state"] == "closed"}
    assert "indexer" in roles
    assert "reporter" in roles
    assert "detector.secrets" in roles

    detail = client.get(f"/api/runs/{result.run_id}").json()
    assert detail["agents"]["pipeline"]
    runs = client.get("/api/runs").json()
    match = next(r for r in runs if r["id"] == result.run_id)
    assert match["agents"]["pipeline"]


def test_dashboard_job_includes_agents(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    phases: list[str] = []

    def fake_run_scan(**kwargs):
        on_progress = kwargs.get("on_progress")
        on_run_created = kwargs.get("on_run_created")
        # Create a minimal DB so job agents can load claims
        cache = Path.home() / ".cache" / "acyl" / "runs"
        cache.mkdir(parents=True, exist_ok=True)
        # Store needs to live under the run id folder — create_run first in a temp db
        # then we need the run id. Use Store in a placeholder then move... simpler:
        # create store at a temp path, get run_id, then the dashboard looks under runs/run_id.
        # So create directory after we know run_id.
        staging = tmp_path / "staging.db"
        store = Store(staging)
        run_id = store.create_run(
            target_path=str(tmp_path),
            git_url=None,
            pinned_revision="deadbeef",
            scope={},
            goals=[],
        )
        store.add_task(run_id, "indexer", priority=10)
        store.add_task(run_id, "cartographer", priority=20)
        claimed = store.claim_task("indexer-0-deadbeef", run_id=run_id, role="indexer")
        assert claimed
        store.close()

        run_dir = cache / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        staging.replace(run_dir / "acyl.db")

        if on_run_created:
            on_run_created(run_id)
        if on_progress:
            on_progress({"phase": "index", "message": "Indexing repository…"})
            phases.append("index")
        return SimpleNamespace(run_id=run_id, counts={}, report_dir=tmp_path)

    monkeypatch.setattr("acyl.dashboard.app.run_scan", fake_run_scan)
    client = TestClient(build_dashboard_app())
    resp = client.post(
        "/api/scans",
        json={
            "path": str(Path("fixtures/vulnerable-app").resolve()),
            "no_antares": True,
            "no_docker": True,
        },
    )
    assert resp.status_code == 200
    job = resp.json()
    assert "agents" in job
    import time

    for _ in range(50):
        job = client.get(f"/api/jobs/{job['id']}").json()
        if job["status"] in {"completed", "failed"}:
            break
        time.sleep(0.05)
    assert job["status"] == "completed"
    assert job["agents"]["pipeline"]
    indexer = next(p for p in job["agents"]["pipeline"] if p["family"] == "indexer")
    assert indexer["state"] == "running"
    assert "indexer-0-deadbeef" in indexer["agents"]
    assert phases == ["index"]
