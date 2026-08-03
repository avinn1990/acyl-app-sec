import threading
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from acyl.dashboard import app as dash_mod
from acyl.dashboard.app import build_dashboard_app
from acyl.orchestrator.scan import run_scan
from acyl.substrate import Store


def test_dashboard_lists_runs_and_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_scan(
        path=Path("fixtures/vulnerable-app").resolve(),
        enable_antares=False,
        use_docker=False,
    )
    client = TestClient(build_dashboard_app())
    health = client.get("/api/health")
    assert health.status_code == 200
    runs = client.get("/api/runs").json()
    assert any(r["id"] == result.run_id for r in runs)
    detail = client.get(f"/api/runs/{result.run_id}").json()
    assert detail["id"] == result.run_id
    findings = client.get(f"/api/runs/{result.run_id}/findings").json()
    assert findings
    report = client.get(f"/api/runs/{result.run_id}/report")
    assert report.status_code == 200
    assert "acyl scan report" in report.text
    page = client.get("/")
    assert page.status_code == 200
    assert "Foundry Spec Repository Scanning" in page.text
    assert "ACYL" in page.text
    assert "Accelerated Cybersecurity Leadership" in page.text


def test_dashboard_scan_endpoint_queues_job(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
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
    assert job["status"] in {"queued", "running", "completed"}
    import time

    for _ in range(50):
        job = client.get(f"/api/jobs/{job['id']}").json()
        if job["status"] in {"completed", "failed"}:
            break
        time.sleep(0.1)
    assert job["status"] == "completed"
    assert job["run_id"]
    store = Store(Path.home() / ".cache" / "acyl" / "runs" / job["run_id"] / "acyl.db")
    assert store.list_findings(job["run_id"])
    store.close()


def test_dashboard_scan_defaults_enable_antares(tmp_path, monkeypatch):
    """Omit no_antares in the JSON body — API default must enable Antares."""
    monkeypatch.setenv("HOME", str(tmp_path))
    called: dict[str, object] = {}

    def fake_run_scan(**kwargs):
        called.update(kwargs)
        return SimpleNamespace(run_id="run_" + ("c" * 32), counts={}, report_dir=tmp_path)

    monkeypatch.setattr("acyl.dashboard.app.run_scan", fake_run_scan)
    client = TestClient(build_dashboard_app())
    resp = client.post(
        "/api/scans",
        json={
            "path": str(Path("fixtures/vulnerable-app").resolve()),
            "no_docker": True,
        },
    )
    assert resp.status_code == 200
    import time

    job = resp.json()
    for _ in range(50):
        job = client.get(f"/api/jobs/{job['id']}").json()
        if job["status"] in {"completed", "failed"}:
            break
        time.sleep(0.05)
    assert job["status"] == "completed"
    assert called.get("enable_antares") is True
    assert job["request"]["no_antares"] is False


def test_dashboard_delete_run(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_scan(
        path=Path("fixtures/vulnerable-app").resolve(),
        enable_antares=False,
        use_docker=False,
    )
    run_dir = Path.home() / ".cache" / "acyl" / "runs" / result.run_id
    assert run_dir.is_dir()
    client = TestClient(build_dashboard_app())
    resp = client.delete(f"/api/runs/{result.run_id}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] == result.run_id
    assert not run_dir.exists()
    assert client.get(f"/api/runs/{result.run_id}").status_code == 404


def test_dashboard_stop_job_sets_cancel_event(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    dash_mod._JOBS.clear()
    cancel_event = threading.Event()
    job_id = "job_" + ("b" * 32)
    run_id = "run_" + ("a" * 32)
    dash_mod._JOBS[job_id] = {
        "id": job_id,
        "status": "running",
        "request": {},
        "started_at": "now",
        "run_id": run_id,
        "error": None,
        "cancel_event": cancel_event,
    }
    client = TestClient(build_dashboard_app())
    stop = client.post(f"/api/jobs/{job_id}/stop")
    assert stop.status_code == 200
    assert stop.json()["status"] == "stopping"
    assert "cancel_event" not in stop.json()
    assert cancel_event.is_set()

    stop_run = client.post(f"/api/runs/{run_id}/stop")
    # already stopping → 409 from second stop on same job, or ok if still stopping
    assert stop_run.status_code in {200, 409}
    dash_mod._JOBS.clear()


def test_run_scan_honours_cancel_event(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cancel_event = threading.Event()
    cancel_event.set()
    try:
        run_scan(
            path=Path("fixtures/vulnerable-app").resolve(),
            enable_antares=False,
            use_docker=False,
            cancel_event=cancel_event,
        )
        raise AssertionError("expected ScanCancelled")
    except Exception as exc:
        from acyl.scan_control import ScanCancelled

        assert isinstance(exc, ScanCancelled)
