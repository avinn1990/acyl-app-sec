from pathlib import Path

from fastapi.testclient import TestClient

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
    # seed an empty runs dir
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
    # Drain background task
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
