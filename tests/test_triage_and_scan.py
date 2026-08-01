import os
from pathlib import Path

import httpx
import pytest

from acyl.orchestrator.scan import run_scan
from acyl.substrate import Store


@pytest.fixture(scope="module")
def mock_model_server():
    # Prefer env pointing at mock if already up; otherwise detectors tolerate connection errors.
    os.environ["ACYL_MODEL_MOCK"] = "1"
    os.environ["ACYL_MODEL_URL"] = "http://127.0.0.1:8765/v1"
    import threading

    import uvicorn

    from acyl.model.server import build_app

    app = build_app(mock=True)
    config = uvicorn.Config(app, host="127.0.0.1", port=8765, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            httpx.get("http://127.0.0.1:8765/health", timeout=0.2)
            break
        except Exception:
            import time

            time.sleep(0.1)
    yield
    server.should_exit = True


def test_end_to_end_fixture_scan(mock_model_server, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_scan(
        path=Path("fixtures/vulnerable-app").resolve(),
        enable_antares=True,
        use_docker=False,
    )
    store = Store(result.db_path)
    try:
        confirmed = store.list_findings(result.run_id, state="confirmed")
        assert confirmed, "expected at least one confirmed finding"
        assert (result.report_dir / "summary.md").is_file()
        assert (result.report_dir / "findings.sarif").is_file()
    finally:
        store.close()
