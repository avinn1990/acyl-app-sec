"""Tests for multi-agent task queue and worker caps."""

from __future__ import annotations

from pathlib import Path

from acyl.orchestrator.config import MAX_WORKERS
from acyl.orchestrator.scan import run_scan
from acyl.substrate import Store


def test_max_workers_policy():
    assert MAX_WORKERS["indexer"] == 1
    assert MAX_WORKERS["cartographer"] == 1
    assert MAX_WORKERS["detector"] == 2
    assert MAX_WORKERS["triager"] == 1
    assert MAX_WORKERS["reporter"] == 1


def test_claim_task_scoped_by_run_and_roles(tmp_path):
    db = tmp_path / "acyl.db"
    store = Store(db)
    run_a = store.create_run(
        target_path="/a",
        pinned_revision="x",
        scope={},
        goals=[],
    )
    run_b = store.create_run(
        target_path="/b",
        pinned_revision="x",
        scope={},
        goals=[],
    )
    store.add_task(run_a, "detector.secrets", priority=30)
    store.add_task(run_b, "detector.secrets", priority=30)
    store.add_task(run_a, "triager", priority=40)

    claimed = store.claim_task(
        "det-1",
        run_id=run_a,
        roles=["detector.secrets", "detector.sca"],
    )
    assert claimed is not None
    assert claimed["run_id"] == run_a
    assert claimed["role"] == "detector.secrets"

    other = store.claim_task(
        "det-2",
        run_id=run_a,
        roles=["detector.secrets", "detector.sca"],
    )
    assert other is None

    triage = store.claim_task("tri-1", run_id=run_a, role="triager")
    assert triage is not None
    assert triage["role"] == "triager"
    store.close()


def test_reclaim_stale_claims(tmp_path):
    db = tmp_path / "acyl.db"
    store = Store(db)
    run_id = store.create_run(
        target_path="/t",
        pinned_revision="x",
        scope={},
        goals=[],
    )
    store.add_task(run_id, "detector.sca", priority=30)
    claimed = store.claim_task("agent", run_id=run_id, role="detector.sca")
    assert claimed is not None
    # Force stale heartbeat
    store._conn.execute(
        "UPDATE claims SET heartbeat_at = ?",
        ("2000-01-01T00:00:00Z",),
    )
    store._conn.commit()
    n = store.reclaim_stale_claims(30.0, run_id=run_id)
    assert n == 1
    again = store.claim_task("agent2", run_id=run_id, role="detector.sca")
    assert again is not None
    store.close()


def test_pipeline_records_closed_tasks(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ACYL_MODEL_MOCK", "1")
    result = run_scan(
        path=Path("fixtures/vulnerable-app").resolve(),
        enable_antares=False,
        use_docker=False,
    )
    store = Store(result.db_path)
    try:
        tasks = store.list_tasks(result.run_id)
        roles = {t["role"] for t in tasks}
        assert "indexer" in roles
        assert "cartographer" in roles
        assert "detector.secrets" in roles
        assert "detector.sca" in roles
        assert "detector.codeguard" in roles
        assert "triager" in roles
        assert "reporter" in roles
        assert all(t["state"] == "closed" for t in tasks)
        assert store.run_terminal_task_state(result.run_id) == "done"
        assert (result.report_dir / "summary.md").is_file()
    finally:
        store.close()


def test_two_detector_claims_concurrent(tmp_path):
    db = tmp_path / "acyl.db"
    store = Store(db)
    run_id = store.create_run(
        target_path="/t",
        pinned_revision="x",
        scope={},
        goals=[],
    )
    for role in ("detector.secrets", "detector.sca", "detector.codeguard"):
        store.add_task(run_id, role, priority=30)

    a = store.claim_task(
        "d0",
        run_id=run_id,
        roles=["detector.secrets", "detector.sca", "detector.codeguard"],
    )
    b = store.claim_task(
        "d1",
        run_id=run_id,
        roles=["detector.secrets", "detector.sca", "detector.codeguard"],
    )
    c = store.claim_task(
        "d2",
        run_id=run_id,
        roles=["detector.secrets", "detector.sca", "detector.codeguard"],
    )
    assert a is not None and b is not None
    assert a["id"] != b["id"]
    # Third claim succeeds at queue level; worker pool caps concurrency at 2.
    assert c is not None
    store.close()
