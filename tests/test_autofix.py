import json
from pathlib import Path

from acyl.autofix.fix import autofix_finding
from acyl.substrate import Store


def test_deterministic_sca_fix(tmp_path: Path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.15"}}),
        encoding="utf-8",
    )
    # init git for patch generation
    import subprocess

    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "init"],
        cwd=root,
        check=True,
        capture_output=True,
    )

    store = Store(tmp_path / "db.sqlite")
    run_id = store.create_run(
        target_path=str(root),
        pinned_revision="x",
        scope={},
        goals=[{"id": "g", "title": "g"}],
    )
    from acyl.fingerprint import fingerprint

    fid = store.upsert_finding(
        run_id=run_id,
        fingerprint=fingerprint("package.json", "lodash@4.17.15", "vulnerable-dependency"),
        title="lodash",
        vuln_class="vulnerable-dependency",
        source="sca",
        path="package.json",
        symbol="lodash@4.17.15",
        metadata={"package": "lodash", "version": "4.17.15"},
        state="confirmed",
    )
    store.set_verdict(fid, verdict="true-positive", state="confirmed")
    result = autofix_finding(store, fid, offline=True)
    assert result.mode in {"offline-patch", "noop"}
    data = json.loads((root / "package.json").read_text(encoding="utf-8"))
    assert data["dependencies"]["lodash"] == "4.17.21"
    store.close()
