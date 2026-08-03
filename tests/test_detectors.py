from pathlib import Path

from acyl.detectors.codeguard import detect_codeguard_presence
from acyl.detectors.sca import detect_sca
from acyl.detectors.secrets import detect_secrets
from acyl.substrate import Store


def test_secrets_and_codeguard_on_fixture(tmp_path: Path):
    db = tmp_path / "t.db"
    store = Store(db)
    run_id = store.create_run(
        target_path=str(Path("fixtures/vulnerable-app").resolve()),
        pinned_revision="test",
        scope={},
        goals=[{"id": "t", "title": "t", "cwe": "CWE-78"}],
    )
    root = Path("fixtures/vulnerable-app")
    assert detect_secrets(store, run_id, root) >= 1
    assert detect_codeguard_presence(store, run_id, root) >= 1
    assert detect_sca(store, run_id, root) >= 1
    findings = store.list_findings(run_id)
    assert any(f["vuln_class"] == "secret-exposure" for f in findings)
    sca = [f for f in findings if f["source"] == "sca"]
    assert sca
    # Fixture lodash is high via KNOWN_BAD when osv-scanner is unavailable
    lodash = [f for f in sca if "lodash" in (f.get("symbol") or "")]
    if lodash:
        assert lodash[0]["severity"] in {"high", "critical", "medium", "low"}
    store.close()


def test_secrets_honors_explicit_empty_exclude(tmp_path: Path):
    """Opting out of excludes still scans .cursor when scope.exclude is empty."""
    from acyl.detectors import secrets as secrets_mod

    skill = tmp_path / ".cursor" / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "notes.md").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    db = tmp_path / "t.db"
    store = Store(db)
    run_id = store.create_run(
        target_path=str(tmp_path),
        pinned_revision="test",
        scope={"include": ["**/*"], "exclude": []},
        goals=[{"id": "t", "title": "t", "cwe": "CWE-798"}],
    )
    original = secrets_mod._gitleaks_available
    secrets_mod._gitleaks_available = lambda: False
    try:
        n = detect_secrets(
            store, run_id, tmp_path, scope={"include": ["**/*"], "exclude": []}
        )
    finally:
        secrets_mod._gitleaks_available = original
    assert n >= 1
    assert any(".cursor/" in str(f.get("path") or "") for f in store.list_findings(run_id))
    store.close()
