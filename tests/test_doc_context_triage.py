"""Tests for documentation-context triage demotion and scoped secret scanning."""

from pathlib import Path

from acyl.detectors.secrets import detect_secrets
from acyl.fingerprint import fingerprint
from acyl.substrate import Store
from acyl.target import DEFAULT_SCOPE
from acyl.triager.triage import triage_run


def _seed_secret_finding(
    store: Store,
    run_id: str,
    *,
    path: str,
    snippet: str = "AKIAJDKEISHFJDUEISHF",
    state: str = "candidate",
) -> str:
    fp = fingerprint(path, "aws-access-key", "secret-exposure")
    finding_id = store.upsert_finding(
        run_id=run_id,
        fingerprint=fp,
        title="Possible AWS access key id",
        vuln_class="secret-exposure",
        source="secrets",
        summary=f"Possible AWS access key id in `{path}`",
        severity="critical",
        path=path,
        symbol="aws-access-key",
        rule_id="aws-access-key",
        metadata={"line": 1, "snippet": snippet},
        state=state,
    )
    store.add_evidence(
        finding_id,
        kind="presence",
        path=path,
        line=1,
        note="Secret pattern matched.",
    )
    store.add_evidence(
        finding_id,
        kind="impact",
        path=path,
        line=1,
        note="Committed secrets may enable unauthorized access.",
    )
    return finding_id


def test_triage_demotes_skill_path_to_needs_review(tmp_path: Path):
    skill = tmp_path / ".cursor" / "skills" / "security-review"
    skill.mkdir(parents=True)
    target = skill / "examples.md"
    target.write_text("AKIAJDKEISHFJDUEISHF\n", encoding="utf-8")

    db = tmp_path / "t.db"
    store = Store(db)
    run_id = store.create_run(
        target_path=str(tmp_path),
        pinned_revision="test",
        scope={},
        goals=[{"id": "secrets", "title": "secrets", "cwe": "CWE-798"}],
    )
    finding_id = _seed_secret_finding(
        store, run_id, path=".cursor/skills/security-review/examples.md"
    )

    counts = triage_run(store, run_id, tmp_path)
    finding = store.get_finding(finding_id)
    assert finding is not None
    assert finding["state"] == "needs-review"
    assert finding["severity"] == "critical"  # severity unchanged
    assert "documentation-context" in (finding.get("summary") or "")
    assert counts["doc-context-demoted"] == 1
    assert counts["true-positive"] == 0
    evidence = store.list_evidence(finding_id)
    assert any(e["kind"] == "context" for e in evidence)
    store.close()


def test_triage_confirms_production_secret(tmp_path: Path):
    prod = tmp_path / "src"
    prod.mkdir()
    (prod / "config.py").write_text("KEY=AKIAJDKEISHFJDUEISHF\n", encoding="utf-8")

    db = tmp_path / "t.db"
    store = Store(db)
    run_id = store.create_run(
        target_path=str(tmp_path),
        pinned_revision="test",
        scope={},
        goals=[{"id": "secrets", "title": "secrets", "cwe": "CWE-798"}],
    )
    finding_id = _seed_secret_finding(store, run_id, path="src/config.py")
    counts = triage_run(store, run_id, tmp_path)
    finding = store.get_finding(finding_id)
    assert finding is not None
    assert finding["state"] == "confirmed"
    assert counts["true-positive"] == 1
    assert counts["doc-context-demoted"] == 0
    store.close()


def test_triage_demotes_placeholder_snippet(tmp_path: Path):
    prod = tmp_path / "src"
    prod.mkdir()
    (prod / "config.py").write_text("KEY=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")

    db = tmp_path / "t.db"
    store = Store(db)
    run_id = store.create_run(
        target_path=str(tmp_path),
        pinned_revision="test",
        scope={},
        goals=[{"id": "secrets", "title": "secrets", "cwe": "CWE-798"}],
    )
    finding_id = _seed_secret_finding(
        store,
        run_id,
        path="src/config.py",
        snippet="AKIAIOSFODNN7EXAMPLE",
    )
    counts = triage_run(store, run_id, tmp_path)
    finding = store.get_finding(finding_id)
    assert finding is not None
    assert finding["state"] == "needs-review"
    assert counts["doc-context-demoted"] == 1
    store.close()


def test_secrets_detector_skips_cursor_by_default_scope(tmp_path: Path):
    skill = tmp_path / ".cursor" / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "notes.md").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    prod = tmp_path / "app"
    prod.mkdir()
    (prod / "secrets.py").write_text(
        "AWS_KEY = 'AKIAJDKEISHFJDUEISHF'\n",
        encoding="utf-8",
    )

    db = tmp_path / "t.db"
    store = Store(db)
    run_id = store.create_run(
        target_path=str(tmp_path),
        pinned_revision="test",
        scope=dict(DEFAULT_SCOPE),
        goals=[{"id": "secrets", "title": "secrets", "cwe": "CWE-798"}],
    )
    # Force regex path so we don't depend on gitleaks being installed.
    from acyl.detectors import secrets as secrets_mod

    original = secrets_mod._gitleaks_available
    secrets_mod._gitleaks_available = lambda: False
    try:
        n = detect_secrets(store, run_id, tmp_path, scope=dict(DEFAULT_SCOPE))
    finally:
        secrets_mod._gitleaks_available = original

    findings = store.list_findings(run_id)
    paths = {f.get("path") for f in findings}
    assert n >= 1
    assert any(str(p).startswith("app/") for p in paths)
    assert not any(str(p).startswith(".cursor/") for p in paths)
    store.close()
