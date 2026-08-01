from pathlib import Path

from acyl.paths import default_goals_file
from acyl.target import load_goals, parse_goals_markdown


def test_parse_standard_goals_metadata():
    text = Path("goals/standard.md").read_text(encoding="utf-8")
    goals = parse_goals_markdown(text)
    assert len(goals) >= 10
    secrets = next(g for g in goals if g["id"] == "secrets")
    assert secrets["cwe"] == "CWE-798"
    assert secrets.get("owasp") == "A02:2025"
    assert secrets.get("codeguard") == "codeguard-1-hardcoded-credentials"
    injection = next(g for g in goals if g["id"] == "injection")
    assert injection["cwe"] == "CWE-78"


def test_parse_fixture_goals():
    text = Path("fixtures/vulnerable-app/goals.md").read_text(encoding="utf-8")
    goals = parse_goals_markdown(text)
    assert len(goals) >= 2
    assert any(g.get("cwe") == "CWE-78" for g in goals)


def test_load_goals_prefers_target_local():
    goals, source = load_goals(Path("fixtures/vulnerable-app"))
    assert goals
    assert source.endswith("fixtures/vulnerable-app/goals.md") or "vulnerable-app/goals.md" in source


def test_load_goals_falls_back_to_bundled_standard(tmp_path):
    # Empty target — no local goals.md
    goals, source = load_goals(tmp_path)
    assert len(goals) >= 10
    assert source.endswith("goals/standard.md")
    assert any(g["id"] == "secrets" for g in goals)


def test_load_goals_explicit_minimal():
    goals, source = load_goals(Path("."), goals_file=Path("goals/minimal.md"))
    assert len(goals) == 3
    assert {g["id"] for g in goals} == {"secrets", "supply-chain", "injection"}
    assert source.endswith("goals/minimal.md")


def test_load_goals_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("ACYL_GOALS_FILE", str(Path("goals/minimal.md").resolve()))
    goals, source = load_goals(tmp_path)
    assert len(goals) == 3
    assert source.endswith("goals/minimal.md")


def test_default_goals_file_exists():
    assert default_goals_file().is_file()
