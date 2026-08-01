from pathlib import Path

from acyl.target import load_goals, parse_goals_markdown


def test_parse_goals_markdown():
    text = Path("fixtures/vulnerable-app/goals.md").read_text(encoding="utf-8")
    goals = parse_goals_markdown(text)
    assert len(goals) >= 2
    assert any(g.get("cwe") == "CWE-78" for g in goals)


def test_load_goals_from_fixture():
    goals = load_goals(Path("fixtures/vulnerable-app"))
    assert goals
