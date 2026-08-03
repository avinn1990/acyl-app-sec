from acyl.reporter.evidence_table import group_presence_impact, markdown_evidence_section


def test_group_presence_impact_pairs_by_file_line():
    evidence = [
        {
            "kind": "presence",
            "path": "app.py",
            "line": 8,
            "note": "Secret pattern `aws-access-key` matched.",
        },
        {
            "kind": "impact",
            "path": "app.py",
            "line": 8,
            "note": "Committed secrets may enable unauthorized access.",
        },
        {
            "kind": "presence",
            "path": "config/settings.py",
            "line": 22,
            "note": "Secret pattern `generic-api-key` matched.",
        },
        {
            "kind": "impact",
            "path": "config/settings.py",
            "line": 22,
            "note": "Committed secrets may enable unauthorized access.",
        },
        {
            "kind": "context",
            "path": "app.py",
            "line": 8,
            "note": "documentation-context: path under fixtures/",
        },
    ]
    rows, other = group_presence_impact(evidence)
    assert rows == [
        {
            "file": "app.py:8",
            "presence": "Secret pattern `aws-access-key` matched.",
            "impact": "Committed secrets may enable unauthorized access.",
        },
        {
            "file": "config/settings.py:22",
            "presence": "Secret pattern `generic-api-key` matched.",
            "impact": "Committed secrets may enable unauthorized access.",
        },
    ]
    assert len(other) == 1
    assert other[0]["kind"] == "context"


def test_markdown_evidence_option_b_table():
    evidence = [
        {
            "kind": "presence",
            "path": "app.py",
            "line": 8,
            "note": "Secret pattern matched.",
        },
        {
            "kind": "impact",
            "path": "app.py",
            "line": 8,
            "note": "Unauthorized access risk.",
        },
        {
            "kind": "context",
            "path": "app.py",
            "line": 8,
            "note": "docs context",
        },
    ]
    md = "\n".join(markdown_evidence_section(evidence))
    assert "| File | Presence | Impact |" in md
    assert "| `app.py:8` | Secret pattern matched. | Unauthorized access risk. |" in md
    assert "Other evidence:" in md
    assert "**context**" in md
    assert "- **presence**" not in md
    assert "- **impact**" not in md
