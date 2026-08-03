"""Markdown + SARIF reporters. Only surfaces confirmed / needs-review by default."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from acyl.reporter.evidence_table import markdown_evidence_section
from acyl.substrate import Store


def write_reports(
    store: Store,
    run_id: str,
    out_dir: Path,
    *,
    include_candidates: bool = False,
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    run = store.get_run(run_id) or {}
    findings = store.list_findings(run_id)
    if not include_candidates:
        findings = [f for f in findings if f["state"] in {"confirmed", "needs-review", "published"}]
    coverage = store.list_coverage(run_id)
    gaps = store.list_rule_gaps(run_id)

    md_path = out_dir / "summary.md"
    sarif_path = out_dir / "findings.sarif"
    md_path.write_text(_markdown(run, findings, coverage, gaps, store), encoding="utf-8")
    sarif_path.write_text(json.dumps(_sarif(findings, store), indent=2), encoding="utf-8")
    return {"markdown": md_path, "sarif": sarif_path}


def _markdown(
    run: dict[str, Any],
    findings: list[dict[str, Any]],
    coverage: list[dict[str, Any]],
    gaps: list[dict[str, Any]],
    store: Store,
) -> str:
    by_state = Counter(f["state"] for f in findings)
    lines = [
        "# acyl scan report",
        "",
        f"- Run: `{run.get('id')}`",
        f"- Target: `{run.get('target_path')}`",
        f"- Pinned revision: `{run.get('pinned_revision')}`",
        f"- Generated: {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "## Summary",
        "",
        f"- Confirmed: {by_state.get('confirmed', 0)}",
        f"- Needs review: {by_state.get('needs-review', 0)}",
        f"- Rule gaps: {len(gaps)}",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("_No findings survived triage._")
    for f in findings:
        lines.extend(
            [
                f"### {f['title']}",
                "",
                f"- Id: `{f['id']}`",
                f"- State / verdict: `{f['state']}` / `{f.get('verdict')}`",
                f"- Severity: `{f.get('severity')}`",
                f"- Class: `{f['vuln_class']}`",
                f"- Path: `{f.get('path')}`",
                f"- Symbol: `{f.get('symbol')}`",
                f"- Source: `{f['source']}`",
                f"- Fingerprint: `{f['fingerprint']}`",
                "",
                f.get("summary") or "",
                "",
            ]
        )
        lines.extend(markdown_evidence_section(store.list_evidence(f["id"])))
    lines.extend(["## Coverage", ""])
    for c in coverage:
        lines.append(
            f"- `{c['goal']}` / `{c['technique']}` → `{c['state']}`"
        )
    if gaps:
        lines.extend(["", "## Rule gaps", ""])
        for g in gaps:
            lines.append(f"- Finding `{g['finding_id']}` class `{g['vuln_class']}`: {g['pattern_note']}")
    lines.append("")
    return "\n".join(lines)


def _sarif(findings: list[dict[str, Any]], store: Store) -> dict[str, Any]:
    rules = {}
    results = []
    for f in findings:
        rule_id = f.get("rule_id") or f["vuln_class"]
        rules[rule_id] = {
            "id": rule_id,
            "shortDescription": {"text": f["title"]},
        }
        level = "note"
        if f["state"] == "confirmed":
            level = "error" if (f.get("severity") in {"critical", "high"}) else "warning"
        elif f["state"] == "needs-review":
            level = "note"
        region: dict[str, Any] = {}
        evidence = store.list_evidence(f["id"])
        line = next((e.get("line") for e in evidence if e.get("line")), None)
        if line:
            region["startLine"] = int(line)
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.get("path") or "unknown"},
            }
        }
        if region:
            loc["physicalLocation"]["region"] = region
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f.get("summary") or f["title"]},
                "locations": [loc],
                "properties": {
                    "fingerprint": f["fingerprint"],
                    "verdict": f.get("verdict"),
                    "state": f["state"],
                    "findingId": f["id"],
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "acyl",
                        "informationUri": "https://github.com/avinn1990/acyl-app-sec",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
