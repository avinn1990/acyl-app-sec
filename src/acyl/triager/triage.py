"""Evidence-gated triage."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from acyl.model.client import ChatClient
from acyl.paths import default_rules_dir
from acyl.substrate import Store

PRESENCE_CLASSES = {
    "secret-exposure",
    "hardcoded-credentials",
    "weak-crypto",
    "vulnerable-dependency",
}


def _resolve_citation(root: Path, path: str | None, line: int | None) -> bool:
    if not path:
        return False
    full = root / path
    if not full.is_file():
        return False
    if line is None or line <= 0:
        return True
    try:
        text = full.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return line <= text.count("\n") + 1


def triage_run(store: Store, run_id: str, root: Path) -> dict[str, int]:
    counts = {
        "true-positive": 0,
        "false-positive": 0,
        "needs-review": 0,
        "recorded": 0,
        "rule-gaps": 0,
    }
    rule_ids = {p.stem for p in default_rules_dir().glob("codeguard-*")}
    for finding in store.list_findings(run_id):
        if finding["state"] not in {"candidate", "needs-review"}:
            continue
        evidence = store.list_evidence(finding["id"])
        kinds = {e["kind"] for e in evidence}
        vuln_class = finding["vuln_class"]
        citations_ok = all(
            _resolve_citation(root, e.get("path"), e.get("line"))
            for e in evidence
            if e.get("path")
        )

        if vuln_class in PRESENCE_CLASSES:
            has_presence = "presence" in kinds
            has_impact = "impact" in kinds
            if has_presence and has_impact and citations_ok:
                store.set_verdict(finding["id"], verdict="true-positive", state="confirmed")
                counts["true-positive"] += 1
            elif has_presence:
                store.set_verdict(finding["id"], verdict="needs-review", state="needs-review")
                counts["needs-review"] += 1
            else:
                store.set_verdict(finding["id"], verdict="false-positive", state="recorded")
                counts["false-positive"] += 1
            continue

        # Full evidence gate for non-presence classes
        has_reach = "reachability" in kinds or "presence" in kinds
        has_trust = "trust-boundary" in kinds or vuln_class == "antares-localization"
        has_impact = "impact" in kinds
        if has_reach and has_trust and has_impact and citations_ok:
            store.set_verdict(finding["id"], verdict="true-positive", state="confirmed")
            counts["true-positive"] += 1
            # Rule-gap: exploratory/antares TP with no CodeGuard rule coverage
            rule_id = finding.get("rule_id") or ""
            if finding["source"] == "antares" and not rule_id.startswith("codeguard-"):
                if rule_id not in rule_ids:
                    store.add_rule_gap(
                        run_id,
                        finding["id"],
                        vuln_class,
                        pattern_note="Exploratory/Antares true-positive with no matching CodeGuard rule.",
                    )
                    counts["rule-gaps"] += 1
        elif citations_ok and (has_reach or has_impact):
            store.set_verdict(finding["id"], verdict="needs-review", state="needs-review")
            counts["needs-review"] += 1
        else:
            store.set_verdict(
                finding["id"],
                verdict="false-positive",
                state="recorded",
                summary=(finding.get("summary") or "") + " [demoted: evidence gate failed]",
            )
            counts["false-positive"] += 1
    return counts


def llm_codeguard_sweep(
    store: Store,
    run_id: str,
    root: Path,
    index_files: list[dict[str, Any]],
    *,
    client: ChatClient | None = None,
    limit: int = 20,
) -> int:
    """Optional Phase-3 LLM rule evaluation against localhost model."""
    url = os.environ.get("ACYL_TRIAGE_MODEL_URL") or os.environ.get("ACYL_MODEL_URL")
    if not url and client is None:
        return 0
    client = client or ChatClient(base_url=url)
    rules_dir = default_rules_dir()
    rule_files = sorted(rules_dir.glob("codeguard-1-*.mdc"))[:3]
    if not rule_files:
        return 0
    created = 0
    candidates = [f for f in index_files if f.get("language") in {"python", "javascript", "typescript"}][
        :limit
    ]
    for file_info in candidates:
        path = root / file_info["path"]
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:4000]
        except OSError:
            continue
        for rule_path in rule_files:
            prompt = (
                f"Rule id: {rule_path.stem}\n"
                f"Rule excerpt:\n{rule_path.read_text(encoding='utf-8')[:1500]}\n\n"
                f"File: {file_info['path']}\n```\n{text}\n```\n"
                "Reply with JSON only: {\"hit\": true|false, \"line\": N|null, \"reason\": \"...\"}"
            )
            try:
                content = client.chat(
                    [
                        {
                            "role": "system",
                            "content": "You are a CodeGuard rule evaluator. Be conservative.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.1,
                    max_tokens=200,
                )
            except Exception:
                return created
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if not match:
                continue
            try:
                data = json.loads(match.group(0))
            except json.JSONDecodeError:
                continue
            if not data.get("hit"):
                continue
            from acyl.fingerprint import fingerprint

            line = data.get("line")
            fp = fingerprint(file_info["path"], rule_path.stem, "codeguard-llm")
            finding_id = store.upsert_finding(
                run_id=run_id,
                fingerprint=fp,
                title=f"CodeGuard LLM hit: {rule_path.stem}",
                vuln_class="codeguard-llm",
                source="codeguard-llm",
                summary=str(data.get("reason") or ""),
                severity="medium",
                path=file_info["path"],
                symbol=rule_path.stem,
                rule_id=rule_path.stem,
                metadata={"line": line},
            )
            store.add_evidence(
                finding_id,
                kind="presence",
                path=file_info["path"],
                line=int(line) if line else None,
                note=str(data.get("reason") or ""),
            )
            store.add_evidence(
                finding_id,
                kind="impact",
                path=file_info["path"],
                note="LLM-evaluated CodeGuard rule indicated a violation.",
            )
            created += 1
    store.set_coverage(run_id, "codeguard-llm", "llm-sweep", "done", area="sast")
    return created
