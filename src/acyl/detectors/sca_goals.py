"""Synthesize Antares localization goals from SCA findings."""

from __future__ import annotations

import json
import re
from typing import Any

SCA_ANTARES_CAP = 40
_SEVERITY_ORDER = {"critical": 0, "high": 1}


def _parse_metadata(finding: dict[str, Any]) -> dict[str, Any]:
    raw = finding.get("metadata_json") or finding.get("metadata") or {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            data = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}
    return {}


def _advisory_slug(advisory: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", advisory.strip()).strip("-").lower()
    return slug or "advisory"


def synthesize_sca_antares_goals(
    findings: list[dict[str, Any]],
    *,
    limit: int = SCA_ANTARES_CAP,
) -> list[dict[str, Any]]:
    """Build Antares goals for high/critical SCA findings (cap ``limit``, default 40)."""
    candidates: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
    for finding in findings:
        if finding.get("source") != "sca":
            continue
        severity = (finding.get("severity") or "").lower()
        if severity not in _SEVERITY_ORDER:
            continue
        meta = _parse_metadata(finding)
        candidates.append((_SEVERITY_ORDER[severity], finding, meta))

    candidates.sort(
        key=lambda row: (
            row[0],
            str(row[2].get("advisory") or row[1].get("rule_id") or ""),
            str(row[2].get("package") or ""),
        )
    )
    selected = candidates[: max(0, limit)]
    goals: list[dict[str, Any]] = []
    for _, finding, meta in selected:
        package = str(meta.get("package") or (finding.get("symbol") or "").split("@")[0] or "unknown")
        version = str(meta.get("version") or "")
        if not version and "@" in str(finding.get("symbol") or ""):
            version = str(finding.get("symbol")).split("@", 1)[1]
        advisory = str(meta.get("advisory") or finding.get("rule_id") or "osv")
        aliases = meta.get("aliases") or []
        if not isinstance(aliases, list):
            aliases = [aliases]
        cwes = meta.get("cwes") or []
        if not isinstance(cwes, list):
            cwes = [cwes]
        cwes = [str(c) for c in cwes if c]
        fixed = meta.get("fixed_version")
        primary_cwe = cwes[0] if cwes else "CWE-1104"
        alias_text = ", ".join(str(a) for a in aliases) if aliases else "(none)"
        cwe_text = ", ".join(cwes) if cwes else "(none listed)"
        fixed_text = str(fixed) if fixed else "(unknown)"
        summary = finding.get("title") or finding.get("summary") or ""
        body = (
            f"This repository depends on {package}@{version}.\n"
            f"Advisory: {advisory}\n"
            f"Aliases: {alias_text}\n"
            f"CWEs: {cwe_text}\n"
            f"Fixed version (best effort): {fixed_text}\n"
            f"Summary: {summary}\n\n"
            "Locate application call sites or configuration that exercise the vulnerable "
            "behavior of this dependency. Prefer first-party application code over "
            "node_modules/vendor trees. If the package is only a transitive unused "
            "dependency with no reachable usage in app code, submit_no_vulnerability_found."
        )
        goals.append(
            {
                "id": f"sca-{_advisory_slug(advisory)}",
                "cwe": primary_cwe,
                "title": f"{advisory}: {package}@{version}",
                "body": body,
                "metadata": {
                    "sca_finding_id": finding.get("id"),
                    "advisory": advisory,
                    "package": package,
                    "version": version,
                    "aliases": aliases,
                    "cwes": cwes,
                    "fixed_version": fixed,
                    "severity": finding.get("severity"),
                    "source": "sca",
                },
            }
        )
    return goals
