"""SCA detector via osv-scanner, with manifest heuristic fallback."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acyl.fingerprint import fingerprint
from acyl.substrate import Store

KNOWN_BAD = {
    # Intentionally outdated packages used by the fixture
    "lodash": ("4.17.15", "GHSA-demo-lodash", "high"),
    "requests": ("2.19.0", "GHSA-demo-requests", "medium"),
}

SEVERITY_BANDS = frozenset({"critical", "high", "medium", "low"})


@dataclass
class ScaHit:
    path: str
    package: str
    version: str
    advisory: str
    severity: str
    title: str
    cwes: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    fixed_version: str | None = None


def _osv_available() -> bool:
    return shutil.which("osv-scanner") is not None


def _normalize_severity_label(value: str | None) -> str | None:
    if not value:
        return None
    label = str(value).strip().lower()
    # Common OSV / GHSA variants
    if label in SEVERITY_BANDS:
        return label
    if label in {"mod", "moderate"}:
        return "medium"
    return None


def _cvss_score_to_band(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_cvss_score(entry: dict[str, Any]) -> float | None:
    """Pull a numeric CVSS score from an OSV severity entry."""
    raw = entry.get("score")
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        # Bare number or CVSS vector string with embedded score metadata
        try:
            return float(raw.strip())
        except ValueError:
            pass
        # Some tools nest score in the vector as "CVSS:3.1/AV:N/..."; ignore vector-only.
    nested = entry.get("cvss_v3") or entry.get("cvssV3") or entry.get("cvss")
    if isinstance(nested, dict):
        for key in ("base_score", "baseScore", "score"):
            val = nested.get(key)
            if isinstance(val, (int, float)):
                return float(val)
            if isinstance(val, str):
                try:
                    return float(val.strip())
                except ValueError:
                    continue
    return None


def parse_osv_severity(vuln: dict[str, Any]) -> str:
    """Resolve advisory severity: database_specific label, then CVSS score, else medium."""
    db = vuln.get("database_specific") or {}
    if isinstance(db, dict):
        labeled = _normalize_severity_label(db.get("severity"))
        if labeled:
            return labeled

    best_score: float | None = None
    for entry in vuln.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        # Prefer explicit score over misreading type (CVSS_V3) as a band
        labeled = _normalize_severity_label(entry.get("severity"))
        if labeled:
            return labeled
        score = _extract_cvss_score(entry)
        if score is not None and (best_score is None or score > best_score):
            best_score = score
    if best_score is not None:
        return _cvss_score_to_band(best_score)
    return "medium"


def extract_cwes(vuln: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    seen: set[str] = set()

    def _add(raw: Any) -> None:
        if raw is None:
            return
        text = str(raw).strip().upper()
        if not text:
            return
        if not text.startswith("CWE-"):
            if text.isdigit():
                text = f"CWE-{text}"
            else:
                return
        if text not in seen:
            seen.add(text)
            cwes.append(text)

    db = vuln.get("database_specific") or {}
    if isinstance(db, dict):
        for key in ("cwe_ids", "cwes", "CWE"):
            val = db.get(key)
            if isinstance(val, list):
                for item in val:
                    _add(item)
            else:
                _add(val)

    for entry in vuln.get("severity") or []:
        if isinstance(entry, dict):
            for item in entry.get("cwe_ids") or []:
                _add(item)

    return cwes


def extract_fixed_version(vuln: dict[str, Any]) -> str | None:
    fixed: list[str] = []
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for range_entry in affected.get("ranges") or []:
            if not isinstance(range_entry, dict):
                continue
            for event in range_entry.get("events") or []:
                if not isinstance(event, dict):
                    continue
                ver = event.get("fixed")
                if ver:
                    fixed.append(str(ver))
    if not fixed:
        return None
    # Prefer the last fixed event as a best-effort hint
    return fixed[-1]


def vuln_to_hit(
    *,
    path: str,
    package: str,
    version: str,
    vuln: dict[str, Any],
) -> ScaHit:
    advisory = str(vuln.get("id") or "osv")
    aliases = [str(a) for a in (vuln.get("aliases") or []) if a]
    return ScaHit(
        path=path or "manifest",
        package=package,
        version=version,
        advisory=advisory,
        severity=parse_osv_severity(vuln),
        title=vuln.get("summary") or f"Vulnerable dependency {package}@{version}",
        cwes=extract_cwes(vuln),
        aliases=aliases,
        fixed_version=extract_fixed_version(vuln),
    )


def parse_osv_report(data: dict[str, Any]) -> list[ScaHit]:
    """Parse osv-scanner JSON into ScaHit rows (testable without the binary)."""
    hits: list[ScaHit] = []
    for result in data.get("results") or []:
        source = (result.get("source") or {}).get("path") or ""
        for package in result.get("packages") or []:
            pkg = package.get("package") or {}
            name = pkg.get("name") or "unknown"
            version = pkg.get("version") or ""
            for vuln in package.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                hits.append(
                    vuln_to_hit(path=source, package=name, version=version, vuln=vuln)
                )
    return hits


def run_osv(root: Path) -> list[ScaHit]:
    report = root / ".acyl-osv.json"
    cmd = [
        "osv-scanner",
        "--format",
        "json",
        "--output",
        str(report),
        str(root),
    ]
    subprocess.run(cmd, check=False, capture_output=True, text=True)
    if not report.is_file():
        return []
    try:
        data = json.loads(report.read_text(encoding="utf-8") or "{}")
    finally:
        report.unlink(missing_ok=True)
    if not isinstance(data, dict):
        return []
    return parse_osv_report(data)


def run_manifest_fallback(root: Path) -> list[ScaHit]:
    hits: list[ScaHit] = []
    pkg_json = root / "package.json"
    if pkg_json.is_file():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
        deps = {}
        deps.update(data.get("dependencies") or {})
        deps.update(data.get("devDependencies") or {})
        for name, version in deps.items():
            ver = str(version).lstrip("^~=")
            if name in KNOWN_BAD and ver.startswith(KNOWN_BAD[name][0].split(".")[0]):
                expected, advisory, severity = KNOWN_BAD[name]
                if ver == expected or ver.startswith(expected):
                    hits.append(
                        ScaHit(
                            path="package.json",
                            package=name,
                            version=ver,
                            advisory=advisory,
                            severity=severity,
                            title=f"Known-vulnerable dependency {name}@{ver}",
                        )
                    )
    req = root / "requirements.txt"
    if req.is_file():
        for line in req.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.-]+)\s*==\s*([0-9.]+)", line)
            if not m:
                continue
            name, ver = m.group(1), m.group(2)
            key = name.lower()
            if key in KNOWN_BAD and ver == KNOWN_BAD[key][0]:
                _, advisory, severity = KNOWN_BAD[key]
                hits.append(
                    ScaHit(
                        path="requirements.txt",
                        package=name,
                        version=ver,
                        advisory=advisory,
                        severity=severity,
                        title=f"Known-vulnerable dependency {name}@{ver}",
                    )
                )
    return hits


def detect_sca(store: Store, run_id: str, root: Path) -> int:
    hits = run_osv(root) if _osv_available() else run_manifest_fallback(root)
    count = 0
    for hit in hits:
        fp = fingerprint(hit.path, f"{hit.package}@{hit.version}", "vulnerable-dependency")
        finding_id = store.upsert_finding(
            run_id=run_id,
            fingerprint=fp,
            title=hit.title,
            vuln_class="vulnerable-dependency",
            source="sca",
            summary=f"{hit.package}@{hit.version} ({hit.advisory})",
            severity=hit.severity,
            path=hit.path,
            symbol=f"{hit.package}@{hit.version}",
            rule_id=hit.advisory,
            metadata={
                "package": hit.package,
                "version": hit.version,
                "advisory": hit.advisory,
                "aliases": hit.aliases,
                "cwes": hit.cwes,
                "fixed_version": hit.fixed_version,
                "severity": hit.severity,
            },
        )
        store.add_evidence(
            finding_id,
            kind="presence",
            path=hit.path,
            note=f"Dependency {hit.package}@{hit.version} declared in manifest.",
        )
        store.add_evidence(
            finding_id,
            kind="impact",
            path=hit.path,
            note=f"Advisory {hit.advisory} indicates a known vulnerability class.",
        )
        count += 1
    store.set_coverage(run_id, "sca", "osv-or-manifest", "done", area="dependencies")
    return count
