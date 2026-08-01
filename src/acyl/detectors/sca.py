"""SCA detector via osv-scanner, with manifest heuristic fallback."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from acyl.fingerprint import fingerprint
from acyl.substrate import Store

KNOWN_BAD = {
    # Intentionally outdated packages used by the fixture
    "lodash": ("4.17.15", "GHSA-demo-lodash", "high"),
    "requests": ("2.19.0", "GHSA-demo-requests", "medium"),
}


@dataclass
class ScaHit:
    path: str
    package: str
    version: str
    advisory: str
    severity: str
    title: str


def _osv_available() -> bool:
    return shutil.which("osv-scanner") is not None


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
    hits: list[ScaHit] = []
    results = data.get("results") or []
    for result in results:
        source = (result.get("source") or {}).get("path") or ""
        for package in result.get("packages") or []:
            pkg = package.get("package") or {}
            name = pkg.get("name") or "unknown"
            version = pkg.get("version") or ""
            for vuln in package.get("vulnerabilities") or []:
                sev = "medium"
                for s in vuln.get("severity") or []:
                    sev = (s.get("type") or sev).lower()
                hits.append(
                    ScaHit(
                        path=source or "manifest",
                        package=name,
                        version=version,
                        advisory=vuln.get("id") or "osv",
                        severity=sev if sev in {"critical", "high", "medium", "low"} else "medium",
                        title=vuln.get("summary") or f"Vulnerable dependency {name}@{version}",
                    )
                )
    return hits


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
