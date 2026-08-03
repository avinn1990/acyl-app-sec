"""Secrets detector via gitleaks, with a regex fallback."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from acyl.fingerprint import fingerprint
from acyl.scope import normalize_rel_path, path_excluded, scope_excludes
from acyl.substrate import Store

SECRET_PATTERNS = [
    (
        "aws-access-key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "critical",
        "Possible AWS access key id",
    ),
    (
        "generic-api-key",
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
        "high",
        "Hardcoded secret-like assignment",
    ),
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "critical",
        "Private key material in source",
    ),
]


@dataclass
class SecretHit:
    path: str
    line: int
    rule_id: str
    snippet: str
    severity: str
    title: str


def _gitleaks_available() -> bool:
    return shutil.which("gitleaks") is not None


def _relativize_hit_path(root: Path, raw: str) -> str:
    """Normalize gitleaks/file paths to repo-relative posix paths."""
    text = normalize_rel_path(raw)
    if not text:
        return ""
    candidate = Path(text)
    try:
        if candidate.is_absolute():
            return candidate.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return text
    return text


def run_gitleaks(root: Path) -> list[SecretHit]:
    report = root / ".acyl-gitleaks.json"
    cmd = [
        "gitleaks",
        "detect",
        "--source",
        str(root),
        "--no-git",
        "--report-format",
        "json",
        "--report-path",
        str(report),
        "--exit-code",
        "0",
    ]
    subprocess.run(cmd, check=False, capture_output=True, text=True)
    if not report.is_file():
        return []
    try:
        data = json.loads(report.read_text(encoding="utf-8") or "[]")
    finally:
        report.unlink(missing_ok=True)
    hits: list[SecretHit] = []
    for item in data:
        hits.append(
            SecretHit(
                path=item.get("File") or item.get("file") or "",
                line=int(item.get("StartLine") or item.get("startLine") or 0),
                rule_id=item.get("RuleID") or item.get("RuleId") or "gitleaks",
                snippet=(item.get("Secret") or item.get("Match") or "")[:80],
                severity="high",
                title=item.get("Description") or "Secret detected by gitleaks",
            )
        )
    return hits


def run_regex_fallback(root: Path, *, exclude: list[str] | None = None) -> list[SecretHit]:
    hits: list[SecretHit] = []
    skip_dirs = {".git", "node_modules", ".venv", "venv", "dist", "build", "vendor"}
    exclude = exclude or []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".woff", ".zip", ".pdf"}:
            continue
        rel = path.relative_to(root).as_posix()
        if path_excluded(rel, exclude):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rule_id, pattern, severity, title in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                hits.append(
                    SecretHit(
                        path=rel,
                        line=line,
                        rule_id=rule_id,
                        snippet=match.group(0)[:80],
                        severity=severity,
                        title=title,
                    )
                )
    return hits


def _filter_hits(root: Path, hits: list[SecretHit], exclude: list[str]) -> list[SecretHit]:
    kept: list[SecretHit] = []
    for hit in hits:
        rel = _relativize_hit_path(root, hit.path)
        if path_excluded(rel, exclude):
            continue
        hit.path = rel or hit.path
        kept.append(hit)
    return kept


def detect_secrets(
    store: Store,
    run_id: str,
    root: Path,
    scope: dict[str, Any] | None = None,
) -> int:
    exclude = scope_excludes(scope)
    raw = run_gitleaks(root) if _gitleaks_available() else run_regex_fallback(root, exclude=exclude)
    hits = _filter_hits(root, raw, exclude)
    count = 0
    for hit in hits:
        fp = fingerprint(hit.path, hit.rule_id, "secret-exposure")
        finding_id = store.upsert_finding(
            run_id=run_id,
            fingerprint=fp,
            title=hit.title,
            vuln_class="secret-exposure",
            source="secrets",
            summary=f"{hit.title} in `{hit.path}`",
            severity=hit.severity,
            path=hit.path,
            symbol=hit.rule_id,
            rule_id=hit.rule_id,
            metadata={"line": hit.line, "snippet": hit.snippet},
        )
        store.add_evidence(
            finding_id,
            kind="presence",
            path=hit.path,
            line=hit.line,
            note=f"Secret pattern `{hit.rule_id}` matched.",
        )
        store.add_evidence(
            finding_id,
            kind="impact",
            path=hit.path,
            line=hit.line,
            note="Committed secrets may enable unauthorized access.",
        )
        count += 1
    store.set_coverage(run_id, "secrets", "gitleaks-or-regex", "done", area="secrets")
    return count
