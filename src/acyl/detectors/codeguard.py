"""CodeGuard presence-rule sweep (deterministic patterns from rule corpus)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from acyl.fingerprint import fingerprint
from acyl.paths import default_rules_dir
from acyl.substrate import Store

# High-signal presence patterns aligned with CodeGuard tiers.
PRESENCE_RULES: list[tuple[str, str, re.Pattern[str], str, str]] = [
    (
        "codeguard-1-hardcoded-credentials",
        "hardcoded-credentials",
        re.compile(
            r"(?i)(password|passwd|api_key|apikey|secret_key|access_token)\s*=\s*['\"][^'\"]{6,}['\"]"
        ),
        "high",
        "Hardcoded credential assignment",
    ),
    (
        "codeguard-1-crypto-algorithms",
        "weak-crypto",
        re.compile(r"\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)|CryptoJS\.MD5|DES\.new|RC4"),
        "medium",
        "Weak or deprecated cryptographic primitive",
    ),
    (
        "codeguard-0-input-validation-injection",
        "command-injection",
        re.compile(
            r"\bos\.system\s*\(|\bsubprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True"
            r"|child_process\.exec\s*\(|eval\s*\("
        ),
        "high",
        "Potential command/code injection sink",
    ),
    (
        "codeguard-0-api-web-services",
        "insecure-transport",
        re.compile(r"http://(?!localhost|127\.0\.0\.1|\[::1\])[^\s'\"]+"),
        "medium",
        "Cleartext HTTP URL in source",
    ),
]


@dataclass
class RuleHit:
    rule_id: str
    vuln_class: str
    path: str
    line: int
    snippet: str
    severity: str
    title: str
    symbol: str


def list_rule_files(rules_dir: Path | None = None) -> list[Path]:
    root = rules_dir or default_rules_dir()
    if not root.is_dir():
        return []
    return sorted(root.glob("codeguard-*.mdc")) + sorted(root.glob("codeguard-*.md"))


def detect_codeguard_presence(
    store: Store,
    run_id: str,
    root: Path,
    rules_dir: Path | None = None,
) -> int:
    _ = list_rule_files(rules_dir)  # ensure corpus is present / discoverable
    skip_dirs = {".git", "node_modules", ".venv", "venv", "dist", "build", "vendor", "rules"}
    hits: list[RuleHit] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.suffix.lower() not in {
            ".py",
            ".js",
            ".ts",
            ".tsx",
            ".jsx",
            ".go",
            ".java",
            ".rb",
            ".php",
            ".c",
            ".cpp",
            ".cs",
            ".sh",
            ".env",
            ".yml",
            ".yaml",
            ".json",
            ".toml",
        }:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        for rule_id, vuln_class, pattern, severity, title in PRESENCE_RULES:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                # crude symbol: nearest def/function above
                before = text[: match.start()].splitlines()
                symbol = ""
                for prev in reversed(before[-30:]):
                    m = re.search(r"\b(?:def|function|func|class)\s+(\w+)", prev)
                    if m:
                        symbol = m.group(1)
                        break
                hits.append(
                    RuleHit(
                        rule_id=rule_id,
                        vuln_class=vuln_class,
                        path=rel,
                        line=line,
                        snippet=match.group(0)[:120],
                        severity=severity,
                        title=title,
                        symbol=symbol or rule_id,
                    )
                )
    count = 0
    for hit in hits:
        fp = fingerprint(hit.path, hit.symbol, hit.vuln_class)
        finding_id = store.upsert_finding(
            run_id=run_id,
            fingerprint=fp,
            title=hit.title,
            vuln_class=hit.vuln_class,
            source="codeguard",
            summary=f"{hit.title} at `{hit.path}`",
            severity=hit.severity,
            path=hit.path,
            symbol=hit.symbol,
            rule_id=hit.rule_id,
            metadata={"line": hit.line, "snippet": hit.snippet},
        )
        store.add_evidence(
            finding_id,
            kind="presence",
            path=hit.path,
            symbol=hit.symbol,
            line=hit.line,
            note=f"CodeGuard presence pattern for `{hit.rule_id}` matched: {hit.snippet}",
        )
        store.add_evidence(
            finding_id,
            kind="impact",
            path=hit.path,
            symbol=hit.symbol,
            line=hit.line,
            note="Presence of this pattern indicates a security-relevant defect class.",
        )
        count += 1
    store.set_coverage(run_id, "codeguard-presence", "pattern-sweep", "done", area="sast")
    return count
