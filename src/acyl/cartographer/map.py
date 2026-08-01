"""Generate a lightweight security map Markdown artifact."""

from __future__ import annotations

from pathlib import Path

from acyl.indexer import Index

ENTRY_HINTS = (
    "main.py",
    "app.py",
    "server.py",
    "index.js",
    "index.ts",
    "main.go",
    "cmd/",
    "routes/",
    "api/",
    "handlers/",
)


def write_security_map(index: Index, dest: Path) -> Path:
    entry_points = [
        f.path
        for f in index.files
        if any(hint in f.path for hint in ENTRY_HINTS)
    ][:40]
    lines = [
        "# Security map",
        "",
        f"Root: `{index.root}`",
        f"Files indexed: {len(index.files)}",
        "",
        "## Languages",
        "",
    ]
    for lang, count in sorted(index.languages.items(), key=lambda x: -x[1]):
        lines.append(f"- {lang}: {count}")
    lines.extend(["", "## Likely entry points", ""])
    if entry_points:
        for p in entry_points:
            lines.append(f"- `{p}`")
    else:
        lines.append("- (none detected from heuristics)")
    lines.extend(
        [
            "",
            "## Trust boundaries (template)",
            "",
            "- Untrusted: HTTP/API handlers, webhook receivers, CLI args, uploaded files",
            "- Semi-trusted: authenticated sessions, internal service calls",
            "- Trusted: local config loaded from operator-controlled paths, pinned deps",
            "",
            "## Sensitive assets",
            "",
            "- Credentials / secrets in source or env templates",
            "- Dependency manifests (`package.json`, `pyproject.toml`, `go.mod`, etc.)",
            "- Authn/authz and session code",
            "",
            "_This map is context for later roles, not ground truth._",
            "",
        ]
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines), encoding="utf-8")
    return dest
