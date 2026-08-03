"""Path scope matching and documentation-context heuristics."""

from __future__ import annotations

import fnmatch
from typing import Any

# Soft-demote (not hard-exclude) when a finding path looks like non-product
# instructional / fixture / agent-skill material that remained in scope.
_DOC_PATH_SUFFIXES = (".md", ".mdc", ".rst", ".txt", ".adoc")


def normalize_rel_path(path: str | None) -> str:
    """Normalize a finding/repo-relative path for matching."""
    if not path:
        return ""
    text = path.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def path_excluded(rel: str, exclude: list[str]) -> bool:
    """Return True if *rel* matches any exclude glob (same rules as the indexer)."""
    rel = normalize_rel_path(rel)
    if not rel or not exclude:
        return False
    for pattern in exclude:
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern.rstrip("/")):
            return True
        # directory prefixes
        parts = rel.split("/")
        for i in range(len(parts)):
            prefix = "/".join(parts[: i + 1])
            if fnmatch.fnmatch(prefix, pattern.rstrip("/**")) or fnmatch.fnmatch(
                prefix + "/", pattern
            ):
                return True
    return False


def scope_excludes(scope: dict[str, Any] | None) -> list[str]:
    """Resolve exclude patterns from a scope dict, defaulting to DEFAULT_SCOPE."""
    from acyl.target import DEFAULT_SCOPE

    if scope is None:
        return list(DEFAULT_SCOPE.get("exclude") or [])
    if "exclude" not in scope:
        return list(DEFAULT_SCOPE.get("exclude") or [])
    return list(scope.get("exclude") or [])


def documentation_context_reason(path: str | None) -> str | None:
    """If *path* looks like docs/skills/fixtures/examples, return an auditable reason.

    Used to demote attention (confirmed → needs-review), not to rewrite severity.
    Returns None when no soft context applies.
    """
    rel = normalize_rel_path(path)
    if not rel:
        return None
    parts = rel.split("/")
    lower_parts = [p.lower() for p in parts]
    name = lower_parts[-1] if lower_parts else ""

    if ".cursor" in lower_parts:
        return (
            "path under .cursor; likely agent skill/config material, not production code"
        )
    if ".claude" in lower_parts:
        return (
            "path under .claude; likely agent config material, not production code"
        )
    if name == "skill.md":
        return "SKILL.md agent skill document; likely instructional examples"
    if "skills" in lower_parts:
        return "path under a skills/ directory; likely instructional agent material"
    if "fixtures" in lower_parts:
        return "path under fixtures/; likely intentional test fixture data"
    if "examples" in lower_parts:
        return "path under examples/; likely sample/demo material"
    if "docs" in lower_parts and name.endswith(_DOC_PATH_SUFFIXES):
        return "documentation path; likely illustrative examples"
    return None


def looks_like_placeholder_secret(snippet: str | None) -> bool:
    """Heuristic: secret-shaped text that is obviously a placeholder/example."""
    if not snippet:
        return False
    text = snippet.lower()
    markers = (
        "example",
        "placeholder",
        "your_",
        "changeme",
        "todo",
        "xxx",
        "redacted",
        "dummy",
        "sample",
        "not_a_real",
        "insert_",
    )
    return any(m in text for m in markers)
