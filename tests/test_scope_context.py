"""Tests for scope matching and documentation-context heuristics."""

from acyl.scope import (
    documentation_context_reason,
    looks_like_placeholder_secret,
    path_excluded,
    scope_excludes,
)
from acyl.target import DEFAULT_SCOPE


def test_path_excluded_cursor_glob():
    exclude = list(DEFAULT_SCOPE["exclude"])
    assert path_excluded(".cursor/skills/security-review/SKILL.md", exclude)
    assert path_excluded(".claude/settings.json", exclude)
    assert not path_excluded("packages/backend/src/app.py", exclude)


def test_scope_excludes_defaults_when_missing():
    assert ".cursor/**" in scope_excludes(None)
    assert ".cursor/**" in scope_excludes({})
    assert scope_excludes({"exclude": []}) == []
    assert scope_excludes({"exclude": ["docs/**"]}) == ["docs/**"]


def test_documentation_context_reasons():
    assert documentation_context_reason(".cursor/skills/foo/SKILL.md")
    assert documentation_context_reason("docs/guide.md")
    assert documentation_context_reason("packages/examples/demo.py")
    assert documentation_context_reason("fixtures/vulnerable-app/app.py")
    assert documentation_context_reason(None) is None
    assert documentation_context_reason("src/auth/login.py") is None


def test_placeholder_secret_heuristic():
    assert looks_like_placeholder_secret("AKIAIOSFODNN7EXAMPLE")
    assert looks_like_placeholder_secret("password = 'changeme123'")
    assert not looks_like_placeholder_secret("AKIAJDKEISHFJDUEISHF")
