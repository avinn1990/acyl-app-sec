"""Basic repository index: languages, files, crude symbols."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".md": "markdown",
    ".sh": "shell",
    ".toml": "toml",
}

FUNC_PATTERNS = {
    "python": re.compile(r"^\s*(async\s+)?def\s+(\w+)\s*\(", re.MULTILINE),
    "javascript": re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)|^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(",
        re.MULTILINE,
    ),
    "typescript": re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)|^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(",
        re.MULTILINE,
    ),
    "go": re.compile(r"^\s*func\s+(?:\([^)]+\)\s*)?(\w+)\s*\(", re.MULTILINE),
}


@dataclass
class FileInfo:
    path: str
    language: str
    size: int
    symbols: list[str] = field(default_factory=list)


@dataclass
class Index:
    root: Path
    files: list[FileInfo]
    languages: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "file_count": len(self.files),
            "languages": self.languages,
            "files": [
                {
                    "path": f.path,
                    "language": f.language,
                    "size": f.size,
                    "symbols": f.symbols[:50],
                }
                for f in self.files
            ],
        }


def _excluded(rel: str, exclude: list[str]) -> bool:
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


def build_index(root: Path, scope: dict[str, Any] | None = None) -> Index:
    scope = scope or {}
    exclude = list(scope.get("exclude") or [])
    files: list[FileInfo] = []
    languages: dict[str, int] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if _excluded(rel, exclude):
            continue
        lang = LANG_BY_EXT.get(path.suffix.lower(), "other")
        symbols: list[str] = []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        pattern = FUNC_PATTERNS.get(lang)
        if pattern:
            for match in pattern.finditer(text):
                name = next((g for g in match.groups() if g), None)
                if name:
                    symbols.append(name)
        info = FileInfo(path=rel, language=lang, size=path.stat().st_size, symbols=symbols)
        files.append(info)
        languages[lang] = languages.get(lang, 0) + 1
    return Index(root=root, files=files, languages=languages)
