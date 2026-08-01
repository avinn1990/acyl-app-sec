"""Pin a target revision and load scope/goals."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from acyl.paths import default_data_dir


@dataclass
class Target:
    path: Path
    pinned_revision: str
    git_url: str | None
    scope: dict[str, Any]
    goals: list[dict[str, Any]]


DEFAULT_SCOPE = {
    "include": ["**/*"],
    "exclude": [
        ".git/**",
        "node_modules/**",
        "vendor/**",
        ".venv/**",
        "venv/**",
        "dist/**",
        "build/**",
        "target/**",
        ".cursor/**",
        ".claude/**",
    ],
}


def _run(cmd: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def resolve_revision(path: Path) -> str:
    git_dir = path / ".git"
    if git_dir.exists() or (path / ".git").is_file():
        try:
            return _run(["git", "rev-parse", "HEAD"], cwd=path)
        except subprocess.CalledProcessError:
            pass
    # Non-git trees: hash a stable marker from file mtimes/names
    import hashlib

    h = hashlib.sha256()
    for p in sorted(path.rglob("*")):
        if p.is_file() and ".git" not in p.parts:
            h.update(str(p.relative_to(path)).encode())
            h.update(str(p.stat().st_mtime_ns).encode())
    return f"tree-{h.hexdigest()[:12]}"


def load_scope(path: Path) -> dict[str, Any]:
    for name in ("scope.yml", "scope.yaml", ".acyl/scope.yml"):
        candidate = path / name
        if candidate.is_file():
            data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            merged = dict(DEFAULT_SCOPE)
            merged.update(data)
            return merged
    return dict(DEFAULT_SCOPE)


def load_goals(path: Path, goals_file: Path | None = None) -> list[dict[str, Any]]:
    candidates: list[Path] = []
    if goals_file:
        candidates.append(goals_file)
    candidates.extend(
        [
            path / "goals.md",
            path / ".acyl" / "goals.md",
            path / "goals.yml",
            path / "goals.yaml",
        ]
    )
    for candidate in candidates:
        if not candidate.is_file():
            continue
        if candidate.suffix in {".yml", ".yaml"}:
            data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or []
            if isinstance(data, dict):
                data = data.get("goals", [])
            return list(data)
        return parse_goals_markdown(candidate.read_text(encoding="utf-8"))
    raise ValueError(
        "No goals document found. Create goals.md (or pass --goals). Empty goals block the run."
    )


def parse_goals_markdown(text: str) -> list[dict[str, Any]]:
    goals: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("## "):
            if current:
                goals.append(current)
            title = line[3:].strip()
            current = {"id": title.lower().replace(" ", "-"), "title": title, "cwe": None, "body": ""}
            continue
        if current is None:
            continue
        if line.lower().startswith("cwe:"):
            current["cwe"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("id:"):
            current["id"] = line.split(":", 1)[1].strip()
        elif line.startswith("- ") or line:
            current["body"] = (current.get("body") or "") + line + "\n"
    if current:
        goals.append(current)
    # Also accept bullet-only goals without headings
    if not goals:
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("- "):
                item = line[2:].strip()
                cwe = None
                if item.upper().startswith("CWE-"):
                    cwe = item.split()[0]
                goals.append(
                    {
                        "id": item.lower().replace(" ", "-")[:64],
                        "title": item,
                        "cwe": cwe,
                        "body": item,
                    }
                )
    if not goals:
        raise ValueError("Goals document is empty; refusing to start a scan.")
    return goals


def prepare_target(
    *,
    path: Path | None = None,
    git_url: str | None = None,
    goals_file: Path | None = None,
    revision: str | None = None,
) -> Target:
    if path is None and not git_url:
        raise ValueError("Provide a local path or --git-url")
    if git_url:
        cache = default_data_dir() / "clones"
        cache.mkdir(parents=True, exist_ok=True)
        name = git_url.rstrip("/").split("/")[-1].removesuffix(".git")
        dest = cache / name
        if dest.exists():
            _run(["git", "fetch", "--all"], cwd=dest)
        else:
            _run(["git", "clone", git_url, str(dest)])
        if revision:
            _run(["git", "checkout", revision], cwd=dest)
        path = dest
    assert path is not None
    path = path.resolve()
    if not path.exists():
        raise FileNotFoundError(path)
    pinned = revision or resolve_revision(path)
    scope = load_scope(path)
    goals = load_goals(path, goals_file=goals_file)
    return Target(
        path=path,
        pinned_revision=pinned,
        git_url=git_url,
        scope=scope,
        goals=goals,
    )


def copy_pinned_snapshot(target: Target, dest: Path) -> Path:
    """Copy target into dest for sandboxed RO use (excludes .git by default)."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(
        target.path,
        dest,
        ignore=shutil.ignore_patterns(".git", "node_modules", ".venv", "venv", "dist", "build"),
    )
    meta = {
        "pinned_revision": target.pinned_revision,
        "git_url": target.git_url,
        "source_path": str(target.path),
    }
    (dest / ".acyl-target.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return dest
