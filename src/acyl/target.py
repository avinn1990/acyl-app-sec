"""Pin a target revision and load scope/goals."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from acyl.paths import default_data_dir, default_goals_file


@dataclass
class Target:
    path: Path
    pinned_revision: str
    git_url: str | None
    scope: dict[str, Any]
    goals: list[dict[str, Any]]
    goals_source: str = ""


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


def _read_goals_file(candidate: Path) -> list[dict[str, Any]]:
    if candidate.suffix in {".yml", ".yaml"}:
        data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or []
        if isinstance(data, dict):
            data = data.get("goals", [])
        goals = list(data)
    else:
        goals = parse_goals_markdown(candidate.read_text(encoding="utf-8"))
    if not goals:
        raise ValueError(f"Goals document is empty ({candidate}); refusing to start a scan.")
    return goals


def load_goals(
    path: Path, goals_file: Path | None = None
) -> tuple[list[dict[str, Any]], str]:
    """Load goals with default fallback.

    Resolution order:
      1. Explicit goals_file (--goals)
      2. Target-local goals.md / .acyl/goals.md / goals.yml
      3. Env ACYL_GOALS_FILE
      4. Bundled goals/standard.md
    """
    import os

    if goals_file is not None:
        candidate = Path(goals_file).expanduser()
        if not candidate.is_file():
            raise FileNotFoundError(f"Goals file not found: {candidate}")
        return _read_goals_file(candidate), str(candidate.resolve())

    for candidate in (
        path / "goals.md",
        path / ".acyl" / "goals.md",
        path / "goals.yml",
        path / "goals.yaml",
    ):
        if candidate.is_file():
            return _read_goals_file(candidate), str(candidate.resolve())

    env_goals = os.environ.get("ACYL_GOALS_FILE")
    if env_goals:
        candidate = Path(env_goals).expanduser()
        if candidate.is_file():
            return _read_goals_file(candidate), str(candidate.resolve())

    bundled = default_goals_file()
    if bundled.is_file():
        return _read_goals_file(bundled), str(bundled.resolve())

    raise ValueError(
        "No goals document found. Bundled goals/standard.md is missing from this install. "
        "Pass --goals or set ACYL_GOALS_FILE."
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
            current = {
                "id": title.lower().replace(" ", "-"),
                "title": title,
                "cwe": None,
                "owasp": None,
                "codeguard": None,
                "body": "",
            }
            continue
        if current is None:
            continue
        lower = line.lower()
        if lower.startswith("cwe:"):
            current["cwe"] = line.split(":", 1)[1].strip()
        elif lower.startswith("id:"):
            current["id"] = line.split(":", 1)[1].strip()
        elif lower.startswith("owasp:"):
            current["owasp"] = line.split(":", 1)[1].strip()
        elif lower.startswith("codeguard:"):
            current["codeguard"] = line.split(":", 1)[1].strip()
        elif line.startswith(("# ", "#acyl")):
            continue
        elif line:
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
                        "owasp": None,
                        "codeguard": None,
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
    goals, goals_source = load_goals(path, goals_file=goals_file)
    return Target(
        path=path,
        pinned_revision=pinned,
        git_url=git_url,
        scope=scope,
        goals=goals,
        goals_source=goals_source,
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
