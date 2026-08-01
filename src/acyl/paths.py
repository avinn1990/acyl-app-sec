"""Repository-relative path helpers."""

from __future__ import annotations

import os
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PKG_ROOT.parents[1]


def repo_root() -> Path:
    """Return the acyl-app-sec checkout root when running from source."""
    return REPO_ROOT


def default_rules_dir() -> Path:
    env = os.environ.get("ACYL_RULES_DIR")
    if env:
        return Path(env)
    for candidate in (
        Path("/app/rules"),
        repo_root() / "rules",
        PKG_ROOT / "rules",
    ):
        if candidate.is_dir():
            return candidate
    return repo_root() / "rules"


def default_goals_file() -> Path:
    """Resolve the bundled standard goals pack."""
    for candidate in (
        Path("/app/goals/standard.md"),
        repo_root() / "goals" / "standard.md",
        PKG_ROOT / "goals" / "standard.md",
    ):
        if candidate.is_file():
            return candidate
    return repo_root() / "goals" / "standard.md"


def default_data_dir() -> Path:
    env = os.environ.get("ACYL_DATA_DIR")
    if env:
        path = Path(env)
    else:
        path = Path.home() / ".cache" / "acyl"
    path.mkdir(parents=True, exist_ok=True)
    return path


def models_dir() -> Path:
    return default_data_dir() / "models"


def runs_dir() -> Path:
    return default_data_dir() / "runs"
