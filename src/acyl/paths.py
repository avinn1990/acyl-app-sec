"""Repository-relative path helpers."""

from __future__ import annotations

from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PKG_ROOT.parents[1]


def repo_root() -> Path:
    """Return the acyl-app-sec checkout root when running from source."""
    return REPO_ROOT


def default_rules_dir() -> Path:
    candidate = repo_root() / "rules"
    if candidate.is_dir():
        return candidate
    return PKG_ROOT / "rules"


def default_data_dir() -> Path:
    return Path.home() / ".cache" / "acyl"


def models_dir() -> Path:
    return default_data_dir() / "models"


def runs_dir() -> Path:
    return default_data_dir() / "runs"
