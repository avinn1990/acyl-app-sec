"""Stable finding fingerprints (path + symbol + vuln_class; no line numbers)."""

from __future__ import annotations

import hashlib
import re


def normalize_path(path: str | None) -> str:
    if not path:
        return ""
    value = path.replace("\\", "/").lstrip("./")
    return value


def normalize_symbol(symbol: str | None) -> str:
    if not symbol:
        return ""
    return re.sub(r"\s+", "", symbol)


def normalize_class(vuln_class: str) -> str:
    return re.sub(r"\s+", "-", vuln_class.strip().lower())


def fingerprint(path: str | None, symbol: str | None, vuln_class: str) -> str:
    key = "|".join(
        [
            normalize_path(path),
            normalize_symbol(symbol),
            normalize_class(vuln_class),
        ]
    )
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"{normalize_class(vuln_class)}:{digest}"
