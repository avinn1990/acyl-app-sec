"""Format presence/impact evidence as File | Presence | Impact rows."""

from __future__ import annotations

from typing import Any


def _loc_key(ev: dict[str, Any]) -> tuple[str, int | None]:
    path = str(ev.get("path") or "").strip()
    line = ev.get("line")
    try:
        line_i = int(line) if line is not None and str(line).strip() != "" else None
    except (TypeError, ValueError):
        line_i = None
    if line_i is not None and line_i <= 0:
        line_i = None
    return path, line_i


def format_file_loc(path: str | None, line: int | None = None) -> str:
    """Human-readable file location for table cells."""
    text = (path or "").strip()
    if not text:
        return "—"
    if line is not None and int(line) > 0:
        return f"{text}:{int(line)}"
    return text


def group_presence_impact(
    evidence: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    """Split evidence into paired presence/impact rows plus leftover kinds.

    Each row dict has keys: file, presence, impact (strings; "—" when missing).
    Leftover evidence (context, reachability, trace, …) is returned unchanged.
    """
    by_loc: dict[tuple[str, int | None], dict[str, Any]] = {}
    other: list[dict[str, Any]] = []
    order: list[tuple[str, int | None]] = []

    for ev in evidence:
        kind = str(ev.get("kind") or "").lower()
        if kind not in {"presence", "impact"}:
            other.append(ev)
            continue
        key = _loc_key(ev)
        if key not in by_loc:
            by_loc[key] = {"path": key[0], "line": key[1], "presence": None, "impact": None}
            order.append(key)
        slot = by_loc[key]
        note = str(ev.get("note") or "").strip() or "—"
        if kind == "presence":
            slot["presence"] = note
        else:
            slot["impact"] = note

    rows: list[dict[str, str]] = []
    for key in order:
        slot = by_loc[key]
        rows.append(
            {
                "file": format_file_loc(slot.get("path"), slot.get("line")),
                "presence": str(slot.get("presence") or "—"),
                "impact": str(slot.get("impact") or "—"),
            }
        )
    return rows, other


def _cell(text: str) -> str:
    """Escape markdown table cell content."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def markdown_evidence_section(evidence: list[dict[str, Any]]) -> list[str]:
    """Markdown lines for an Evidence section using Option B table layout."""
    rows, other = group_presence_impact(evidence)
    lines: list[str] = ["Evidence:", ""]
    if rows:
        lines.extend(
            [
                "| File | Presence | Impact |",
                "|---|---|---|",
            ]
        )
        for row in rows:
            file_cell = "—" if row["file"] == "—" else f"`{_cell(row['file'])}`"
            lines.append(
                f"| {file_cell} | {_cell(row['presence'])} | {_cell(row['impact'])} |"
            )
        lines.append("")
    if other:
        if rows:
            lines.extend(["Other evidence:", ""])
        for ev in other:
            loc = f"`{ev.get('path')}`" if ev.get("path") else "—"
            if ev.get("line"):
                loc += f":{ev['line']}"
            lines.append(f"- **{ev.get('kind')}** {loc} — {ev.get('note') or ''}")
        lines.append("")
    if not rows and not other:
        lines.append("_No evidence recorded._")
        lines.append("")
    return lines
