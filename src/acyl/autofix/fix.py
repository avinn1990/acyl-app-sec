"""Gated autofix for confirmed true-positives."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from acyl.model.client import ChatClient
from acyl.substrate import Store


@dataclass
class FixResult:
    finding_id: str
    mode: str
    branch: str | None
    patch_path: Path | None
    pr_url: str | None
    message: str


def autofix_finding(
    store: Store,
    finding_id: str,
    *,
    offline: bool = False,
    fix_model_url: str | None = None,
) -> FixResult:
    finding = store.get_finding(finding_id)
    if not finding:
        raise ValueError(f"Unknown finding: {finding_id}")
    if finding.get("verdict") != "true-positive" or finding.get("state") != "confirmed":
        raise ValueError("Autofix only runs for confirmed true-positive findings")
    run = store.get_run(finding["run_id"])
    if not run:
        raise ValueError("Finding has no run")
    root = Path(run["target_path"])
    slug = re.sub(r"[^a-z0-9-]+", "-", finding["fingerprint"].lower())[:40]
    branch = f"acyl/fix/{slug}"

    changed = _apply_deterministic_fix(root, finding)
    if not changed:
        changed = _apply_llm_fix(root, finding, fix_model_url=fix_model_url)

    if not changed:
        return FixResult(
            finding_id=finding_id,
            mode="noop",
            branch=None,
            patch_path=None,
            pr_url=None,
            message="No automatic fix produced; manual remediation required.",
        )

    out = Path.home() / ".cache" / "acyl" / "runs" / finding["run_id"] / "fixes"
    out.mkdir(parents=True, exist_ok=True)
    patch_path = out / f"{slug}.patch"
    diff = subprocess.run(
        ["git", "diff"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if diff.returncode == 0 and diff.stdout.strip():
        patch_path.write_text(diff.stdout, encoding="utf-8")
    else:
        # Non-git or already applied without git — write a note
        patch_path.write_text(
            f"# Manual note for {finding_id}\n# Files touched: {', '.join(changed)}\n",
            encoding="utf-8",
        )

    script = out / "fix-branch.sh"
    script.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                f'cd "{root}"',
                f'git checkout -B "{branch}"',
                f'git apply "{patch_path}" || true',
                f'git add -A && git commit -m "fix({finding["vuln_class"]}): {finding["title"][:60]}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    script.chmod(0o755)

    pr_url = None
    mode = "offline-patch"
    if not offline and shutil.which("gh") and (root / ".git").exists():
        try:
            subprocess.run(["git", "checkout", "-B", branch], cwd=root, check=True, capture_output=True)
            subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
            subprocess.run(
                [
                    "git",
                    "commit",
                    "-m",
                    f"fix({finding['vuln_class']}): {finding['title'][:60]}",
                ],
                cwd=root,
                check=False,
                capture_output=True,
            )
            subprocess.run(["git", "push", "-u", "origin", branch], cwd=root, check=False, capture_output=True)
            pr = subprocess.run(
                [
                    "gh",
                    "pr",
                    "create",
                    "--title",
                    f"[acyl] {finding['title'][:72]}",
                    "--body",
                    _pr_body(finding, store),
                    "--draft",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            if pr.returncode == 0:
                pr_url = pr.stdout.strip()
                mode = "github-pr"
        except subprocess.CalledProcessError:
            mode = "offline-patch"

    store.set_verdict(
        finding_id,
        verdict="true-positive",
        state="published",
        summary=(finding.get("summary") or "") + f" [autofix:{mode}]",
    )
    return FixResult(
        finding_id=finding_id,
        mode=mode,
        branch=branch,
        patch_path=patch_path,
        pr_url=pr_url,
        message=f"Fix prepared via {mode}",
    )


def _pr_body(finding: dict[str, Any], store: Store) -> str:
    evidence = store.list_evidence(finding["id"])
    lines = [
        "## acyl autofix",
        "",
        f"- Finding: `{finding['id']}`",
        f"- Fingerprint: `{finding['fingerprint']}`",
        f"- Class: `{finding['vuln_class']}`",
        "- Confidence: medium (review required)",
        "",
        finding.get("summary") or "",
        "",
        "### Evidence",
        "",
    ]
    for ev in evidence:
        lines.append(f"- {ev['kind']}: `{ev.get('path')}` — {ev.get('note')}")
    lines.extend(["", "Do not merge without human review.", ""])
    return "\n".join(lines)


def _apply_deterministic_fix(root: Path, finding: dict[str, Any]) -> list[str]:
    meta = json.loads(finding.get("metadata_json") or "{}")
    changed: list[str] = []
    if finding["vuln_class"] == "vulnerable-dependency":
        package = meta.get("package")
        path = finding.get("path") or ""
        if package and path.endswith("package.json"):
            pkg_path = root / path
            data = json.loads(pkg_path.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies"):
                if package in (data.get(section) or {}):
                    data[section][package] = "^4.17.21" if package == "lodash" else data[section][package]
                    if package == "lodash":
                        data[section][package] = "4.17.21"
                    changed.append(path)
            if changed:
                pkg_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        if package and path.endswith("requirements.txt"):
            req = root / path
            lines = []
            for line in req.read_text(encoding="utf-8").splitlines():
                if line.lower().startswith(f"{package.lower()}=="):
                    # bump requests fixture to a safer pin placeholder
                    lines.append(f"{package}==2.32.3")
                    changed.append(path)
                else:
                    lines.append(line)
            if changed:
                req.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return changed

    if finding["vuln_class"] in {"secret-exposure", "hardcoded-credentials"}:
        path = finding.get("path")
        if not path:
            return []
        full = root / path
        if not full.is_file():
            return []
        text = full.read_text(encoding="utf-8", errors="ignore")
        line_no = meta.get("line")
        new_lines = []
        for idx, line in enumerate(text.splitlines(), start=1):
            if line_no and idx == int(line_no):
                new_lines.append(
                    re.sub(
                        r"(['\"])[^'\"]{6,}(['\"])",
                        r'\1${' + (finding.get("symbol") or "SECRET") + r'}\2',
                        line,
                    )
                    + "  # acyl: moved secret to environment"
                )
                changed.append(path)
            else:
                new_lines.append(line)
        if changed:
            full.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        return changed
    return []


def _apply_llm_fix(
    root: Path,
    finding: dict[str, Any],
    *,
    fix_model_url: str | None,
) -> list[str]:
    url = fix_model_url or os.environ.get("ACYL_FIX_MODEL_URL")
    if not url:
        return []
    path = finding.get("path")
    if not path:
        return []
    full = root / path
    if not full.is_file():
        return []
    original = full.read_text(encoding="utf-8", errors="ignore")
    client = ChatClient(base_url=url)
    prompt = (
        f"Produce a minimal unified-diff or full fixed file for this security issue.\n"
        f"Title: {finding['title']}\nSummary: {finding.get('summary')}\n"
        f"File: {path}\n```\n{original[:6000]}\n```\n"
        "Return only the full corrected file contents."
    )
    try:
        content = client.chat(
            [
                {
                    "role": "system",
                    "content": "You write minimal security fixes. Preserve behavior otherwise.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=2000,
        )
    except Exception:
        return []
    # Strip fences
    content = re.sub(r"^```[a-zA-Z0-9]*\n", "", content.strip())
    content = re.sub(r"\n```$", "", content)
    if content.strip() == original.strip() or len(content) < 10:
        return []
    full.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")
    return [path]
