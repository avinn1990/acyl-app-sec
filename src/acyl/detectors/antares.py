"""Antares terminal-agent localization detector lane."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from acyl.fingerprint import fingerprint
from acyl.model.client import ChatClient
from acyl.sandbox import Sandbox
from acyl.substrate import Store

TOOL_CALL_RE = re.compile(
    r"<tool_call>\s*(\{.*?\})\s*</tool_call>",
    re.DOTALL,
)

SYSTEM_PROMPT = """You are a security vulnerability localization agent.
You have access to a terminal with the repository mounted at /workspace/repo/.
Use shell commands (grep, find, cat, etc.) to explore the codebase and identify
files that contain the reported vulnerability. When confident, submit your findings
using submit_vulnerable_files or submit_no_vulnerability_found.
"""


def _parse_tool_call(text: str) -> dict[str, Any] | None:
    match = TOOL_CALL_RE.search(text)
    if not match:
        # Also accept bare JSON tool calls
        try:
            data = json.loads(text.strip())
            if isinstance(data, dict) and "name" in data:
                return data
        except json.JSONDecodeError:
            return None
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


def run_antares_localization(
    store: Store,
    run_id: str,
    root: Path,
    goal: dict[str, Any],
    *,
    artifacts: Path,
    client: ChatClient | None = None,
    max_turns: int = 15,
    use_docker: bool | None = None,
) -> int:
    client = client or ChatClient()
    cwe = goal.get("cwe") or goal.get("title") or goal.get("id")
    body = (goal.get("body") or goal.get("title") or "").strip()
    user = f"Vulnerability to locate:\n{cwe}\n\n{body}".strip()
    messages: list[dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]
    trace: list[dict[str, Any]] = []
    files: list[str] = []
    with Sandbox(root, artifacts / "antares", use_docker=use_docker) as box:
        for _ in range(max_turns):
            try:
                content = client.chat(messages, temperature=0.3, top_p=1.0, max_tokens=512)
            except Exception as exc:
                store.set_coverage(
                    run_id,
                    str(goal.get("id") or cwe),
                    "antares",
                    "error",
                    area="localization",
                )
                store.upsert_finding(
                    run_id=run_id,
                    fingerprint=fingerprint(None, str(cwe), "antares-unavailable"),
                    title=f"Antares unavailable for {cwe}",
                    vuln_class="tooling",
                    source="antares",
                    summary=str(exc),
                    severity="info",
                    metadata={"error": str(exc)},
                    state="recorded",
                )
                return 0
            messages.append({"role": "assistant", "content": content})
            call = _parse_tool_call(content)
            if not call:
                trace.append({"event": "no-tool-call", "content": content[:500]})
                break
            name = call.get("name")
            args = call.get("arguments") or {}
            if name == "terminal":
                command = str(args.get("command") or "")
                result = box.exec(command)
                tool_response = (
                    f"<tool_response>\nexit={result.exit_code}\n"
                    f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}\n</tool_response>"
                )
                messages.append({"role": "user", "content": tool_response})
                trace.append(
                    {
                        "command": command,
                        "exit": result.exit_code,
                        "stdout": result.stdout[:2000],
                        "stderr": result.stderr[:500],
                    }
                )
                continue
            if name == "submit_vulnerable_files":
                raw_files = args.get("files") or args.get("paths") or []
                files = [str(f).lstrip("./") for f in raw_files]
                trace.append({"event": "submit", "files": files})
                break
            if name == "submit_no_vulnerability_found":
                trace.append({"event": "none-found"})
                files = []
                break
            # Unknown tool — feed error
            messages.append(
                {
                    "role": "user",
                    "content": f"<tool_response>Unknown tool: {name}</tool_response>",
                }
            )

    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / f"antares-{goal.get('id', 'goal')}.json").write_text(
        json.dumps({"goal": goal, "trace": trace, "files": files}, indent=2),
        encoding="utf-8",
    )

    count = 0
    for path in files:
        # Keep only files that exist in the target
        if not (root / path).exists():
            continue
        fp = fingerprint(path, str(cwe), "antares-localization")
        finding_id = store.upsert_finding(
            run_id=run_id,
            fingerprint=fp,
            title=f"Antares localized {cwe} in {path}",
            vuln_class="antares-localization",
            source="antares",
            summary=f"Model ranked `{path}` for goal {cwe}",
            severity="medium",
            path=path,
            symbol=str(cwe),
            rule_id=str(cwe),
            metadata={"goal": goal, "trace_steps": len(trace)},
        )
        store.add_evidence(
            finding_id,
            kind="reachability",
            path=path,
            note="Antares exploration trace selected this file as likely vulnerable.",
        )
        store.add_evidence(
            finding_id,
            kind="impact",
            path=path,
            note=f"Goal {cwe}: {body[:200]}",
        )
        # Attach condensed trace
        store.add_evidence(
            finding_id,
            kind="trace",
            path=path,
            note=json.dumps(trace[-5:])[:4000],
        )
        count += 1
    store.set_coverage(
        run_id,
        str(goal.get("id") or cwe),
        "antares",
        "done" if files else "attempted",
        area="localization",
    )
    return count
