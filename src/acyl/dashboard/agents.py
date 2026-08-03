"""Build dashboard-facing agent / pipeline status from durable task rows."""

from __future__ import annotations

from typing import Any

from acyl.orchestrator.config import (
    ROLE_CARTOGRAPHER,
    ROLE_DETECTOR_CODEGUARD,
    ROLE_DETECTOR_SCA,
    ROLE_DETECTOR_SECRETS,
    ROLE_INDEXER,
    ROLE_REPORTER,
    ROLE_TRIAGER,
)

# Canonical pipeline order for the status board.
PIPELINE_FAMILIES: tuple[str, ...] = (
    "indexer",
    "cartographer",
    "detector",
    "triager",
    "reporter",
)

ROLE_LABELS: dict[str, str] = {
    ROLE_INDEXER: "Indexer",
    ROLE_CARTOGRAPHER: "Cartographer",
    "detector.secrets": "Secrets detector",
    "detector.sca": "SCA detector",
    "detector.codeguard": "CodeGuard detector",
    "detector.antares": "Antares detector",
    "detector.codeguard_llm": "CodeGuard LLM",
    ROLE_TRIAGER: "Triager",
    ROLE_REPORTER: "Reporter",
}

FAMILY_LABELS: dict[str, str] = {
    "indexer": "Indexer",
    "cartographer": "Cartographer",
    "detector": "Detectors",
    "triager": "Triager",
    "reporter": "Reporter",
}

# Roles always expected once cartographer finishes (excluding optional Antares/LLM).
CORE_ROLES: tuple[str, ...] = (
    ROLE_INDEXER,
    ROLE_CARTOGRAPHER,
    ROLE_DETECTOR_SECRETS,
    ROLE_DETECTOR_SCA,
    ROLE_DETECTOR_CODEGUARD,
    ROLE_TRIAGER,
    ROLE_REPORTER,
)

# Map progress-callback phases → pipeline family for jobs that have no DB yet.
PHASE_FAMILY: dict[str, str] = {
    "queued": "indexer",
    "starting": "indexer",
    "index": "indexer",
    "cartographer": "cartographer",
    "secrets": "detector",
    "sca": "detector",
    "codeguard": "detector",
    "antares": "detector",
    "codeguard_llm": "detector",
    "triage": "triager",
    "report": "reporter",
    "done": "reporter",
}

_TASK_TO_UI = {
    "open": "queued",
    "claimed": "running",
    "closed": "done",
    "blocked": "blocked",
}


def role_family(role: str) -> str:
    if role.startswith("detector."):
        return "detector"
    return role


def _rollup_state(task_states: list[str]) -> str:
    """Derive a family-level state from child task states (DB values)."""
    if not task_states:
        return "pending"
    if any(s == "blocked" for s in task_states):
        return "blocked"
    if any(s == "claimed" for s in task_states):
        return "running"
    if any(s == "open" for s in task_states):
        return "running" if any(s == "closed" for s in task_states) else "queued"
    if all(s == "closed" for s in task_states):
        return "done"
    return "pending"


def _agent_from_task(task: dict[str, Any]) -> dict[str, Any]:
    role = str(task.get("role") or "")
    state = str(task.get("state") or "open")
    payload = task.get("payload") or {}
    goal = payload.get("goal") if isinstance(payload, dict) else None
    label = ROLE_LABELS.get(role, role)
    if role == "detector.antares" and goal:
        label = f"Antares · {goal}"
    return {
        "role": role,
        "family": role_family(role),
        "label": label,
        "state": _TASK_TO_UI.get(state, state),
        "task_state": state,
        "task_id": task.get("task_id") or task.get("id"),
        "agent_id": task.get("agent_id"),
        "claim_id": task.get("claim_id"),
        "claimed_at": task.get("claimed_at"),
        "heartbeat_at": task.get("heartbeat_at"),
        "updated_at": task.get("updated_at"),
        "goal": goal,
    }


def _pending_agent(role: str) -> dict[str, Any]:
    return {
        "role": role,
        "family": role_family(role),
        "label": ROLE_LABELS.get(role, role),
        "state": "pending",
        "task_state": None,
        "task_id": None,
        "agent_id": None,
        "claim_id": None,
        "claimed_at": None,
        "heartbeat_at": None,
        "updated_at": None,
        "goal": None,
    }


def build_agent_status(
    tasks: list[dict[str, Any]],
    *,
    phase: str | None = None,
    job_status: str | None = None,
) -> dict[str, Any]:
    """Normalize task+claim rows into agents + pipeline summaries for the UI."""
    agents = [_agent_from_task(t) for t in tasks]
    seen_roles = {a["role"] for a in agents}

    # Fill core pipeline slots that are not yet enqueued so the board stays complete.
    for role in CORE_ROLES:
        if role not in seen_roles:
            agents.append(_pending_agent(role))

    by_family: dict[str, list[dict[str, Any]]] = {f: [] for f in PIPELINE_FAMILIES}
    for agent in agents:
        by_family.setdefault(agent["family"], []).append(agent)

    pipeline: list[dict[str, Any]] = []
    for fam in PIPELINE_FAMILIES:
        members = by_family.get(fam) or []
        real = [m for m in members if m.get("task_state") is not None]
        source = real or members
        if real:
            fam_state = _rollup_state([str(m["task_state"]) for m in real])
        else:
            fam_state = "pending"
        pipeline.append(
            {
                "family": fam,
                "label": FAMILY_LABELS.get(fam, fam),
                "state": fam_state,
                "done": sum(1 for m in source if m["state"] == "done"),
                "active": sum(1 for m in source if m["state"] == "running"),
                "queued": sum(1 for m in source if m["state"] == "queued"),
                "total": len(source),
                "agents": [
                    m["agent_id"]
                    for m in source
                    if m.get("agent_id") and m["state"] == "running"
                ],
            }
        )

    # Jobs with no durable tasks yet: infer progress from the latest phase.
    if not tasks and phase:
        active_fam = PHASE_FAMILY.get(phase)
        if job_status == "completed":
            for step in pipeline:
                step["state"] = "done"
                step["done"] = step["total"]
        elif active_fam and job_status not in {"failed", "cancelled"}:
            reached = False
            for step in pipeline:
                if step["family"] == active_fam:
                    step["state"] = "running"
                    reached = True
                elif not reached:
                    step["state"] = "done"
                    step["done"] = step["total"]

    return {
        "agents": agents,
        "pipeline": pipeline,
        "active_count": sum(1 for a in agents if a["state"] == "running"),
        "phase": phase,
    }
