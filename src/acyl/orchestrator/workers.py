"""Role workers that claim tasks under configured concurrency caps."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any

from acyl.orchestrator.config import (
    DETECTOR_ROLES,
    MAX_WORKERS,
    ROLE_CARTOGRAPHER,
    ROLE_INDEXER,
    ROLE_REPORTER,
    ROLE_TRIAGER,
    STALE_CLAIM_SECONDS,
    WORKER_IDLE_SLEEP,
)
from acyl.orchestrator.pipeline import PipelineContext, run_task_safely
from acyl.scan_control import ScanCancelled

log = logging.getLogger(__name__)


def _agent_id(family: str, slot: int) -> str:
    return f"{family}-{slot}-{uuid.uuid4().hex[:8]}"


def _worker_loop(
    ctx: PipelineContext,
    *,
    family: str,
    slot: int,
    roles: list[str],
    stop: threading.Event,
) -> None:
    agent_id = _agent_id(family, slot)
    store = ctx.store
    run_id = ctx.run_id
    while not stop.is_set():
        try:
            ctx.cancel_check()
        except ScanCancelled:
            return
        task = store.claim_task(agent_id, run_id=run_id, roles=roles)
        if task is None:
            time.sleep(WORKER_IDLE_SLEEP)
            continue
        claim_id = task["claim_id"]
        hb_stop = threading.Event()

        def _heartbeat(
            stop_event: threading.Event = hb_stop,
            cid: str = claim_id,
        ) -> None:
            while not stop_event.wait(timeout=15.0):
                try:
                    store.heartbeat(cid)
                except Exception:
                    return

        hb_thread = threading.Thread(
            target=_heartbeat,
            name=f"hb-{agent_id}",
            daemon=True,
        )
        hb_thread.start()
        try:
            run_task_safely(ctx, task)
        except ScanCancelled:
            return
        except Exception:
            log.exception("worker %s failed on task %s", agent_id, task.get("id"))
        finally:
            hb_stop.set()
            hb_thread.join(timeout=1.0)


def _reaper_loop(ctx: PipelineContext, stop: threading.Event) -> None:
    while not stop.wait(timeout=10.0):
        try:
            ctx.store.reclaim_stale_claims(STALE_CLAIM_SECONDS, run_id=ctx.run_id)
        except Exception:
            log.exception("reaper failed for run %s", ctx.run_id)


def run_worker_pool(ctx: PipelineContext) -> dict[str, Any]:
    """Start role workers (max 1 each; detectors max 2) and wait for terminal state."""
    stop = threading.Event()
    threads: list[threading.Thread] = []

    families: list[tuple[str, list[str]]] = [
        ("indexer", [ROLE_INDEXER]),
        ("cartographer", [ROLE_CARTOGRAPHER]),
        ("detector", list(DETECTOR_ROLES)),
        ("triager", [ROLE_TRIAGER]),
        ("reporter", [ROLE_REPORTER]),
    ]
    for family, roles in families:
        n = MAX_WORKERS.get(family, 1)
        for slot in range(n):
            t = threading.Thread(
                target=_worker_loop,
                kwargs={
                    "ctx": ctx,
                    "family": family,
                    "slot": slot,
                    "roles": roles,
                    "stop": stop,
                },
                name=f"acyl-{family}-{slot}",
                daemon=True,
            )
            t.start()
            threads.append(t)

    reaper = threading.Thread(
        target=_reaper_loop,
        kwargs={"ctx": ctx, "stop": stop},
        name=f"acyl-reaper-{ctx.run_id[:12]}",
        daemon=True,
    )
    reaper.start()
    threads.append(reaper)

    try:
        while True:
            ctx.cancel_check()
            terminal = ctx.store.run_terminal_task_state(ctx.run_id)
            if terminal == "done":
                break
            if terminal == "blocked":
                raise RuntimeError(
                    f"scan {ctx.run_id} blocked: a task exceeded release retries"
                )
            time.sleep(WORKER_IDLE_SLEEP)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=2.0)

    with ctx.lock:
        return dict(ctx.counts)
