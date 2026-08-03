"""Cooperative scan cancellation."""

from __future__ import annotations

import threading
from collections.abc import Callable


class ScanCancelled(Exception):
    """Raised when an in-flight scan is force-stopped."""

    def __init__(self, run_id: str | None = None) -> None:
        self.run_id = run_id
        suffix = f" ({run_id})" if run_id else ""
        super().__init__(f"scan cancelled{suffix}")


def make_cancel_check(
    cancel_event: threading.Event | None,
    run_id_holder: list[str | None] | None = None,
) -> Callable[[], None]:
    """Return a no-arg function that raises ScanCancelled when the event is set."""

    def _check() -> None:
        if cancel_event is not None and cancel_event.is_set():
            run_id = run_id_holder[0] if run_id_holder else None
            raise ScanCancelled(run_id)

    return _check
