"""SQLite WAL substrate with atomic claim/finding helpers."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id(prefix: str = "") -> str:
    value = uuid.uuid4().hex
    return f"{prefix}{value}" if prefix else value


class Store:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=60.0,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self.migrate()

    def migrate(self) -> None:
        with self._lock:
            sql = SCHEMA_PATH.read_text(encoding="utf-8")
            self._conn.executescript(sql)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def create_run(
        self,
        *,
        target_path: str,
        pinned_revision: str,
        scope: dict[str, Any],
        goals: list[dict[str, Any]],
        git_url: str | None = None,
    ) -> str:
        run_id = new_id("run_")
        now = utcnow()
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO runs (
                  id, target_path, git_url, pinned_revision, scope_json, goals_json,
                  state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)
                """,
                (
                    run_id,
                    target_path,
                    git_url,
                    pinned_revision,
                    json.dumps(scope),
                    json.dumps(goals),
                    now,
                    now,
                ),
            )
        return run_id

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            return dict(row) if row else None

    def set_run_state(self, run_id: str, state: str) -> None:
        with self.tx() as conn:
            conn.execute(
                "UPDATE runs SET state = ?, updated_at = ? WHERE id = ?",
                (state, utcnow(), run_id),
            )

    def add_task(
        self,
        run_id: str,
        role: str,
        payload: dict[str, Any] | None = None,
        priority: int = 100,
    ) -> str:
        task_id = new_id("task_")
        now = utcnow()
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO tasks (id, run_id, role, priority, state, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'open', ?, ?, ?)
                """,
                (task_id, run_id, role, priority, json.dumps(payload or {}), now, now),
            )
        return task_id

    def add_task_if_absent(
        self,
        run_id: str,
        role: str,
        payload: dict[str, Any] | None = None,
        priority: int = 100,
    ) -> str | None:
        """Insert a singleton-role task if none exists for this run/role yet."""
        task_id = new_id("task_")
        now = utcnow()
        with self.tx() as conn:
            existing = conn.execute(
                "SELECT id FROM tasks WHERE run_id = ? AND role = ? LIMIT 1",
                (run_id, role),
            ).fetchone()
            if existing:
                return None
            conn.execute(
                """
                INSERT INTO tasks (id, run_id, role, priority, state, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'open', ?, ?, ?)
                """,
                (task_id, run_id, role, priority, json.dumps(payload or {}), now, now),
            )
        return task_id

    def claim_task(
        self,
        agent_id: str,
        role: str | None = None,
        *,
        run_id: str | None = None,
        roles: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """Atomically claim the highest-priority open task.

        Prefer ``roles`` (any-of) when a worker covers a role family (e.g. detectors).
        ``role`` remains supported for a single exact match.
        """
        role_list = list(roles) if roles else ([role] if role else None)
        with self.tx() as conn:
            clauses = ["state = 'open'"]
            params: list[Any] = []
            if run_id:
                clauses.append("run_id = ?")
                params.append(run_id)
            if role_list:
                placeholders = ",".join("?" for _ in role_list)
                clauses.append(f"role IN ({placeholders})")
                params.extend(role_list)
            sql = f"""
                SELECT * FROM tasks
                WHERE {' AND '.join(clauses)}
                ORDER BY priority ASC, created_at ASC
                LIMIT 1
            """
            row = conn.execute(sql, params).fetchone()
            if not row:
                return None
            now = utcnow()
            claim_id = new_id("claim_")
            try:
                conn.execute(
                    """
                    INSERT INTO claims (id, task_id, agent_id, heartbeat_at, claimed_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (claim_id, row["id"], agent_id, now, now),
                )
            except sqlite3.IntegrityError:
                return None
            conn.execute(
                "UPDATE tasks SET state = 'claimed', updated_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            task = dict(row)
            task["claim_id"] = claim_id
            task["payload"] = json.loads(task["payload_json"])
            return task

    def heartbeat(self, claim_id: str) -> None:
        with self.tx() as conn:
            conn.execute(
                "UPDATE claims SET heartbeat_at = ? WHERE id = ?",
                (utcnow(), claim_id),
            )

    def complete_task(self, task_id: str) -> None:
        with self.tx() as conn:
            conn.execute(
                "UPDATE tasks SET state = 'closed', updated_at = ? WHERE id = ?",
                (utcnow(), task_id),
            )
            conn.execute("DELETE FROM claims WHERE task_id = ?", (task_id,))

    def release_task(self, task_id: str, reason: str = "") -> None:
        with self.tx() as conn:
            conn.execute(
                """
                UPDATE tasks
                SET state = 'open', release_count = release_count + 1, updated_at = ?
                WHERE id = ?
                """,
                (utcnow(), task_id),
            )
            row = conn.execute(
                "SELECT release_count FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if row and row["release_count"] >= 3:
                conn.execute(
                    "UPDATE tasks SET state = 'blocked', updated_at = ? WHERE id = ?",
                    (utcnow(), task_id),
                )
            conn.execute("DELETE FROM claims WHERE task_id = ?", (task_id,))
            _ = reason

    def reclaim_stale_claims(self, stale_seconds: float, *, run_id: str | None = None) -> int:
        """Release claims whose heartbeat is older than ``stale_seconds`` (constitution III)."""
        if stale_seconds <= 0:
            return 0
        cutoff = datetime.now(UTC).timestamp() - stale_seconds
        with self.tx() as conn:
            rows = conn.execute(
                """
                SELECT c.id AS claim_id, c.task_id, c.heartbeat_at, t.run_id
                FROM claims c
                JOIN tasks t ON t.id = c.task_id
                WHERE t.state = 'claimed'
                """
            ).fetchall()
            reclaimed = 0
            for row in rows:
                if run_id and row["run_id"] != run_id:
                    continue
                try:
                    hb = datetime.strptime(row["heartbeat_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
                        tzinfo=UTC
                    )
                except ValueError:
                    continue
                if hb.timestamp() > cutoff:
                    continue
                conn.execute(
                    """
                    UPDATE tasks
                    SET state = 'open', release_count = release_count + 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (utcnow(), row["task_id"]),
                )
                rc = conn.execute(
                    "SELECT release_count FROM tasks WHERE id = ?",
                    (row["task_id"],),
                ).fetchone()
                if rc and rc["release_count"] >= 3:
                    conn.execute(
                        "UPDATE tasks SET state = 'blocked', updated_at = ? WHERE id = ?",
                        (utcnow(), row["task_id"]),
                    )
                conn.execute("DELETE FROM claims WHERE id = ?", (row["claim_id"],))
                reclaimed += 1
            return reclaimed

    def list_tasks(self, run_id: str, *, state: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if state:
                rows = self._conn.execute(
                    "SELECT * FROM tasks WHERE run_id = ? AND state = ? ORDER BY priority, created_at",
                    (run_id, state),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM tasks WHERE run_id = ? ORDER BY priority, created_at",
                    (run_id,),
                ).fetchall()
            out: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                item["payload"] = json.loads(item["payload_json"])
                out.append(item)
            return out

    def count_tasks(self, run_id: str, *, roles: list[str] | None = None) -> dict[str, int]:
        clauses = ["run_id = ?"]
        params: list[Any] = [run_id]
        if roles:
            placeholders = ",".join("?" for _ in roles)
            clauses.append(f"role IN ({placeholders})")
            params.extend(roles)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT state, COUNT(*) AS n FROM tasks
                WHERE {' AND '.join(clauses)}
                GROUP BY state
                """,
                params,
            ).fetchall()
            return {str(r["state"]): int(r["n"]) for r in rows}

    def has_incomplete_tasks(self, run_id: str, *, roles: list[str] | None = None) -> bool:
        counts = self.count_tasks(run_id, roles=roles)
        return any(counts.get(s, 0) > 0 for s in ("open", "claimed", "blocked"))

    def run_terminal_task_state(self, run_id: str) -> str | None:
        """Return 'done' if reporter closed, 'blocked' if any blocked, else None."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT role, state FROM tasks WHERE run_id = ?",
                (run_id,),
            ).fetchall()
            if not rows:
                return None
            if any(r["state"] == "blocked" for r in rows):
                return "blocked"
            reporter = [r for r in rows if r["role"] == "reporter"]
            if reporter and all(r["state"] == "closed" for r in reporter):
                return "done"
            return None

    def upsert_finding(
        self,
        *,
        run_id: str,
        fingerprint: str,
        title: str,
        vuln_class: str,
        source: str,
        summary: str = "",
        severity: str | None = None,
        path: str | None = None,
        symbol: str | None = None,
        rule_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        state: str = "candidate",
    ) -> str:
        now = utcnow()
        with self.tx() as conn:
            existing = conn.execute(
                "SELECT id FROM findings WHERE run_id = ? AND fingerprint = ?",
                (run_id, fingerprint),
            ).fetchone()
            if existing:
                finding_id = existing["id"]
                conn.execute(
                    """
                    UPDATE findings
                    SET title = ?, summary = ?, severity = COALESCE(?, severity),
                        path = COALESCE(?, path), symbol = COALESCE(?, symbol),
                        rule_id = COALESCE(?, rule_id),
                        metadata_json = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        title,
                        summary,
                        severity,
                        path,
                        symbol,
                        rule_id,
                        json.dumps(metadata or {}),
                        now,
                        finding_id,
                    ),
                )
                return finding_id
            finding_id = new_id("find_")
            conn.execute(
                """
                INSERT INTO findings (
                  id, run_id, fingerprint, state, verdict, severity, title, summary,
                  vuln_class, path, symbol, source, rule_id, metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    run_id,
                    fingerprint,
                    state,
                    severity,
                    title,
                    summary,
                    vuln_class,
                    path,
                    symbol,
                    source,
                    rule_id,
                    json.dumps(metadata or {}),
                    now,
                    now,
                ),
            )
            return finding_id

    def add_evidence(
        self,
        finding_id: str,
        *,
        kind: str,
        path: str | None = None,
        symbol: str | None = None,
        line: int | None = None,
        note: str = "",
    ) -> str:
        evidence_id = new_id("ev_")
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO evidence (id, finding_id, kind, path, symbol, line, note, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (evidence_id, finding_id, kind, path, symbol, line, note, utcnow()),
            )
        return evidence_id

    def list_findings(self, run_id: str, state: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if state:
                rows = self._conn.execute(
                    "SELECT * FROM findings WHERE run_id = ? AND state = ? ORDER BY created_at",
                    (run_id, state),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM findings WHERE run_id = ? ORDER BY created_at",
                    (run_id,),
                ).fetchall()
            return [dict(r) for r in rows]

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_evidence(self, finding_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM evidence WHERE finding_id = ? ORDER BY created_at",
                (finding_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def set_verdict(
        self,
        finding_id: str,
        *,
        verdict: str,
        state: str,
        summary: str | None = None,
    ) -> None:
        with self.tx() as conn:
            if summary is None:
                conn.execute(
                    """
                    UPDATE findings
                    SET verdict = ?, state = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (verdict, state, utcnow(), finding_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE findings
                    SET verdict = ?, state = ?, summary = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (verdict, state, summary, utcnow(), finding_id),
                )

    def set_coverage(
        self,
        run_id: str,
        goal: str,
        technique: str,
        state: str,
        area: str = "",
    ) -> None:
        now = utcnow()
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO coverage (id, run_id, goal, area, technique, state, last_attempt_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, goal, technique) DO UPDATE SET
                  state = excluded.state,
                  last_attempt_at = excluded.last_attempt_at,
                  area = excluded.area
                """,
                (new_id("cov_"), run_id, goal, area, technique, state, now),
            )

    def list_coverage(self, run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM coverage WHERE run_id = ? ORDER BY goal, technique",
                (run_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def add_rule_gap(
        self,
        run_id: str,
        finding_id: str,
        vuln_class: str,
        pattern_note: str = "",
    ) -> str:
        gap_id = new_id("gap_")
        with self.tx() as conn:
            conn.execute(
                """
                INSERT INTO rule_gaps (id, run_id, finding_id, vuln_class, pattern_note, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (gap_id, run_id, finding_id, vuln_class, pattern_note, utcnow()),
            )
        return gap_id

    def list_rule_gaps(self, run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM rule_gaps WHERE run_id = ? ORDER BY created_at",
                (run_id,),
            ).fetchall()
            return [dict(r) for r in rows]
