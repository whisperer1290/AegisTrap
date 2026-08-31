"""Session state store (Core Module 2).

Holds a consistent fake world per attacker session so the LLM never has to
invent state. Everything the response engine shows an attacker is read from
here first; the LLM only *renders* these values (Section 13).

SQLite is used deliberately: the synopsis scopes the state store to SQLite,
and a single-file store keeps the honeypot self-contained on an isolated VM.
Access is serialised through a re-entrant lock because SQLite writes are fast
relative to LLM calls, so lock contention is never the bottleneck here.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegistrap.logging_setup import get_logger
from aegistrap.models import AttackerPersona

log = get_logger("store")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    id                      TEXT PRIMARY KEY,
    session_key             TEXT NOT NULL,
    source_ip               TEXT NOT NULL DEFAULT '',
    user_agent              TEXT NOT NULL DEFAULT '',
    first_seen              REAL NOT NULL,
    last_seen               REAL NOT NULL,
    request_count           INTEGER NOT NULL DEFAULT 0,
    persona                 TEXT NOT NULL DEFAULT 'unknown',
    persona_confidence      REAL NOT NULL DEFAULT 0.0,
    persona_scores          TEXT NOT NULL DEFAULT '{}',
    persona_signals         TEXT NOT NULL DEFAULT '[]',
    world_persona           TEXT NOT NULL DEFAULT 'fintech',
    world_seeded            INTEGER NOT NULL DEFAULT 0,
    authenticated_user_id   TEXT,
    closed_at               REAL,
    reported_at             REAL,
    llm_calls               INTEGER NOT NULL DEFAULT 0,
    llm_tokens              INTEGER NOT NULL DEFAULT 0,
    llm_latency_ms_total    REAL NOT NULL DEFAULT 0.0,
    consistency_violations  INTEGER NOT NULL DEFAULT 0,
    -- Evaluation support: set only for seeded red-team traffic.
    ground_truth_persona    TEXT,
    ground_truth_techniques TEXT NOT NULL DEFAULT '[]',
    experiment_tag          TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_key      ON sessions(session_key);
CREATE INDEX IF NOT EXISTS idx_sessions_lastseen ON sessions(last_seen);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    seq           INTEGER NOT NULL,
    ts            REAL NOT NULL,
    method        TEXT NOT NULL,
    path          TEXT NOT NULL,
    query_string  TEXT NOT NULL DEFAULT '',
    headers       TEXT NOT NULL DEFAULT '{}',
    body          TEXT NOT NULL DEFAULT '',
    status_code   INTEGER NOT NULL DEFAULT 0,
    response      TEXT NOT NULL DEFAULT '',
    generator     TEXT NOT NULL DEFAULT 'template',
    latency_ms    REAL NOT NULL DEFAULT 0.0,
    llm_tokens    INTEGER NOT NULL DEFAULT 0,
    weaknesses    TEXT NOT NULL DEFAULT '[]',
    persona_at_time TEXT NOT NULL DEFAULT 'unknown',
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);

-- The fake world. Generic collection/object shape so the same store backs both
-- the fintech and e-commerce personas, and can absorb objects an attacker
-- "creates" via POST without a migration.
CREATE TABLE IF NOT EXISTS world_objects (
    session_id  TEXT NOT NULL,
    collection  TEXT NOT NULL,
    object_id   TEXT NOT NULL,
    owner_id    TEXT,
    sensitive   INTEGER NOT NULL DEFAULT 0,
    data        TEXT NOT NULL,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    PRIMARY KEY (session_id, collection, object_id)
);
CREATE INDEX IF NOT EXISTS idx_world_owner ON world_objects(session_id, collection, owner_id);

CREATE TABLE IF NOT EXISTS world_counters (
    session_id TEXT NOT NULL,
    name       TEXT NOT NULL,
    value      INTEGER NOT NULL,
    PRIMARY KEY (session_id, name)
);

CREATE TABLE IF NOT EXISTS reports (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    created_at  REAL NOT NULL,
    generator   TEXT NOT NULL DEFAULT 'rules',
    severity    TEXT NOT NULL DEFAULT 'informational',
    confidence  REAL NOT NULL DEFAULT 0.0,
    document    TEXT NOT NULL,
    markdown    TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_reports_session ON reports(session_id);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at);
"""


@dataclass
class Session:
    id: str
    session_key: str
    source_ip: str
    user_agent: str
    first_seen: float
    last_seen: float
    request_count: int
    persona: AttackerPersona
    persona_confidence: float
    persona_scores: dict[str, float]
    persona_signals: list[str]
    world_persona: str
    world_seeded: bool
    authenticated_user_id: str | None
    closed_at: float | None
    reported_at: float | None
    llm_calls: int
    llm_tokens: int
    llm_latency_ms_total: float
    consistency_violations: int
    ground_truth_persona: str | None
    ground_truth_techniques: list[str]
    experiment_tag: str | None

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def is_closed(self) -> bool:
        return self.closed_at is not None


@dataclass
class Event:
    id: int
    session_id: str
    seq: int
    ts: float
    method: str
    path: str
    query_string: str
    headers: dict[str, str]
    body: str
    status_code: int
    response: str
    generator: str
    latency_ms: float
    llm_tokens: int
    weaknesses: list[str]
    persona_at_time: str


@dataclass
class Report:
    id: str
    session_id: str
    created_at: float
    generator: str
    severity: str
    confidence: float
    document: dict[str, Any]
    markdown: str = ""


@dataclass
class WorldObject:
    collection: str
    object_id: str
    owner_id: str | None
    sensitive: bool
    data: dict[str, Any]
    created_at: float
    updated_at: float

    #: Convenience for the LLM prompt: the object as the API would expose it.
    def public_view(self, drop: tuple[str, ...] = ()) -> dict[str, Any]:
        return {k: v for k, v in self.data.items() if k not in drop}


def _loads(raw: str, fallback: Any) -> Any:
    try:
        return json.loads(raw) if raw else fallback
    except (json.JSONDecodeError, TypeError):
        return fallback


class StateStore:
    """Thread-safe SQLite-backed session and fake-world store."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            isolation_level=None,  # autocommit; explicit transactions where needed
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA_SQL)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- session lifecycle ---------------------------------------------------

    @staticmethod
    def make_session_key(source_ip: str, user_agent: str, explicit: str = "") -> str:
        """Derive a stable session identity.

        Attack tooling rarely honours cookies, so sessions are keyed on
        source IP plus User-Agent. Red-team harnesses can pass an explicit key
        to force session separation from a single host.
        """
        if explicit:
            return f"explicit:{explicit}"
        digest = hashlib.sha256(f"{source_ip}|{user_agent}".encode()).hexdigest()[:24]
        return f"derived:{digest}"

    def get_or_create_session(
        self,
        *,
        session_key: str,
        source_ip: str,
        user_agent: str,
        world_persona: str,
        idle_seconds: float,
        ground_truth_persona: str | None = None,
        ground_truth_techniques: list[str] | None = None,
        experiment_tag: str | None = None,
    ) -> tuple[Session, bool]:
        """Return ``(session, created)`` for this key, rotating idle sessions."""
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                """SELECT * FROM sessions
                   WHERE session_key = ? AND closed_at IS NULL
                   ORDER BY last_seen DESC LIMIT 1""",
                (session_key,),
            ).fetchone()

            if row is not None:
                if now - row["last_seen"] > idle_seconds:
                    # Session went quiet long enough to count as finished; close
                    # it so the auto-reporter picks it up and start a new one.
                    self._conn.execute(
                        "UPDATE sessions SET closed_at = ? WHERE id = ?",
                        (row["last_seen"], row["id"]),
                    )
                else:
                    return self._row_to_session(row), False

            session_id = uuid.uuid4().hex
            self._conn.execute(
                """INSERT INTO sessions (
                       id, session_key, source_ip, user_agent, first_seen, last_seen,
                       world_persona, ground_truth_persona, ground_truth_techniques,
                       experiment_tag
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    session_key,
                    source_ip,
                    user_agent,
                    now,
                    now,
                    world_persona,
                    ground_truth_persona,
                    json.dumps(ground_truth_techniques or []),
                    experiment_tag,
                ),
            )
            row = self._conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
            return self._row_to_session(row), True

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
        return self._row_to_session(row) if row else None

    def list_sessions(
        self,
        *,
        limit: int = 100,
        experiment_tag: str | None = None,
        only_closed: bool = False,
    ) -> list[Session]:
        clauses, params = [], []
        if experiment_tag is not None:
            clauses.append("experiment_tag = ?")
            params.append(experiment_tag)
        if only_closed:
            clauses.append("closed_at IS NOT NULL")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM sessions {where} ORDER BY last_seen DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
        return [self._row_to_session(r) for r in rows]

    def touch_session(self, session_id: str, *, ts: float | None = None) -> int:
        """Bump activity counters; returns the new request sequence number."""
        with self._lock:
            self._conn.execute(
                """UPDATE sessions
                   SET last_seen = ?, request_count = request_count + 1
                   WHERE id = ?""",
                (ts or time.time(), session_id),
            )
            row = self._conn.execute(
                "SELECT request_count FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
        return int(row["request_count"]) if row else 0

    def update_persona(
        self,
        session_id: str,
        persona: AttackerPersona,
        confidence: float,
        scores: dict[str, float],
        signals: list[str],
    ) -> None:
        with self._lock:
            self._conn.execute(
                """UPDATE sessions
                   SET persona = ?, persona_confidence = ?, persona_scores = ?,
                       persona_signals = ?
                   WHERE id = ?""",
                (
                    persona.value,
                    round(float(confidence), 4),
                    json.dumps({k: round(v, 4) for k, v in scores.items()}),
                    json.dumps(signals[:40]),
                    session_id,
                ),
            )

    def set_authenticated_user(self, session_id: str, user_id: str | None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET authenticated_user_id = ? WHERE id = ?",
                (user_id, session_id),
            )

    def record_llm_usage(self, session_id: str, *, tokens: int, latency_ms: float) -> None:
        with self._lock:
            self._conn.execute(
                """UPDATE sessions
                   SET llm_calls = llm_calls + 1,
                       llm_tokens = llm_tokens + ?,
                       llm_latency_ms_total = llm_latency_ms_total + ?
                   WHERE id = ?""",
                (int(tokens), float(latency_ms), session_id),
            )

    def record_consistency_violations(self, session_id: str, count: int) -> None:
        if count <= 0:
            return
        with self._lock:
            self._conn.execute(
                """UPDATE sessions
                   SET consistency_violations = consistency_violations + ?
                   WHERE id = ?""",
                (int(count), session_id),
            )

    def close_session(self, session_id: str, *, ts: float | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET closed_at = ? WHERE id = ? AND closed_at IS NULL",
                (ts or time.time(), session_id),
            )

    def find_idle_sessions(self, idle_seconds: float) -> list[Session]:
        cutoff = time.time() - idle_seconds
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM sessions
                   WHERE closed_at IS NULL AND last_seen < ? AND request_count > 0""",
                (cutoff,),
            ).fetchall()
        return [self._row_to_session(r) for r in rows]

    def find_unreported_sessions(self, limit: int = 20) -> list[Session]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM sessions
                   WHERE closed_at IS NOT NULL AND reported_at IS NULL
                     AND request_count > 0
                   ORDER BY closed_at ASC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._row_to_session(r) for r in rows]

    def mark_reported(self, session_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET reported_at = ? WHERE id = ?",
                (time.time(), session_id),
            )

    # -- events --------------------------------------------------------------

    def record_event(
        self,
        *,
        session_id: str,
        seq: int,
        method: str,
        path: str,
        query_string: str,
        headers: dict[str, str],
        body: str,
        status_code: int,
        response: str,
        generator: str,
        latency_ms: float,
        llm_tokens: int,
        weaknesses: list[str],
        persona_at_time: str,
        ts: float | None = None,
        max_body_bytes: int = 8192,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO events (
                       session_id, seq, ts, method, path, query_string, headers, body,
                       status_code, response, generator, latency_ms, llm_tokens,
                       weaknesses, persona_at_time
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    seq,
                    ts or time.time(),
                    method,
                    path,
                    query_string[:2048],
                    json.dumps(headers),
                    body[:max_body_bytes],
                    status_code,
                    response[:max_body_bytes],
                    generator,
                    float(latency_ms),
                    int(llm_tokens),
                    json.dumps(weaknesses),
                    persona_at_time,
                ),
            )
        return int(cur.lastrowid or 0)

    def get_events(self, session_id: str, *, limit: int = 500) -> list[Event]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE session_id = ? ORDER BY seq ASC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        return [
            Event(
                id=r["id"],
                session_id=r["session_id"],
                seq=r["seq"],
                ts=r["ts"],
                method=r["method"],
                path=r["path"],
                query_string=r["query_string"],
                headers=_loads(r["headers"], {}),
                body=r["body"],
                status_code=r["status_code"],
                response=r["response"],
                generator=r["generator"],
                latency_ms=r["latency_ms"],
                llm_tokens=r["llm_tokens"],
                weaknesses=_loads(r["weaknesses"], []),
                persona_at_time=r["persona_at_time"],
            )
            for r in rows
        ]

    def recent_event_timings(self, session_id: str, limit: int = 40) -> list[float]:
        """Timestamps of the most recent requests, oldest first (for the profiler)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts FROM events WHERE session_id = ? ORDER BY seq DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        return [float(r["ts"]) for r in reversed(rows)]

    # -- fake world ----------------------------------------------------------

    def mark_world_seeded(self, session_id: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE sessions SET world_seeded = 1 WHERE id = ?", (session_id,))

    def put_object(
        self,
        session_id: str,
        collection: str,
        object_id: str,
        data: dict[str, Any],
        *,
        owner_id: str | None = None,
        sensitive: bool = False,
    ) -> WorldObject:
        now = time.time()
        with self._lock:
            existing = self._conn.execute(
                """SELECT created_at FROM world_objects
                   WHERE session_id = ? AND collection = ? AND object_id = ?""",
                (session_id, collection, object_id),
            ).fetchone()
            created = float(existing["created_at"]) if existing else now
            self._conn.execute(
                """INSERT INTO world_objects (
                       session_id, collection, object_id, owner_id, sensitive,
                       data, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(session_id, collection, object_id) DO UPDATE SET
                       owner_id = excluded.owner_id,
                       sensitive = excluded.sensitive,
                       data = excluded.data,
                       updated_at = excluded.updated_at""",
                (
                    session_id,
                    collection,
                    object_id,
                    owner_id,
                    1 if sensitive else 0,
                    json.dumps(data),
                    created,
                    now,
                ),
            )
        return WorldObject(
            collection=collection,
            object_id=object_id,
            owner_id=owner_id,
            sensitive=sensitive,
            data=data,
            created_at=created,
            updated_at=now,
        )

    def get_object(self, session_id: str, collection: str, object_id: str) -> WorldObject | None:
        with self._lock:
            row = self._conn.execute(
                """SELECT * FROM world_objects
                   WHERE session_id = ? AND collection = ? AND object_id = ?""",
                (session_id, collection, str(object_id)),
            ).fetchone()
        return self._row_to_object(row) if row else None

    def list_objects(
        self,
        session_id: str,
        collection: str,
        *,
        owner_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[WorldObject]:
        clauses = ["session_id = ?", "collection = ?"]
        params: list[Any] = [session_id, collection]
        if owner_id is not None:
            clauses.append("owner_id = ?")
            params.append(owner_id)
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT * FROM world_objects WHERE {" AND ".join(clauses)}
                    ORDER BY object_id ASC LIMIT ? OFFSET ?""",
                (*params, limit, offset),
            ).fetchall()
        return [self._row_to_object(r) for r in rows]

    def count_objects(self, session_id: str, collection: str) -> int:
        with self._lock:
            row = self._conn.execute(
                """SELECT COUNT(*) AS n FROM world_objects
                   WHERE session_id = ? AND collection = ?""",
                (session_id, collection),
            ).fetchone()
        return int(row["n"]) if row else 0

    def delete_object(self, session_id: str, collection: str, object_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                """DELETE FROM world_objects
                   WHERE session_id = ? AND collection = ? AND object_id = ?""",
                (session_id, collection, str(object_id)),
            )
        return (cur.rowcount or 0) > 0

    def next_counter(self, session_id: str, name: str, *, start: int = 1) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM world_counters WHERE session_id = ? AND name = ?",
                (session_id, name),
            ).fetchone()
            value = (int(row["value"]) + 1) if row else start
            self._conn.execute(
                """INSERT INTO world_counters (session_id, name, value)
                   VALUES (?, ?, ?)
                   ON CONFLICT(session_id, name) DO UPDATE SET value = excluded.value""",
                (session_id, name, value),
            )
        return value

    # -- reports -------------------------------------------------------------

    def save_report(
        self,
        *,
        session_id: str,
        document: dict[str, Any],
        markdown: str,
        generator: str,
        severity: str,
        confidence: float,
    ) -> Report:
        report_id = uuid.uuid4().hex
        now = time.time()
        with self._lock:
            self._conn.execute(
                """INSERT INTO reports (
                       id, session_id, created_at, generator, severity, confidence,
                       document, markdown)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    report_id,
                    session_id,
                    now,
                    generator,
                    severity,
                    float(confidence),
                    json.dumps(document),
                    markdown,
                ),
            )
        return Report(
            id=report_id,
            session_id=session_id,
            created_at=now,
            generator=generator,
            severity=severity,
            confidence=confidence,
            document=document,
            markdown=markdown,
        )

    def list_reports(self, *, limit: int = 50) -> list[Report]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM reports ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_report(r) for r in rows]

    def get_report(self, report_id: str) -> Report | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        return self._row_to_report(row) if row else None

    def get_reports_for_session(self, session_id: str) -> list[Report]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM reports WHERE session_id = ? ORDER BY created_at DESC",
                (session_id,),
            ).fetchall()
        return [self._row_to_report(r) for r in rows]

    # -- maintenance ---------------------------------------------------------

    def purge_older_than(self, retention_days: int) -> int:
        """Enforce the Section 10 retention window."""
        cutoff = time.time() - retention_days * 86400
        with self._lock:
            cur = self._conn.execute("DELETE FROM sessions WHERE last_seen < ?", (cutoff,))
            self._conn.execute(
                "DELETE FROM events WHERE session_id NOT IN (SELECT id FROM sessions)"
            )
            self._conn.execute(
                "DELETE FROM world_objects WHERE session_id NOT IN (SELECT id FROM sessions)"
            )
            self._conn.execute(
                "DELETE FROM reports WHERE session_id NOT IN (SELECT id FROM sessions)"
            )
        return cur.rowcount or 0

    def summary_stats(self) -> dict[str, Any]:
        with self._lock:
            totals = self._conn.execute(
                """SELECT COUNT(*) AS sessions,
                          COALESCE(SUM(request_count), 0) AS requests,
                          COALESCE(SUM(llm_calls), 0) AS llm_calls,
                          COALESCE(SUM(llm_tokens), 0) AS llm_tokens,
                          COALESCE(SUM(consistency_violations), 0) AS violations
                   FROM sessions"""
            ).fetchone()
            personas = self._conn.execute(
                "SELECT persona, COUNT(*) AS n FROM sessions GROUP BY persona"
            ).fetchall()
            active = self._conn.execute(
                "SELECT COUNT(*) AS n FROM sessions WHERE closed_at IS NULL"
            ).fetchone()
            reports = self._conn.execute("SELECT COUNT(*) AS n FROM reports").fetchone()
            latency = self._conn.execute(
                "SELECT COALESCE(AVG(latency_ms), 0) AS avg_ms FROM events"
            ).fetchone()
        return {
            "sessions": int(totals["sessions"]),
            "active_sessions": int(active["n"]),
            "requests": int(totals["requests"]),
            "llm_calls": int(totals["llm_calls"]),
            "llm_tokens": int(totals["llm_tokens"]),
            "consistency_violations": int(totals["violations"]),
            "reports": int(reports["n"]),
            "avg_latency_ms": round(float(latency["avg_ms"]), 2),
            "personas": {r["persona"]: int(r["n"]) for r in personas},
        }

    # -- row mappers ---------------------------------------------------------

    @staticmethod
    def _row_to_session(row: sqlite3.Row) -> Session:
        try:
            persona = AttackerPersona(row["persona"])
        except ValueError:
            persona = AttackerPersona.UNKNOWN
        return Session(
            id=row["id"],
            session_key=row["session_key"],
            source_ip=row["source_ip"],
            user_agent=row["user_agent"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            request_count=row["request_count"],
            persona=persona,
            persona_confidence=row["persona_confidence"],
            persona_scores=_loads(row["persona_scores"], {}),
            persona_signals=_loads(row["persona_signals"], []),
            world_persona=row["world_persona"],
            world_seeded=bool(row["world_seeded"]),
            authenticated_user_id=row["authenticated_user_id"],
            closed_at=row["closed_at"],
            reported_at=row["reported_at"],
            llm_calls=row["llm_calls"],
            llm_tokens=row["llm_tokens"],
            llm_latency_ms_total=row["llm_latency_ms_total"],
            consistency_violations=row["consistency_violations"],
            ground_truth_persona=row["ground_truth_persona"],
            ground_truth_techniques=_loads(row["ground_truth_techniques"], []),
            experiment_tag=row["experiment_tag"],
        )

    @staticmethod
    def _row_to_object(row: sqlite3.Row) -> WorldObject:
        return WorldObject(
            collection=row["collection"],
            object_id=row["object_id"],
            owner_id=row["owner_id"],
            sensitive=bool(row["sensitive"]),
            data=_loads(row["data"], {}),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _row_to_report(row: sqlite3.Row) -> Report:
        return Report(
            id=row["id"],
            session_id=row["session_id"],
            created_at=row["created_at"],
            generator=row["generator"],
            severity=row["severity"],
            confidence=row["confidence"],
            document=_loads(row["document"], {}),
            markdown=row["markdown"],
        )


_store_singleton: StateStore | None = None
_singleton_lock = threading.Lock()


def get_store(db_path: Path | str | None = None) -> StateStore:
    """Process-wide store singleton."""
    global _store_singleton
    with _singleton_lock:
        if _store_singleton is None:
            if db_path is None:
                from aegistrap.config import get_settings

                db_path = get_settings().db_path
            _store_singleton = StateStore(db_path)
            log.info("state store ready at %s", _store_singleton.db_path)
        return _store_singleton


def reset_store() -> None:
    """Test hook: drop the singleton (does not delete the file)."""
    global _store_singleton
    with _singleton_lock:
        if _store_singleton is not None:
            _store_singleton.close()
        _store_singleton = None
