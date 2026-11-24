"""Persistence behind a small interface (SQLite today; DynamoDB could implement
the same ``Store`` protocol later).

The audit log is append-only and hash-chained: each entry stores the SHA-256
of (prev_hash + canonical JSON of the entry), so tampering is detectable with
``verify_audit_chain()``.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

from .masking import mask_obj, mask_text
from .models import Action, AuditEntry, Incident, iso

GENESIS = "0" * 64
BUSY_TIMEOUT_S = 10.0  # another process (a second server on the same var dir) may hold the write lock briefly


class Store(Protocol):  # pragma: no cover - interface only
    def upsert_incident(self, inc: Incident) -> bool: ...
    def get_incident(self, incident_id: str) -> Incident | None: ...
    def list_incidents(self) -> list[Incident]: ...
    def set_incident_status(self, incident_id: str, status: str) -> None: ...
    def add_action(self, action: Action) -> Action: ...
    def update_action(self, action: Action) -> None: ...
    def get_action(self, action_id: str) -> Action | None: ...
    def list_actions(self, incident_id: str | None = None) -> list[Action]: ...
    def append_audit(self, actor: str, action: str, incident_id: str, details: dict[str, Any]) -> AuditEntry: ...
    def list_audit(self, limit: int = 200) -> list[AuditEntry]: ...
    def verify_audit_chain(self) -> bool: ...
    def cache_get(self, key: str) -> Any | None: ...
    def cache_set(self, key: str, value: Any, ttl_s: int) -> None: ...


class SQLiteStore:
    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        # isolation_level=None: transactions are explicit (``_write``), so read-then-insert steps such as
        # the audit hash chain and action numbering are atomic across processes, not only threads.
        self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=BUSY_TIMEOUT_S, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute(f"PRAGMA busy_timeout={int(BUSY_TIMEOUT_S * 1000)}")
            self._enable_wal()
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, body TEXT NOT NULL, updated_at TEXT);
                CREATE TABLE IF NOT EXISTS actions (id TEXT PRIMARY KEY, incident_id TEXT, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT,
                    incident_id TEXT, details TEXT, prev_hash TEXT, hash TEXT);
                CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT, expires REAL);
                """
            )

    def _enable_wal(self) -> None:
        """Switch to WAL. SQLite reports the switch as busy without calling the busy handler while another
        process is creating the same file, so retry for up to the busy timeout."""
        deadline = time.monotonic() + BUSY_TIMEOUT_S
        while True:
            try:
                self._db.execute("PRAGMA journal_mode=WAL")
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) or time.monotonic() > deadline:
                    raise
                time.sleep(0.05)

    @contextmanager
    def _write(self):
        """One write transaction, holding the SQLite write lock from the first read (BEGIN IMMEDIATE)."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

    # ---------------------------------------------------------------- incidents
    def upsert_incident(self, inc: Incident) -> bool:
        """Insert or update ``inc``; True when it was new (atomic, so only one writer ever sees it as new)."""
        with self._write():
            existing = self.get_incident(inc.id)
            # never downgrade a status a human moved forward (mitigated/resolved)
            if existing and existing.status in {"mitigated", "resolved"} and inc.status == "open":
                inc.status = existing.status
            self._db.execute(
                "INSERT INTO incidents(id, body, updated_at) VALUES(?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET body=excluded.body, updated_at=excluded.updated_at",
                (inc.id, json.dumps(inc.to_dict()), inc.updated_at),
            )
        return existing is None

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            row = self._db.execute("SELECT body FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return Incident.from_dict(json.loads(row["body"])) if row else None

    def list_incidents(self) -> list[Incident]:
        with self._lock:
            rows = self._db.execute("SELECT body FROM incidents ORDER BY id").fetchall()
        return [Incident.from_dict(json.loads(r["body"])) for r in rows]

    def set_incident_status(self, incident_id: str, status: str) -> None:
        with self._write():
            inc = self.get_incident(incident_id)
            if not inc:
                return
            inc.status = status
            inc.updated_at = iso()
            self._db.execute(
                "UPDATE incidents SET body=?, updated_at=? WHERE id=?",
                (json.dumps(inc.to_dict()), inc.updated_at, incident_id),
            )

    def clear_incidents(self) -> None:
        with self._write():
            self._db.execute("DELETE FROM incidents")

    # ------------------------------------------------------------------ actions
    def next_action_id(self) -> str:
        with self._lock:
            n = self._db.execute("SELECT COUNT(*) AS n FROM actions").fetchone()["n"]
        return f"ACT-{n + 1:04d}"

    def add_action(self, action: Action) -> Action:
        with self._write():
            if not action.id:
                action.id = self.next_action_id()
            if not action.created_at:
                action.created_at = iso()
            self._db.execute(
                "INSERT INTO actions(id, incident_id, body) VALUES(?,?,?)",
                (action.id, action.incident_id, json.dumps(action.to_dict())),
            )
        return action

    def update_action(self, action: Action) -> None:
        with self._write():
            self._db.execute("UPDATE actions SET body=? WHERE id=?", (json.dumps(action.to_dict()), action.id))

    def get_action(self, action_id: str) -> Action | None:
        with self._lock:
            row = self._db.execute("SELECT body FROM actions WHERE id=?", (action_id,)).fetchone()
        return Action(**json.loads(row["body"])) if row else None

    def list_actions(self, incident_id: str | None = None) -> list[Action]:
        with self._lock:
            if incident_id:
                rows = self._db.execute("SELECT body FROM actions WHERE incident_id=? ORDER BY id", (incident_id,)).fetchall()
            else:
                rows = self._db.execute("SELECT body FROM actions ORDER BY id").fetchall()
        return [Action(**json.loads(r["body"])) for r in rows]

    # -------------------------------------------------------------------- audit
    @staticmethod
    def _entry_hash(prev_hash: str, ts: str, actor: str, action: str, incident_id: str, details: dict) -> str:
        canon = json.dumps(
            {"prev": prev_hash, "ts": ts, "actor": actor, "action": action, "incident_id": incident_id, "details": details},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canon.encode()).hexdigest()

    def append_audit(self, actor: str, action: str, incident_id: str, details: dict[str, Any]) -> AuditEntry:
        details = mask_obj(details)  # never persist raw secrets in the audit log
        actor = mask_text(str(actor or ""))[:128]  # the actor is user-supplied (approver names) too
        with self._write():  # read the chain head and append under one write lock, or two writers fork the chain
            row = self._db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            ts = iso()
            h = self._entry_hash(prev, ts, actor, action, incident_id, details)
            cur = self._db.execute(
                "INSERT INTO audit(ts, actor, action, incident_id, details, prev_hash, hash) VALUES(?,?,?,?,?,?,?)",
                (ts, actor, action, incident_id, json.dumps(details, sort_keys=True), prev, h),
            )
        return AuditEntry(cur.lastrowid, ts, actor, action, incident_id, details, prev, h)

    def list_audit(self, limit: int = 200) -> list[AuditEntry]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        return [
            AuditEntry(r["seq"], r["ts"], r["actor"], r["action"], r["incident_id"], json.loads(r["details"]), r["prev_hash"], r["hash"])
            for r in rows
        ]

    def verify_audit_chain(self) -> bool:
        with self._lock:
            rows = self._db.execute("SELECT * FROM audit ORDER BY seq").fetchall()
        prev = GENESIS
        for r in rows:
            if r["prev_hash"] != prev:
                return False
            if self._entry_hash(prev, r["ts"], r["actor"], r["action"], r["incident_id"], json.loads(r["details"])) != r["hash"]:
                return False
            prev = r["hash"]
        return True

    # -------------------------------------------------------------------- cache
    def cache_get(self, key: str) -> Any | None:
        with self._lock:
            row = self._db.execute("SELECT v, expires FROM cache WHERE k=?", (key,)).fetchone()
        if not row or row["expires"] < time.time():
            return None
        return json.loads(row["v"])

    def cache_set(self, key: str, value: Any, ttl_s: int) -> None:
        with self._write():
            self._db.execute(
                "INSERT INTO cache(k, v, expires) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, expires=excluded.expires",
                (key, json.dumps(value, default=str), time.time() + ttl_s),
            )
