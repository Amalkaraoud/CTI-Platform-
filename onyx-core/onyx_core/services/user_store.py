"""
ONYX CTI - PostgreSQL store for users, RBAC roles and the audit trail.

The report (section 6) places accounts, roles and audit logs in PostgreSQL. This module owns that
schema. SQL is written to run unchanged on PostgreSQL (psycopg2, paramstyle "%s") and on SQLite
(paramstyle "?"), which is how it is tested without a database server. All values are bound as
parameters; no SQL is built from user input.

Design choices:
  * Bootstrap accounts (environment driven, see onyx_core.services.accounts) are inserted only
    when absent, so a password changed in the database is never overwritten at restart.
  * The API keeps an in-process cache of users (`_DEFAULT_USERS`); `load_users` refreshes it from
    the database, which is the source of truth when POSTGRES_URL is configured.
  * Audit writes never raise: auditing must not break the request path.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS onyx_users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS onyx_audit_log (
        id TEXT PRIMARY KEY,
        ts TEXT NOT NULL,
        action TEXT NOT NULL,
        outcome TEXT NOT NULL,
        actor TEXT NOT NULL,
        resource TEXT,
        client_ip TEXT,
        details TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_onyx_audit_ts ON onyx_audit_log (ts)",
    "CREATE INDEX IF NOT EXISTS idx_onyx_audit_actor ON onyx_audit_log (actor)",
)

_ROLES = {"admin", "analyst", "viewer", "api_key"}


class UserStore:
    def __init__(self, connect: Callable[[], Any], paramstyle: str = "%s") -> None:
        if paramstyle not in ("%s", "?"):
            raise ValueError("paramstyle must be '%s' or '?'")
        self._connect = connect
        self._p = paramstyle

    def _q(self, sql: str) -> str:
        return sql.replace("{}", self._p)

    def _exec(self, sql: str, params: tuple = (), fetch: bool = False):
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(self._q(sql), params)
            rows = cur.fetchall() if fetch else None
            conn.commit()
            return rows
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ---- schema --------------------------------------------------------
    def init_schema(self) -> None:
        for stmt in _SCHEMA:
            self._exec(stmt)

    # ---- users ---------------------------------------------------------
    def ensure_user(self, *, user_id: str, username: str, password_hash: str, role: str,
                    email: str | None = None) -> bool:
        """Insert the account if it does not exist. Returns True when a row was created."""
        if role not in _ROLES:
            raise ValueError(f"unknown role: {role}")
        if self.get_user(username):
            return False
        self._exec(
            "INSERT INTO onyx_users (id, username, email, password_hash, role, is_active, created_at) "
            "VALUES ({}, {}, {}, {}, {}, 1, {}) ON CONFLICT (username) DO NOTHING",
            (user_id, username, email, password_hash, role, datetime.now(timezone.utc).isoformat()),
        )
        return True

    def _row(self, r) -> dict[str, Any]:
        return {"id": r[0], "username": r[1], "email": r[2], "password_hash": r[3],
                "role": r[4], "is_active": bool(r[5]), "created_at": r[6]}

    _COLS = "id, username, email, password_hash, role, is_active, created_at"

    def get_user(self, username: str) -> dict[str, Any] | None:
        rows = self._exec(f"SELECT {self._COLS} FROM onyx_users WHERE username = {{}}", (username,), fetch=True)
        return self._row(rows[0]) if rows else None

    def list_users(self) -> list[dict[str, Any]]:
        rows = self._exec(f"SELECT {self._COLS} FROM onyx_users ORDER BY username", fetch=True)
        return [self._row(r) for r in rows]

    def set_password_hash(self, username: str, password_hash: str) -> None:
        self._exec("UPDATE onyx_users SET password_hash = {} WHERE username = {}", (password_hash, username))

    def set_active(self, username: str, active: bool) -> None:
        self._exec("UPDATE onyx_users SET is_active = {} WHERE username = {}", (1 if active else 0, username))

    # ---- audit ---------------------------------------------------------
    def record_audit(self, event: dict[str, Any]) -> None:
        self._exec(
            "INSERT INTO onyx_audit_log (id, ts, action, outcome, actor, resource, client_ip, details) "
            "VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
            (str(uuid.uuid4()), event.get("ts") or datetime.now(timezone.utc).isoformat(),
             str(event.get("action", ""))[:128], str(event.get("outcome", ""))[:32],
             str(event.get("actor", "anonymous"))[:128], event.get("resource"), event.get("client_ip"),
             json.dumps(event.get("details") or {}, ensure_ascii=False)),
        )

    def recent_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        rows = self._exec(
            "SELECT ts, action, outcome, actor, resource, client_ip, details FROM onyx_audit_log "
            "ORDER BY ts DESC LIMIT {}", (limit,), fetch=True)
        return [{"ts": r[0], "action": r[1], "outcome": r[2], "actor": r[3], "resource": r[4],
                 "client_ip": r[5], "details": json.loads(r[6] or "{}")} for r in rows]


class AuditDatabaseHandler(logging.Handler):
    """Logging handler for the 'onyx.audit' logger: persists each JSON audit line, never raises."""

    def __init__(self, store: UserStore) -> None:
        super().__init__(level=logging.INFO)
        self._store = store

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._store.record_audit(json.loads(record.getMessage()))
        except Exception:                   # noqa: BLE001
            pass


def postgres_store(url: str) -> UserStore:
    """Build a store from a postgresql:// URL (psycopg2 is imported lazily)."""
    import psycopg2  # noqa: PLC0415

    return UserStore(lambda: psycopg2.connect(url, connect_timeout=5), "%s")


def sync_bootstrap_users(store: UserStore, bootstrap: dict[str, dict]) -> dict[str, dict]:
    """Create missing bootstrap accounts, then return every database user keyed by username."""
    store.init_schema()
    for name, u in bootstrap.items():
        role = getattr(u["role"], "value", u["role"])
        store.ensure_user(user_id=u["id"], username=name, password_hash=u["password_hash"],
                          role=role, email=u.get("email"))
    return {u["username"]: u for u in store.list_users()}
