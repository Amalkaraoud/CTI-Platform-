"""User/RBAC/audit store, exercised on SQLite (same SQL as PostgreSQL apart from the paramstyle)."""
import importlib.util
import logging
import sqlite3
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "us", Path(__file__).resolve().parents[2] / "onyx_core/services/user_store.py")
us = importlib.util.module_from_spec(spec); sys.modules["us"] = us; spec.loader.exec_module(us)


@pytest.fixture()
def store(tmp_path):
    db = str(tmp_path / "t.db")
    s = us.UserStore(lambda: sqlite3.connect(db), "?")
    s.init_schema()
    return s


def test_bootstrap_inserts_once_and_never_overwrites(store):
    boot = {"admin": {"id": "u1", "password_hash": "h1", "role": "admin", "email": "a@x"}}
    assert us.sync_bootstrap_users(store, boot)["admin"]["password_hash"] == "h1"
    store.set_password_hash("admin", "changed")
    assert us.sync_bootstrap_users(store, boot)["admin"]["password_hash"] == "changed"


def test_unknown_role_rejected_and_injection_is_inert(store):
    with pytest.raises(ValueError):
        store.ensure_user(user_id="x", username="u", password_hash="h", role="root")
    assert store.get_user("x' OR '1'='1") is None


def test_deactivate(store):
    store.ensure_user(user_id="2", username="bob", password_hash="h", role="viewer")
    store.set_active("bob", False)
    assert store.get_user("bob")["is_active"] is False


def test_audit_roundtrip_and_handler_never_raises(store):
    store.record_audit({"action": "auth.login", "outcome": "failure", "actor": "eve", "details": {"n": 1}})
    assert store.recent_audit(5)[0]["actor"] == "eve"
    h = us.AuditDatabaseHandler(store)
    lg = logging.getLogger("t.audit"); lg.addHandler(h); lg.setLevel(logging.INFO)
    lg.info('{"action":"x.y","outcome":"success","actor":"amy"}')
    lg.info("not json")                     # must not raise
    assert {e["actor"] for e in store.recent_audit(10)} >= {"amy", "eve"}
