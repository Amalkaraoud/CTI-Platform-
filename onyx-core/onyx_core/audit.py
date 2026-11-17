"""
ONYX CTI - structured audit trail (standard library only).

One JSON object per line, written through the 'onyx.audit' logger and, when ONYX_AUDIT_LOG is set,
appended to that file. Covers the "journalisation des acces et des actions" requirement: who did
what, on which resource, with which outcome, from which address. Secrets are never logged: any
field whose name looks like a credential is replaced by a marker.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any

_log = logging.getLogger("onyx.audit")
_lock = threading.Lock()
_SENSITIVE = ("password", "secret", "token", "authorization", "api_key", "apikey", "cookie")


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[redacted]" if any(s in str(k).lower() for s in _SENSITIVE) else _scrub(v))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(v) for v in value]
    return value


def build_event(action: str, outcome: str, *, actor: str | None = None, resource: str | None = None,
                client_ip: str | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "outcome": outcome,                 # success | failure | denied | throttled
        "actor": actor or "anonymous",
        "resource": resource,
        "client_ip": client_ip,
        "details": _scrub(details or {}),
    }


def audit(action: str, outcome: str, **kw: Any) -> dict[str, Any]:
    """Emit one audit event; never raises (auditing must not break the request path)."""
    event = build_event(action, outcome, **kw)
    line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    try:
        _log.info(line)
        path = os.getenv("ONYX_AUDIT_LOG", "")
        if path:
            with _lock, open(path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception:                       # noqa: BLE001
        pass
    return event
