"""
ONYX CTI - IOC -> graph projection.

The architecture keeps relationships in Neo4j (with MongoDB as the degraded-mode fallback).
`plan_ioc_graph` turns an IOC event (the dict published on the `onyx:events:iocs` stream) into
a list of idempotent graph operations; `sync_ioc` executes them through a Neo4j service and
never raises, so a graph outage cannot block ingestion (4-level degradation).

Pure Python: the planning step has no dependency and is unit tested.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Protocol

log = logging.getLogger("onyx.graph_sync")

_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_NAME = re.compile(r"^[\w .:/@+\-]{2,120}$")


class _GraphService(Protocol):
    def upsert_entity(self, label: str, entity_id: str, props: dict | None = None): ...
    def link(self, src_label: str, src_id: str, rel: str, dst_label: str, dst_id: str, props: dict | None = None): ...


def _clean_name(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    v = v.strip()
    return v if _NAME.match(v) else None


def plan_ioc_graph(event: dict[str, Any]) -> list[tuple]:
    """Return ("entity", label, id, props) and ("link", src_label, src_id, rel, dst_label, dst_id) ops."""
    value = event.get("value")
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        return []
    value = value.strip()
    ops: list[tuple] = [(
        "entity", "Indicator", value,
        {"type": str(event.get("type", ""))[:32], "source": str(event.get("source", ""))[:64]},
    )]
    malware = _clean_name(event.get("malware"))
    if malware:
        ops.append(("entity", "Malware", malware.lower(), {"name": malware}))
        ops.append(("link", "Indicator", value, "INDICATES", "Malware", malware.lower()))
    for key in ("actor", "threat_actor"):
        actor = _clean_name(event.get(key))
        if actor:
            ops.append(("entity", "Actor", actor.lower(), {"name": actor}))
            ops.append(("link", "Indicator", value, "ATTRIBUTED_TO", "Actor", actor.lower()))
            if malware:
                ops.append(("link", "Actor", actor.lower(), "USES", "Malware", malware.lower()))
            break
    for tid in event.get("mitre_techniques") or []:
        if isinstance(tid, str) and _TECHNIQUE.match(tid):
            ops.append(("entity", "Technique", tid, {"id": tid}))
            ops.append(("link", "Indicator", value, "RELATED_TO", "Technique", tid))
    return ops


def sync_ioc(service: _GraphService, event: dict[str, Any]) -> int:
    """Apply the plan. Returns the number of operations applied; swallows backend errors."""
    applied = 0
    try:
        for op in plan_ioc_graph(event):
            if op[0] == "entity":
                service.upsert_entity(op[1], op[2], op[3])
            else:
                service.link(op[1], op[2], op[3], op[4], op[5])
            applied += 1
    except Exception as exc:  # graph is an enrichment layer, not a gate
        log.warning("graph sync skipped: %s", exc)
    return applied
