"""Pure query helpers over the armed IOC list, shared by the GraphQL schema (and testable alone)."""
from __future__ import annotations

from typing import Any, Iterable

MAX_LIMIT = 1000


def filter_iocs(iocs: Iterable[dict[str, Any]], *, ioc_type: str | None = None, severity: str | None = None,
                source: str | None = None, text: str | None = None, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), MAX_LIMIT))
    offset = max(0, int(offset))
    t = text.lower() if text else None
    out = []
    for i in iocs:
        if ioc_type and i.get("type") != ioc_type:
            continue
        if severity and i.get("severity") != severity:
            continue
        if source and i.get("source") != source:
            continue
        if t and t not in str(i.get("value", "")).lower():
            continue
        out.append(i)
    return out[offset:offset + limit]


def stats(iocs: Iterable[dict[str, Any]]) -> dict[str, Any]:
    by: dict[str, dict[str, int]] = {"type": {}, "severity": {}, "source": {}}
    total = 0
    for i in iocs:
        total += 1
        for k, d in (("type", "unknown"), ("severity", "medium"), ("source", "unknown")):
            v = i.get(k, d)
            by[k][v] = by[k].get(v, 0) + 1
    return {"total": total, "by_type": by["type"], "by_severity": by["severity"], "by_source": by["source"]}
