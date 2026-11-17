"""
ONYX CTI - GraphQL schema (Strawberry).

The architecture and the report name GraphQL (Strawberry) as the dashboard query interface; the
dependency was declared but no schema existed. This module provides one over the data the REST layer
already serves (armed OSINT indicators) and the three scoring engines.

Mounted by main.py at /graphql behind the same JWT dependency as the REST API. Queries only; no
mutations and no subscriptions (real-time events stay on the WebSocket hub). Depth is limited.
Runtime verification of this module requires strawberry-graphql, which was not installable in the
environment where it was written: the query logic it delegates to is tested (test_ioc_queries.py),
the schema wiring itself has not been executed.
"""
from __future__ import annotations

from typing import Optional

import strawberry
from strawberry.fastapi import GraphQLRouter
from strawberry.scalars import JSON
from strawberry.types import Info

from onyx_api.services import ioc_queries
from onyx_api.services.analysis import ValidationError, assess as _assess


@strawberry.type
class IoC:
    value: str
    type: str
    severity: Optional[str]
    source: Optional[str]
    confidence: Optional[float]


@strawberry.type
class IoCStats:
    total: int
    by_type: JSON
    by_severity: JSON
    by_source: JSON


def _armed(info: Info) -> list[dict]:
    return getattr(info.context["request"].app.state, "armed_iocs", []) or []


def _to_ioc(d: dict) -> IoC:
    c = d.get("confidence")
    return IoC(value=str(d.get("value", "")), type=str(d.get("type", "unknown")), severity=d.get("severity"),
               source=d.get("source"), confidence=float(c) if isinstance(c, (int, float)) else None)


@strawberry.type
class Query:
    @strawberry.field(description="Armed OSINT indicators, filterable and paginated (limit capped at 1000).")
    def iocs(self, info: Info, type: Optional[str] = None, severity: Optional[str] = None,
             source: Optional[str] = None, text: Optional[str] = None, limit: int = 100, offset: int = 0) -> list[IoC]:
        rows = ioc_queries.filter_iocs(_armed(info), ioc_type=type, severity=severity, source=source,
                                       text=text, limit=limit, offset=offset)
        return [_to_ioc(r) for r in rows]

    @strawberry.field(description="Counts by type, severity and source.")
    def ioc_stats(self, info: Info) -> IoCStats:
        s = ioc_queries.stats(_armed(info))
        return IoCStats(total=s["total"], by_type=s["by_type"], by_severity=s["by_severity"], by_source=s["by_source"])

    @strawberry.field(description="Freshness and composite confidence of one indicator profile, decomposed.")
    def assess(self, params: JSON) -> JSON:
        try:
            return _assess(dict(params))
        except ValidationError as e:
            raise ValueError(str(e))


def _extensions():
    try:
        from strawberry.extensions import QueryDepthLimiter
        return [QueryDepthLimiter(max_depth=6)]
    except Exception:  # noqa: BLE001 - older strawberry: run without the limiter
        return []


schema = strawberry.Schema(query=Query, extensions=_extensions())
graphql_router = GraphQLRouter(schema, graphql_ide=None)   # IDE disabled: it would load third-party scripts
