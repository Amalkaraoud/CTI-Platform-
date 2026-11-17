"""
ONYX CTI - Cypher builders for the threat graph (standard library only).

Labels and relationship types cannot be passed as Cypher parameters, so they are checked against a
fixed whitelist here; every value goes through parameters, never string formatting. This keeps the
Neo4j service injection-safe and lets the query text be unit-tested without a Neo4j server.

Model: (:Actor)-[:USES]->(:Malware|:Tool), (:Actor)-[:ATTRIBUTED_TO|:TARGETS|...], (:Campaign)..,
(:Indicator)-[:INDICATES]->(:Malware|:Actor|:Campaign), (:Malware)-[:COMMUNICATES_WITH]->(:Infrastructure).
"""
from __future__ import annotations

LABELS = frozenset({"Actor", "Malware", "Tool", "Campaign", "Indicator", "Infrastructure", "Technique", "Vulnerability"})
RELATIONS = frozenset({"USES", "ATTRIBUTED_TO", "TARGETS", "INDICATES", "COMMUNICATES_WITH", "EXPLOITS", "PART_OF", "RELATED_TO"})
MAX_DEPTH = 6


def _label(x: str) -> str:
    if x not in LABELS:
        raise ValueError(f"label not allowed: {x!r}")
    return x


def _rel(x: str) -> str:
    if x not in RELATIONS:
        raise ValueError(f"relationship not allowed: {x!r}")
    return x


def upsert_entity(label: str) -> str:
    """MERGE on the stable id; properties are replaced from $props. Params: id, props."""
    return f"MERGE (n:{_label(label)} {{id: $id}}) SET n += $props RETURN n.id AS id"


def upsert_relationship(src_label: str, rel: str, dst_label: str) -> str:
    """Idempotent edge. Params: src, dst (ids), props."""
    return (f"MERGE (a:{_label(src_label)} {{id: $src}}) MERGE (b:{_label(dst_label)} {{id: $dst}}) "
            f"MERGE (a)-[r:{_rel(rel)}]->(b) SET r += $props RETURN type(r) AS rel")


def attack_chain(depth: int = 4) -> str:
    """Reconstruct the chain around an indicator value, up to `depth` hops, undirected.
    Param: value. Returns the paths with node labels and ids."""
    d = int(depth)
    if not 1 <= d <= MAX_DEPTH:
        raise ValueError(f"depth must be between 1 and {MAX_DEPTH}")
    return (f"MATCH p = (i:Indicator {{value: $value}})-[*1..{d}]-(x) "
            "RETURN [n IN nodes(p) | {labels: labels(n), id: n.id, name: n.name}] AS nodes, "
            "[r IN relationships(p) | type(r)] AS rels LIMIT 200")


def neighbors() -> str:
    return "MATCH (n {id: $id})-[r]-(m) RETURN labels(m) AS labels, m.id AS id, m.name AS name, type(r) AS rel LIMIT $limit"
