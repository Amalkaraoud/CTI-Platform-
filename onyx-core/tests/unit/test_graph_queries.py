"""Cypher builders: whitelisting and parameterisation. Query text only; no Neo4j server is contacted."""
import importlib.util
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("gq", Path(__file__).resolve().parents[2] / "onyx_core/graph_queries.py")
gq = importlib.util.module_from_spec(spec); sys.modules["gq"] = gq; spec.loader.exec_module(gq)


def test_upsert_uses_parameters_only():
    q = gq.upsert_relationship("Actor", "USES", "Malware")
    assert "$src" in q and "$dst" in q and "MERGE (a)-[r:USES]->(b)" in q


@pytest.mark.parametrize("bad", ["Actor) DETACH DELETE n //", "actor", "", "Actor {id: 1}"])
def test_labels_are_whitelisted(bad):
    with pytest.raises(ValueError):
        gq.upsert_entity(bad)
    with pytest.raises(ValueError):
        gq.upsert_relationship("Actor", "USES]->(x) DELETE x //", "Malware")


@pytest.mark.parametrize("d", [0, 7, -1])
def test_depth_is_bounded(d):
    with pytest.raises(ValueError):
        gq.attack_chain(d)


def test_attack_chain_is_parameterised():
    q = gq.attack_chain(3)
    assert "[*1..3]" in q and "$value" in q and "LIMIT 200" in q
