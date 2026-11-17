"""IOC -> graph projection plan (pure) and failure isolation of sync_ioc."""
import importlib.util
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2] / "onyx_core"
spec = importlib.util.spec_from_file_location("gs", root / "graph_sync.py")
gs = importlib.util.module_from_spec(spec); sys.modules["gs"] = gs; spec.loader.exec_module(gs)


class Fake:
    def __init__(self, fail=False):
        self.entities, self.links, self.fail = [], [], fail

    def upsert_entity(self, label, eid, props=None):
        if self.fail:
            raise RuntimeError("neo4j down")
        self.entities.append((label, eid))

    def link(self, sl, sid, rel, dl, did, props=None):
        self.links.append((sl, sid, rel, dl, did))


EVENT = {"type": "ipv4", "value": "203.0.113.7", "malware": "Emotet", "actor": "TA542",
         "mitre_techniques": ["T1071", "bogus", "T1059.001"]}


def test_plan_builds_entities_and_links():
    ops = gs.plan_ioc_graph(EVENT)
    kinds = {(o[1], o[2]) for o in ops if o[0] == "entity"}
    assert ("Indicator", "203.0.113.7") in kinds and ("Malware", "emotet") in kinds and ("Actor", "ta542") in kinds
    assert ("Technique", "T1071") in kinds and ("Technique", "T1059.001") in kinds
    assert not any(o[2] == "bogus" for o in ops if o[0] == "entity")
    assert any(o[0] == "link" and o[3] == "USES" for o in ops)


def test_invalid_events_produce_nothing():
    assert gs.plan_ioc_graph({}) == []
    assert gs.plan_ioc_graph({"value": "x" * 5000}) == []
    assert gs.plan_ioc_graph({"value": "  "}) == []


def test_hostile_names_are_dropped():
    ops = gs.plan_ioc_graph({"value": "a.example", "malware": "x'}) DETACH DELETE n //"})
    assert [o for o in ops if o[0] == "entity"] == [("entity", "Indicator", "a.example", {"type": "", "source": ""})]


def test_sync_applies_and_swallows_errors():
    f = Fake()
    assert gs.sync_ioc(f, EVENT) > 0 and f.links
    assert gs.sync_ioc(Fake(fail=True), EVENT) == 0
