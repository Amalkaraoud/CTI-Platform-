"""Tests for the behavioral convergence engine (pure Python, no web stack needed)."""
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "behavioral_convergence",
    Path(__file__).resolve().parents[1] / "onyx_api/services/behavioral_convergence.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["behavioral_convergence"] = mod
spec.loader.exec_module(mod)


def test_jaccard_basics():
    assert mod.jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert mod.jaccard({"a"}, {"b"}) == 0.0
    assert mod.jaccard(set(), {"a"}) == 0.0
    assert mod.jaccard({"a", "b"}, {"b", "c"}) == 1 / 3


def test_threshold_flag():
    e = mod.BehavioralConvergenceEngine()
    same = e.compare("X", ["T1", "T2", "T3"], "Y", ["T1", "T2", "T3"])
    assert same.convergent and same.jaccard_score == 1.0
    apart = e.compare("X", ["T1"], "Y", ["T2"])
    assert not apart.convergent


def test_find_peers_excludes_self_and_is_sorted():
    e = mod.BehavioralConvergenceEngine()
    peers = e.find_peers("APT29", sorted(mod._ACTOR_TTP_DB["APT29"]), min_jaccard=0.0)
    assert all(p.actor_b != "APT29" for p in peers)
    scores = [p.jaccard_score for p in peers]
    assert scores == sorted(scores, reverse=True)
