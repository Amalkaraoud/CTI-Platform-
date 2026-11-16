"""Tests for the engine analysis facade (pure Python)."""
import importlib.util
import sys
from pathlib import Path

import pytest

_p = Path(__file__).resolve().parents[1] / "onyx_api" / "services" / "analysis.py"
_s = importlib.util.spec_from_file_location("analysis", _p)
A = importlib.util.module_from_spec(_s)
sys.modules["analysis"] = A
_s.loader.exec_module(A)


def test_assess_matches_engine_and_contributions_add_up():
    r = A.assess({"ioc_type": "ipv4", "host_type": "tor_exit", "hours_since_seen": 48, "source": "circl_misp"})
    assert r["decay"] == pytest.approx(0.5, abs=1e-4)
    total = sum(c["contribution"] for c in r["components"]) * r["contestation_penalty"]
    assert total == pytest.approx(r["composite"], abs=1e-3)
    assert r["analyst_component_derived"] is True


def test_contested_applies_penalty():
    base = A.assess({"ioc_type": "url", "source": "cisa_advisory", "hours_since_seen": 1})
    cont = A.assess({"ioc_type": "url", "source": "cisa_advisory", "hours_since_seen": 1,
                     "contested": True, "contestation_certainty": 0.0})
    assert cont["composite"] == pytest.approx(base["composite"] * 0.65, abs=1e-3)


def test_analyst_override_replaces_derived_component():
    r = A.assess({"ioc_type": "url", "source": "unknown", "analyst_override_score": 100})
    assert r["analyst_component_derived"] is False
    assert [c for c in r["components"] if c["name"] == "analyst"][0]["value"] == 1.0


def test_more_corroboration_raises_confidence():
    one = A.assess({"ioc_type": "ipv4", "source": "otx_alienvault", "corroboration_count": 1})["composite"]
    five = A.assess({"ioc_type": "ipv4", "source": "otx_alienvault", "corroboration_count": 5})["composite"]
    assert five > one


def test_curve_is_monotonic_and_reports_half_life():
    c = A.curve({"ioc_type": "ipv4", "host_type": "cloud_legitimate", "end_hours": 48, "points": 49})
    vals = [p["decay"] for p in c["points"]]
    assert vals == sorted(vals, reverse=True)
    assert c["first_hour_at_or_below_half"] == 6.0      # 6 h half-life for cloud hosts


@pytest.mark.parametrize("bad", [
    {"ioc_type": "pigeon"}, {"ioc_type": "ipv4", "hours_since_seen": -1}, {"ioc_type": "ipv4", "hours_since_seen": "x"},
    {"ioc_type": "ipv4", "hours_since_seen": float("nan")}, {"ioc_type": "ipv4", "host_type": "nope"},
    {"ioc_type": "ipv4", "weights": {"source": 1, "corroboration": 1, "freshness": 0, "context": 0, "analyst": 0}},
    {"ioc_type": "ipv4", "corroboration_count": 0}, {"ioc_type": "ipv4", "contestation_certainty": 2},
])
def test_assess_rejects_bad_input(bad):
    with pytest.raises(A.ValidationError):
        A.assess(bad)


def test_curve_bounds_enforced():
    with pytest.raises(A.ValidationError):
        A.curve({"ioc_type": "ipv4", "points": 100000})
    with pytest.raises(A.ValidationError):
        A.curve({"ioc_type": "ipv4", "start_hours": 10, "end_hours": 5})


def test_custom_weights_change_the_result():
    w = {"source": 1.0, "corroboration": 0.0, "freshness": 0.0, "context": 0.0, "analyst": 0.0}
    r = A.assess({"ioc_type": "ipv4", "source": "mitre_attack", "weights": w})
    assert r["composite"] == pytest.approx(1.0)


def test_parent_technique_collapse():
    assert A.parent_technique("T1059.001") == "T1059" and A.parent_technique("T1566") == "T1566"
    r = A.compare("x", ["T1059.001", "T1059.003"], "y", ["T1059.005"], level="parent")
    assert r["jaccard"] == 1.0 and r["convergent"]
    r2 = A.compare("x", ["T1059.001", "T1059.003"], "y", ["T1059.005"], level="technique")
    assert r2["jaccard"] == 0.0


def test_compare_rejects_oversized_and_non_lists():
    with pytest.raises(A.ValidationError):
        A.compare("x", "T1059", "y", [])
    with pytest.raises(A.ValidationError):
        A.compare("x", [f"T{i}" for i in range(A.MAX_TTPS + 1)], "y", [])


def test_matrix_on_repository_data_is_symmetric_with_unit_diagonal():
    actors = A.load_actors()
    assert len(actors) == 12
    for lvl in ("technique", "parent"):
        m = A.matrix(actors, lvl)
        n = len(actors)
        assert all(m["matrix"][i][i] == 1.0 for i in range(n))
        assert all(m["matrix"][i][j] == m["matrix"][j][i] for i in range(n) for j in range(n))
        assert 0.0 <= m["max_offdiagonal"] <= 1.0


def test_meta_lists_engine_parameters():
    m = A.meta()
    assert "tor_exit" in m["host_types"] and ".tk" in m["tlds"] and m["convergence_threshold"] == 0.65
