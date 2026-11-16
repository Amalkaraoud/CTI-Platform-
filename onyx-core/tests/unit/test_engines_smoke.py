"""Dependency-light tests (stdlib + pytest only) for the scoring engines."""
import importlib.util
import math
import sys
from pathlib import Path

import pytest

# Both engines are pure Python. They are loaded by path so these tests run even where the
# heavy optional dependencies imported by onyx_core/__init__.py (elasticsearch, redis...) are absent.
_SVC = Path(__file__).resolve().parents[2] / "onyx_core" / "services"


def _load(name):
    spec = importlib.util.spec_from_file_location(f"_t_{name}", _SVC / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


_d, _c = _load("decay_engine"), _load("confidence_composite")
calculate_decay, classify_decay_state, DecayState = _d.calculate_decay, _d.classify_decay_state, _d.DecayState
ConfidenceWeights, calculate_composite_confidence = _c.ConfidenceWeights, _c.calculate_composite_confidence
corroboration_score, get_source_reliability = _c.corroboration_score, _c.get_source_reliability


def test_half_life_is_exact_for_tor_exit():
    assert calculate_decay("ipv4", 48.0, host_type="tor_exit") == pytest.approx(0.5)


def test_decay_is_monotonic_non_increasing():
    vals = [calculate_decay("url", h) for h in range(0, 500, 12)]
    assert all(a >= b for a, b in zip(vals, vals[1:]))


def test_hash_and_cve_floors():
    assert calculate_decay("sha256", 24 * 5000) == pytest.approx(0.30)
    assert calculate_decay("cve", 24 * 5000) == pytest.approx(0.10)


def test_revoked_hash_is_near_zero():
    assert calculate_decay("sha256", 0, revoked=True) == 0.05


def test_unknown_type_rejected():
    with pytest.raises(ValueError):
        calculate_decay("carrier_pigeon", 1)


@pytest.mark.parametrize("score,state", [(0.95, DecayState.VALID), (0.6, DecayState.DEGRADING),
                                          (0.3, DecayState.STALE), (0.01, DecayState.OBSOLETE)])
def test_state_thresholds(score, state):
    assert classify_decay_state(score) is state


def test_corroboration_reference_values():
    assert corroboration_score(1) == pytest.approx(1 - math.exp(-0.5))
    assert corroboration_score(5) > 0.9


def test_unknown_source_falls_back_and_prefix_match_works():
    assert get_source_reliability("nobody") == 0.15
    assert get_source_reliability("mandiant_apt_report_2024") == 0.92


def test_weights_must_sum_to_one():
    with pytest.raises(ValueError):
        ConfidenceWeights(source=0.5)


def test_contestation_lowers_composite_and_fresh_beats_stale():
    fresh = calculate_composite_confidence("cisa_advisory", 1.0).composite
    stale = calculate_composite_confidence("cisa_advisory", 0.0).composite
    contested = calculate_composite_confidence("cisa_advisory", 1.0, contested=True,
                                               contestation_certainty=0.0).composite
    assert fresh > stale
    assert contested == pytest.approx(fresh * 0.65)
    assert 0.0 <= fresh <= 1.0
