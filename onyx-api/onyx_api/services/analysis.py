"""
ONYX CTI - Engine analysis facade (pure Python, stdlib only).

Dict-in / dict-out functions over the three scoring engines, so that the REST router,
the Signal Lab server and the tests all call the same code path:

    decay_engine.calculate_decay            -> freshness
    confidence_composite                    -> composite score and its decomposition
    behavioral_convergence.jaccard          -> actor comparison

Nothing here re-implements a formula. It validates input, calls the engines, and shapes
the output (including the weighted contribution of each component, which the engines
compute internally but do not return).
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[3]


def _load(module: str, rel_path: str):
    """Import from the installed package; fall back to the file when heavy deps are missing."""
    try:
        return importlib.import_module(module)
    except Exception:
        name = "_onyx_" + module.replace(".", "_")
        if name in sys.modules:
            return sys.modules[name]
        spec = importlib.util.spec_from_file_location(name, _ROOT / rel_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod


decay = _load("onyx_core.services.decay_engine", "onyx-core/onyx_core/services/decay_engine.py")
conf = _load("onyx_core.services.confidence_composite", "onyx-core/onyx_core/services/confidence_composite.py")
conv = _load("onyx_api.services.behavioral_convergence", "onyx-api/onyx_api/services/behavioral_convergence.py")

IOC_TYPES = ["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email", "ja3", "ja4",
             "mutex", "registry_key", "named_pipe", "user_agent", "yara_rule", "cve"]
MAX_POINTS = 500
MAX_HOURS = 24 * 365 * 5
MAX_TTPS = 2000


class ValidationError(ValueError):
    """Bad caller input; the router maps it to HTTP 422."""


def _num(payload: dict, key: str, default: float, lo: float, hi: float) -> float:
    try:
        v = float(payload.get(key, default))
    except (TypeError, ValueError):
        raise ValidationError(f"{key} must be a number")
    if not (lo <= v <= hi) or v != v:
        raise ValidationError(f"{key} must be between {lo} and {hi}")
    return v


def _choice(payload: dict, key: str, allowed, default):
    v = payload.get(key, default)
    if v not in allowed:
        raise ValidationError(f"{key} must be one of {sorted(map(str, allowed))}")
    return v


def meta() -> dict[str, Any]:
    return {
        "ioc_types": IOC_TYPES,
        "host_types": sorted(decay._IP_HALF_LIFE_HOURS),
        "tlds": sorted(decay._TLD_BASE_HALF_LIFE_DAYS),
        "registrar_tiers": sorted(decay._REGISTRAR_TIER_MODIFIER),
        "sources": dict(sorted(conf.SOURCE_RELIABILITY.items(), key=lambda kv: -kv[1])),
        "default_weights": dict(conf.DEFAULT_WEIGHTS),
        "convergence_threshold": conv.CONVERGENCE_THRESHOLD,
        "states": [
            {"name": "valid", "above": 0.80}, {"name": "degrading", "above": 0.50},
            {"name": "stale", "above": 0.15}, {"name": "obsolete", "above": 0.0},
        ],
    }


def _decay_kwargs(p: dict) -> dict[str, Any]:
    kw: dict[str, Any] = {}
    if "host_type" in p:
        kw["host_type"] = _choice(p, "host_type", decay._IP_HALF_LIFE_HOURS, "default")
    if "tld" in p:
        kw["tld"] = _choice(p, "tld", decay._TLD_BASE_HALF_LIFE_DAYS, "default")
    if "registrar_tier" in p:
        kw["registrar_tier"] = int(_choice(p, "registrar_tier", decay._REGISTRAR_TIER_MODIFIER, 2))
    if p.get("revoked"):
        kw["revoked"] = True
    if p.get("exploit_available"):
        kw["exploit_available"] = True
    if p.get("learned_half_life_hours") not in (None, ""):
        kw["learned_half_life_hours"] = _num(p, "learned_half_life_hours", 1, 0.1, 24 * 3650)
    return kw


def decay_value(ioc_type: str, hours: float, params: dict) -> float:
    try:
        return decay.calculate_decay(ioc_type, hours, **_decay_kwargs(params))
    except ValueError as e:               # unsupported type
        raise ValidationError(str(e))


def curve(p: dict) -> dict[str, Any]:
    """Decay over time for one indicator profile."""
    t = _choice(p, "ioc_type", IOC_TYPES, "ipv4")
    start = _num(p, "start_hours", 0, 0, MAX_HOURS)
    end = _num(p, "end_hours", 24 * 30, 1, MAX_HOURS)
    pts = int(_num(p, "points", 61, 2, MAX_POINTS))
    if end <= start:
        raise ValidationError("end_hours must be greater than start_hours")
    out = []
    for i in range(pts):
        h = start + (end - start) * i / (pts - 1)
        d = decay_value(t, h, p)
        out.append({"hours": round(h, 3), "decay": round(d, 5),
                    "state": decay.classify_decay_state(d).value})
    half = next((x["hours"] for x in out if x["decay"] <= 0.5), None)
    return {"ioc_type": t, "points": out, "first_hour_at_or_below_half": half}


def assess(p: dict) -> dict[str, Any]:
    """Freshness + composite confidence for one indicator, with the weighted contribution of each part."""
    t = _choice(p, "ioc_type", IOC_TYPES, "ipv4")
    hours = _num(p, "hours_since_seen", 0, 0, MAX_HOURS)
    source = str(p.get("source", "unknown"))[:80]
    n = int(_num(p, "corroboration_count", 1, 1, 50))
    d = decay_value(t, hours, p)
    override = p.get("analyst_override_score")
    override = None if override in (None, "") else int(_num(p, "analyst_override_score", 0, 0, 100))
    contested = bool(p.get("contested"))
    certainty = _num(p, "contestation_certainty", 1.0, 0.0, 1.0)
    try:
        w = conf.ConfidenceWeights(**{k: float(v) for k, v in (p.get("weights") or conf.DEFAULT_WEIGHTS).items()})
    except (TypeError, ValueError) as e:
        raise ValidationError(f"weights: {e}")

    b = conf.calculate_composite_confidence(
        source, d, corroboration_count=n,
        actor_sectors=p.get("actor_sectors"), actor_countries=p.get("actor_countries"),
        ioc_campaign_sectors=p.get("campaign_sectors"), ioc_campaign_countries=p.get("campaign_countries"),
        contested=contested, contestation_certainty=certainty,
        analyst_override_score=override, weights=w,
    )
    analyst_part = b.analyst_override if b.analyst_override is not None else (b.source_reliability + b.freshness) / 2
    parts = [
        ("source", w.source, b.source_reliability), ("corroboration", w.corroboration, b.corroboration),
        ("freshness", w.freshness, b.freshness), ("context", w.context, b.contextual_relevance),
        ("analyst", w.analyst, analyst_part),
    ]
    return {
        "ioc_type": t, "hours_since_seen": hours,
        "decay": round(d, 5), "state": decay.classify_decay_state(d).value,
        "source": source, "source_known": source.lower().strip() in conf.SOURCE_RELIABILITY,
        "composite": round(b.composite, 5),
        "contestation_penalty": b.contestation_penalty,
        "components": [{"name": k, "weight": round(wt, 4), "value": round(v, 5), "contribution": round(wt * v, 5)}
                       for k, wt, v in parts],
        "analyst_component_derived": b.analyst_override is None,
    }


# ----------------------------------------------------------------------------
# Convergence
# ----------------------------------------------------------------------------
def parent_technique(tid: str) -> str:
    """T1059.001 -> T1059"""
    return tid.split(".", 1)[0]


def _ttps(raw: Any, level: str) -> set[str]:
    if not isinstance(raw, (list, tuple, set)) or len(raw) > MAX_TTPS:
        raise ValidationError(f"techniques must be a list of at most {MAX_TTPS} identifiers")
    ids = {str(x).strip().upper() for x in raw if str(x).strip()}
    return {parent_technique(i) for i in ids} if level == "parent" else ids


def compare(a_name: str, a_ttps: Any, b_name: str, b_ttps: Any, level: str = "technique") -> dict[str, Any]:
    level = _choice({"level": level}, "level", ("technique", "parent"), "technique")
    r = conv.BehavioralConvergenceEngine().compare(a_name, sorted(_ttps(a_ttps, level)), b_name, sorted(_ttps(b_ttps, level)))
    return {"a": a_name, "b": b_name, "level": level, "jaccard": r.jaccard_score,
            "shared": r.shared_techniques, "only_a": r.unique_to_a, "only_b": r.unique_to_b,
            "convergent": r.convergent, "threshold": conv.CONVERGENCE_THRESHOLD,
            "interpretation": r.interpretation}


def load_actors(path: Path | None = None) -> list[dict[str, Any]]:
    """Read the MITRE actor export shipped in the repository (UTF-16 JSON)."""
    path = path or _ROOT / "actors.json"
    raw = path.read_bytes()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8")
    actors = []
    for a in json.loads(text)["threat_actors"]:
        t = a["techniques"]
        t = ast.literal_eval(t) if isinstance(t, str) else t
        actors.append({"name": a["name"], "target": a.get("target", ""), "status": a.get("status", ""),
                       "ttps": sorted({x["id"] for x in t})})
    return actors


def matrix(actors: list[dict[str, Any]], level: str = "technique") -> dict[str, Any]:
    level = _choice({"level": level}, "level", ("technique", "parent"), "technique")
    sets = [_ttps(a["ttps"], level) for a in actors]
    m = [[round(conv.jaccard(x, y), 4) for y in sets] for x in sets]
    off = [m[i][j] for i in range(len(m)) for j in range(len(m)) if i != j]
    top = sorted(((m[i][j], actors[i]["name"], actors[j]["name"])
                  for i in range(len(m)) for j in range(i + 1, len(m))), reverse=True)[:5]
    return {"level": level, "threshold": conv.CONVERGENCE_THRESHOLD,
            "actors": [{"name": a["name"], "count": len(s), "status": a["status"], "target": a["target"]}
                       for a, s in zip(actors, sets)],
            "matrix": m, "max_offdiagonal": max(off) if off else 0.0,
            "pairs_at_or_above_threshold": sum(1 for v in off if v >= conv.CONVERGENCE_THRESHOLD) // 2,
            "top_pairs": [{"jaccard": s, "a": a, "b": b} for s, a, b in top]}
