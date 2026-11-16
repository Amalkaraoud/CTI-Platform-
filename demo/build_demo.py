#!/usr/bin/env python3
"""
Build ONYX Signal Lab: a self-contained HTML demo driven by the platform's real engines.

What is real:
  - decay curves, confidence composite and convergence scores are computed by the
    unmodified engines in onyx-core / onyx-api (loaded straight from their files,
    so no third-party dependency is required);
  - actor technique sets come from actors.json (MITRE ATT&CK export shipped in the repo);
  - the indicator values come from onyx-api/assets/osint_cache.json (the platform's seed cache).

What is simulated (and labelled as such in the page):
  - "hours since last seen" for the seed indicators: the cache carries no observation
    timestamps, so AGE_AT_T0 below assigns illustrative ones. CVE ages are real
    (days since NVD publication date, relative to REFERENCE_DATE).

Usage:  python3 demo/build_demo.py        ->  demo/ONYX_Signal_Lab.html
"""
from __future__ import annotations

import importlib.util
import json
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REFERENCE_DATE = date(2026, 11, 17)


def load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name] = mod          # required by dataclasses
    spec.loader.exec_module(mod)
    return mod


decay = load("onyx_decay", "onyx-core/onyx_core/services/decay_engine.py")
conf = load("onyx_conf", "onyx-core/onyx_core/services/confidence_composite.py")
conv = load("onyx_conv", "onyx-api/onyx_api/services/behavioral_convergence.py")
analysis = load("onyx_analysis", "onyx-api/onyx_api/services/analysis.py")

# Seed-cache source label -> key of SOURCE_RELIABILITY (unmapped labels fall to "unknown",
# which is exactly what the engine does in production).
SOURCE_KEY = {
    "MISP Warninglist": "circl_misp",
    "abuse.ch Feodo Tracker": "abuse_ch_feodo",
    "abuse.ch URLhaus": "abuse_ch_urlhaus",
    "URLhaus": "abuse_ch_urlhaus",
    "OTX AlienVault": "otx_alienvault",
    "Spamhaus DROP": "spamhaus",
    "AbuseIPDB": "abuseipdb",
    "CISA KEV": "cisa_advisory",
    "MalTrail": "unverified_community",
    "SpiderFoot OSINT": "unverified_community",
    "FireEye iSIGHT": "mandiant_apt",
}

# Illustrative hours-since-last-seen at t0 (SIMULATED; see module docstring).
AGE_AT_T0_H = {
    "185.220.101.45": 10, "91.108.56.181": 30, "194.165.16.78": 55, "45.142.212.100": 5,
    "77.83.36.18": 80, "5.188.86.172": 20, "91.219.236.137": 40, "195.123.246.138": 120,
    "185.220.101.47": 14, "onion-router-c2.tk": 24 * 2, "update-microsoft-cdn.ru": 24 * 9,
    "evil-beacon-2026.xyz": 24 * 4, "103.21.124.5": 8, "175.45.176.3": 24 * 6,
}
CVE_PUBLISHED = {  # real NVD publication dates
    "CVE-2024-21887": date(2024, 1, 10),
    "CVE-2023-44487": date(2023, 10, 10),
}
EXPLOITED = {"CVE-2024-21887": True, "CVE-2023-44487": True}


def host_type(tags: list[str]) -> str:
    if "tor-exit" in tags:
        return "tor_exit"
    if "hijacked" in tags or "drop" in tags:
        return "bulletproof"
    if "c2" in tags or "feodo" in tags:
        return "dedicated_criminal"
    return "default"


def tld(value: str) -> str:
    return "." + value.rsplit(".", 1)[-1]


STEP_H, MAX_H = 6, 720
STEPS = list(range(0, MAX_H + 1, STEP_H))


def build_iocs():
    cache = json.loads((ROOT / "onyx-api/assets/osint_cache.json").read_text(encoding="utf-8"))
    out = []
    for ioc in cache["iocs"]:
        v, t = ioc["value"], ioc["type"]
        if t == "cve":
            base_h = (REFERENCE_DATE - CVE_PUBLISHED[v]).days * 24.0
            age_note = "real: days since NVD publication"
        else:
            base_h = float(AGE_AT_T0_H[v])
            age_note = "simulated"
        kw = {}
        if t == "ipv4":
            kw["host_type"] = host_type(ioc["tags"])
        elif t == "domain":
            kw["tld"] = tld(v)
            kw["registrar_tier"] = 3
        elif t == "cve":
            kw["exploit_available"] = EXPLOITED[v]
        src_key = SOURCE_KEY.get(ioc["source"], "unknown")
        series = {}
        for n in (1, 3):
            row = []
            for h in STEPS:
                d = decay.calculate_decay(t, base_h + h, **kw)
                b = conf.calculate_composite_confidence(src_key, d, corroboration_count=n)
                row.append([round(d, 4), round(b.composite, 4), decay.classify_decay_state(d).value])
            series[str(n)] = row
        b0 = conf.calculate_composite_confidence(src_key, series["1"][0][0], corroboration_count=1)
        out.append({
            "type": t, "value": v, "source": ioc["source"], "source_key": src_key,
            "tags": ioc["tags"], "vendor_confidence": ioc["confidence"],
            "base_age_h": base_h, "age_note": age_note, "params": kw,
            "parts": {
                "source": round(b0.source_reliability, 4),
                "corroboration": round(b0.corroboration, 4),
                "freshness": round(b0.freshness, 4),
                "context": round(b0.contextual_relevance, 4),
            },
            "series": series,
        })
    return out


def build_curves():
    """Decay of each indicator family over 0..60 days, default parameters."""
    spec = [
        ("ipv4 (tor exit)", "ipv4", {"host_type": "tor_exit"}),
        ("ipv4 (cloud)", "ipv4", {"host_type": "cloud_legitimate"}),
        ("ipv4 (bulletproof)", "ipv4", {"host_type": "bulletproof"}),
        ("url", "url", {}),
        ("domain .xyz", "domain", {"tld": ".xyz", "registrar_tier": 3}),
        ("domain .com", "domain", {"tld": ".com", "registrar_tier": 3}),
        ("sha256", "sha256", {}),
        ("ja3", "ja3", {}),
    ]
    days = list(range(0, 61))
    return {
        "days": days,
        "series": [
            {"label": lbl, "values": [round(decay.calculate_decay(t, d * 24.0, **kw), 4) for d in days]}
            for lbl, t, kw in spec
        ],
    }


def build_convergence():
    """Both comparison levels, from the same facade the REST API uses."""
    actors = analysis.load_actors()
    out = {"threshold": conv.CONVERGENCE_THRESHOLD}
    for level in ("technique", "parent"):
        m = analysis.matrix(actors, level)
        detail = {}
        for i, a in enumerate(actors):
            for b in actors[i + 1:]:
                r = analysis.compare(a["name"], a["ttps"], b["name"], b["ttps"], level)
                detail[f'{a["name"]}|{b["name"]}'] = {"shared": r["shared"], "na": len(r["only_a"]),
                                                      "nb": len(r["only_b"]), "convergent": r["convergent"]}
        out[level] = {"actors": m["actors"], "matrix": m["matrix"], "max": m["max_offdiagonal"],
                      "top": m["top_pairs"], "detail": detail}
    return out


def main():
    data = {
        "reference_date": REFERENCE_DATE.isoformat(),
        "steps": STEPS,
        "weights": conf.DEFAULT_WEIGHTS,
        "iocs": build_iocs(),
        "curves": build_curves(),
        "convergence": build_convergence(),
        "meta": analysis.meta(),
    }
    tpl = (ROOT / "demo/template.html").read_text(encoding="utf-8")
    html = tpl.replace("/*__DATA__*/null", json.dumps(data, separators=(",", ":")))
    out = ROOT / "demo/ONYX_Signal_Lab.html"
    out.write_text(html, encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}  ({out.stat().st_size // 1024} KiB, "
          f"{len(data['iocs'])} indicators, {len(data['convergence']['technique']['actors'])} actors)")


if __name__ == "__main__":
    main()
