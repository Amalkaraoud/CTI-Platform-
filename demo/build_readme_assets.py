"""Generate docs/assets/banner.svg and docs/assets/decay-profiles.svg from the real decay engine.

Stdlib only. Every plotted value comes from onyx-api/onyx_api/services/analysis.py (decay_engine).
Run:  python3 demo/build_readme_assets.py
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("an", ROOT / "onyx-api/onyx_api/services/analysis.py")
an = importlib.util.module_from_spec(spec)
sys.modules["an"] = an
spec.loader.exec_module(an)

DAYS = 120
PROFILES = [  # label, params, colour
    ("IPv4, cloud provider", {"ioc_type": "ipv4", "host_type": "cloud_legitimate"}, "#7d8aa0"),
    ("IPv4, criminal hosting", {"ioc_type": "ipv4", "host_type": "dedicated_criminal"}, "#e0a458"),
    ("Domain, .com", {"ioc_type": "domain", "tld": ".com"}, "#5ee0d0"),
    ("Domain, .tk", {"ioc_type": "domain", "tld": ".tk"}, "#c77dff"),
    ("JA3 fingerprint", {"ioc_type": "ja3"}, "#8fb8ff"),
    ("SHA-256 hash", {"ioc_type": "sha256"}, "#e8edf4"),
]
FONT = "-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"
MONO = "ui-monospace,'SF Mono',Consolas,'DejaVu Sans Mono',monospace"


def series(params):
    r = an.curve({**params, "start_hours": 0, "end_hours": DAYS * 24, "points": 121})
    half = r["first_hour_at_or_below_half"]
    if half is not None:  # refine: same engine, finer window around the crossing
        r2 = an.curve({**params, "start_hours": 0, "end_hours": max(half * 1.5, 2), "points": 500})
        half = r2["first_hour_at_or_below_half"]
    return [(p["hours"] / 24.0, p["decay"]) for p in r["points"]], half


def path(pts, x0, y0, w, h, xmax=DAYS):
    return " ".join(("M" if i == 0 else "L") + f"{x0 + d / xmax * w:.1f},{y0 + (1 - v) * h:.1f}"
                    for i, (d, v) in enumerate(pts))


def banner():
    W, H = 1280, 360
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" '
         f'aria-label="ONYX CTI: threat intelligence that knows when an indicator goes stale">',
         '<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0a0e13"/>'
         '<stop offset="1" stop-color="#101822"/></linearGradient>'
         '<linearGradient id="fade" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#0a0e13" stop-opacity="1"/>'
         '<stop offset="0.55" stop-color="#0a0e13" stop-opacity="0.85"/><stop offset="1" stop-color="#0a0e13" stop-opacity="0"/></linearGradient></defs>',
         f'<rect width="{W}" height="{H}" fill="url(#bg)"/>']
    # faint grid
    for gx in range(0, W, 80):
        s.append(f'<line x1="{gx}" y1="0" x2="{gx}" y2="{H}" stroke="#ffffff" stroke-opacity="0.025"/>')
    for gy in range(0, H, 80):
        s.append(f'<line x1="0" y1="{gy}" x2="{W}" y2="{gy}" stroke="#ffffff" stroke-opacity="0.025"/>')
    # real decay curves on the right
    x0, y0, w, h = 800, 70, 420, 220
    s.append(f'<line x1="{x0}" y1="{y0 + h / 2:.0f}" x2="{x0 + w}" y2="{y0 + h / 2:.0f}" stroke="#5ee0d0" stroke-opacity="0.25" stroke-dasharray="4 6"/>')
    for label, params, col in PROFILES:
        pts, _ = series(params)
        s.append(f'<path d="{path(pts, x0, y0, w, h)}" fill="none" stroke="{col}" stroke-width="2" stroke-linecap="round" stroke-opacity="0.9"/>')
    s.append(f'<text x="{x0 + w}" y="{y0 + h / 2 - 8:.0f}" text-anchor="end" font-family="{MONO}" font-size="11" fill="#5ee0d0" fill-opacity="0.7">0.5</text>')
    s.append(f'<text x="{x0}" y="{y0 + h + 28}" font-family="{MONO}" font-size="11" fill="#7d8aa0">day 0</text>')
    s.append(f'<text x="{x0 + w}" y="{y0 + h + 28}" text-anchor="end" font-family="{MONO}" font-size="11" fill="#7d8aa0">day {DAYS}  (computed by decay_engine.py)</text>')
    s.append(f'<rect x="0" y="0" width="860" height="{H}" fill="url(#fade)"/>')
    # wordmark
    s.append(f'<text x="64" y="168" font-family="{FONT}" font-size="92" font-weight="800" letter-spacing="6" fill="#f2f5f9">ONYX</text>')
    s.append(f'<text x="64" y="168" dx="300" font-family="{FONT}" font-size="92" font-weight="200" letter-spacing="6" fill="#5ee0d0">CTI</text>')
    s.append(f'<rect x="66" y="196" width="72" height="3" fill="#5ee0d0"/>')
    s.append(f'<text x="64" y="240" font-family="{FONT}" font-size="24" fill="#c9d3df">Threat intelligence that knows when an indicator goes stale.</text>')
    s.append(f'<text x="64" y="282" font-family="{MONO}" font-size="14" fill="#7d8aa0" letter-spacing="1.5">DECAY  /  COMPOSITE CONFIDENCE  /  BEHAVIOURAL CONVERGENCE</text>')
    s.append("</svg>")
    return "\n".join(s)


def profiles():
    W, H = 1100, 520
    x0, y0, w, h = 90, 70, 640, 340
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" '
         f'aria-label="Decay of six indicator profiles over {DAYS} days, computed by the ONYX decay engine">',
         f'<rect width="{W}" height="{H}" rx="10" fill="#0d1218"/>',
         f'<text x="40" y="38" font-family="{FONT}" font-size="18" font-weight="600" fill="#f2f5f9">How fast does an indicator lose value?</text>',
         f'<text x="40" y="58" font-family="{FONT}" font-size="12.5" fill="#7d8aa0">Freshness score over {DAYS} days for six indicator profiles. Values from onyx-core decay_engine.calculate_decay, not hand-drawn.</text>']
    for v in (0, 0.25, 0.5, 0.75, 1.0):
        y = y0 + (1 - v) * h
        s.append(f'<line x1="{x0}" y1="{y:.1f}" x2="{x0 + w}" y2="{y:.1f}" stroke="#ffffff" stroke-opacity="{0.22 if v == 0.5 else 0.07}"' + (' stroke-dasharray="4 5"' if v == 0.5 else '') + '/>')
        s.append(f'<text x="{x0 - 12}" y="{y + 4:.1f}" text-anchor="end" font-family="{MONO}" font-size="11" fill="#7d8aa0">{v:.2f}</text>')
    for d in range(0, DAYS + 1, 20):
        x = x0 + d / DAYS * w
        s.append(f'<text x="{x:.1f}" y="{y0 + h + 22}" text-anchor="middle" font-family="{MONO}" font-size="11" fill="#7d8aa0">{d} d</text>')
    ly = 100
    for label, params, col in PROFILES:
        pts, half = series(params)
        s.append(f'<path d="{path(pts, x0, y0, w, h)}" fill="none" stroke="{col}" stroke-width="2.4" stroke-linecap="round"/>')
        if half is not None:
            hx = x0 + (half / 24.0) / DAYS * w
            s.append(f'<circle cx="{hx:.1f}" cy="{y0 + h / 2:.1f}" r="3.5" fill="{col}"/>')
            htxt = f"score reaches 0.5 at about {half:.0f} h" if half < 72 else f"score reaches 0.5 at about day {half / 24:.0f}"
        else:
            htxt = f"day {DAYS}: {pts[-1][1]:.2f}"
        s.append(f'<rect x="770" y="{ly - 10}" width="14" height="3" fill="{col}"/>')
        s.append(f'<text x="794" y="{ly - 4}" font-family="{FONT}" font-size="14" fill="#e6ebf2">{label}</text>')
        s.append(f'<text x="794" y="{ly + 14}" font-family="{MONO}" font-size="11.5" fill="#7d8aa0">{htxt}</text>')
        ly += 52
    s.append(f'<text x="40" y="{H - 22}" font-family="{FONT}" font-size="12" fill="#7d8aa0">Dashed line: score 0.5. A hash decays slowly by design (it stays useful for forensics); a criminal-hosted IP is recycled within days.</text>')
    s.append("</svg>")
    return "\n".join(s)


if __name__ == "__main__":
    out = ROOT / "docs" / "assets"
    (out / "banner.svg").write_text(banner(), encoding="utf-8")
    (out / "decay-profiles.svg").write_text(profiles(), encoding="utf-8")
    print("wrote banner.svg, decay-profiles.svg")
