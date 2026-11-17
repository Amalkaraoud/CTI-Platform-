"""
ONYX CTI - detection rule generation (YARA and Sigma), standard library only.

Turns a validated threat (name, indicators, ATT&CK techniques) into rules that SOC tooling can load:

  * Sigma rules (YAML text), one per telemetry category: DNS queries for domains, network
    connections for IPv4 addresses, proxy/web logs for URLs, file events for hashes.
  * One YARA rule combining string matches (domains, URLs, IPs) and file-hash conditions.

Nothing here contacts a network or reads a file. Indicators are validated and escaped before they
reach a rule, so a hostile indicator value cannot inject rule syntax.
The output is syntactically conservative; it has not been compiled against a YARA engine in this
repository's test environment (see tests/test_rules.py for what is verified).
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import date
from typing import Any, Iterable

_NS = uuid.UUID("6f0b8a52-4f3a-4b9e-9a55-0e11a0c7e001")   # fixed namespace: same input -> same rule id
_HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_LEVELS = {"low", "medium", "high", "critical"}


def _slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")
    return (s or "threat")[:48]


def _yaml_str(s: str) -> str:
    """Single-quoted YAML scalar (the only escape needed is a doubled quote); newlines are folded."""
    return "'" + " ".join(str(s).split()).replace("'", "''") + "'"


def _yara_str(s: str) -> str:
    out = []
    for ch in s:
        if ch in '\\"':
            out.append("\\" + ch)
        elif ord(ch) < 32 or ord(ch) > 126:
            out.append("\\x%02x" % (ord(ch) & 0xFF) if ord(ch) < 256 else "?")
        else:
            out.append(ch)
    return "".join(out)


def sanitize_indicators(iocs: Iterable[dict[str, Any]]) -> dict[str, list[str]]:
    """Group valid indicator values by kind; silently drop malformed ones."""
    out: dict[str, set[str]] = {"domain": set(), "ipv4": set(), "url": set(), "md5": set(), "sha1": set(), "sha256": set()}
    for i in iocs:
        t, v = str(i.get("type", "")).lower(), str(i.get("value", "")).strip()
        if t in ("domain", "hostname") and _DOMAIN.match(v.lower()):
            out["domain"].add(v.lower())
        elif t in ("ip", "ipv4"):
            try:
                if ipaddress.ip_address(v).version == 4 and ipaddress.ip_address(v).is_global:
                    out["ipv4"].add(v)
            except ValueError:
                pass
        elif t == "url" and re.match(r"^https?://[^\s'\"<>\\]{1,2000}$", v, re.I):
            out["url"].add(v)
        elif t in _HASH_LEN and re.fullmatch(r"[0-9a-fA-F]{%d}" % _HASH_LEN[t], v):
            out[t].add(v.lower())
    return {k: sorted(v) for k, v in out.items() if v}


def _tags(techniques: Iterable[str]) -> list[str]:
    return sorted({"attack." + t.lower() for t in map(lambda x: str(x).upper(), techniques) if _TECHNIQUE.match(t)})


def _sigma(rule_key: str, title: str, desc: str, logsource: dict[str, str], detection: dict[str, Any],
           tags: list[str], level: str, today: str, refs: list[str]) -> dict[str, str]:
    lines = [
        f"title: {_yaml_str(title)}",
        f"id: {uuid.uuid5(_NS, rule_key)}",
        "status: experimental",
        f"description: {_yaml_str(desc)}",
        "references:" if refs else "references: []",
        *[f"    - {_yaml_str(r)}" for r in refs],
        "author: ONYX CTI",
        f"date: {today}",
    ]
    if tags:
        lines += ["tags:"] + [f"    - {t}" for t in tags]
    lines += ["logsource:"] + [f"    {k}: {v}" for k, v in logsource.items()]
    lines += ["detection:", "    selection:"]
    for field, values in detection.items():
        lines.append(f"        {field}:")
        lines += [f"            - {_yaml_str(v)}" for v in values]
    lines += ["    condition: selection", "falsepositives:", "    - Legitimate use of a shared or recycled indicator",
              f"level: {level}"]
    return {"rule_id": str(uuid.uuid5(_NS, rule_key)), "text": "\n".join(lines) + "\n"}


def generate_sigma(name: str, indicators: dict[str, list[str]], techniques: Iterable[str] = (),
                   level: str = "high", references: Iterable[str] = (), today: str | None = None) -> list[dict[str, str]]:
    level = level if level in _LEVELS else "medium"
    today = today or date.today().strftime("%Y/%m/%d")
    tags, refs = _tags(techniques), [r for r in references if re.match(r"^https?://\S+$", r)]
    base = f"ONYX {name}"
    specs = [
        ("domain", "DNS query to", {"category": "dns"}, "QueryName|endswith"),
        ("ipv4", "Connection to", {"category": "network_connection", "product": "windows"}, "DestinationIp"),
        ("url", "Web request to", {"category": "proxy"}, "c-uri|contains"),
    ]
    rules = []
    for kind, verb, logsource, field in specs:
        vals = indicators.get(kind)
        if vals:
            rules.append(_sigma(f"{name}|{kind}|{','.join(vals)}", f"{base} - {verb} known {kind} indicators",
                                f"Detects {kind} indicators attributed to {name} by ONYX CTI.",
                                logsource, {field: vals}, tags, level, today, refs))
    hashes = [f"{k.upper()}={h}" for k in ("md5", "sha1", "sha256") for h in indicators.get(k, [])]
    if hashes:
        rules.append(_sigma(f"{name}|hash|{','.join(hashes)}", f"{base} - File with known hash",
                            f"Detects files whose hash is attributed to {name} by ONYX CTI.",
                            {"category": "file_event", "product": "windows"}, {"Hashes|contains": hashes},
                            tags, level, today, refs))
    return rules


def generate_yara(name: str, indicators: dict[str, list[str]], techniques: Iterable[str] = (),
                  today: str | None = None) -> str | None:
    strings = [("dom", v) for v in indicators.get("domain", [])] + [("url", v) for v in indicators.get("url", [])] \
        + [("ip", v) for v in indicators.get("ipv4", [])]
    hashes = [(k, h) for k in ("md5", "sha1", "sha256") for h in indicators.get(k, [])]
    if not strings and not hashes:
        return None
    rid = uuid.uuid5(_NS, f"yara|{name}|{strings}|{hashes}")
    rule = f"ONYX_{_slug(name)}_{rid.hex[:8]}"
    out = []
    if hashes:
        out.append('import "hash"\n')
    out += [f"rule {rule}", "{", "    meta:", '        author = "ONYX CTI"', f'        threat = "{_yara_str(name)}"',
            f'        date = "{today or date.today().isoformat()}"', f'        id = "{rid}"',
            f'        attack = "{",".join(sorted(t.upper() for t in techniques if _TECHNIQUE.match(str(t).upper())))}"']
    conds = []
    if strings:
        out.append("    strings:")
        for n, (kind, v) in enumerate(strings):
            out.append(f'        $s{n} = "{_yara_str(v)}" ascii wide nocase')
        conds.append("any of ($s*)")
    for k, h in hashes:
        conds.append(f'hash.{k}(0, filesize) == "{h}"')
    out += ["    condition:", "        " + "\n        or ".join(conds), "}"]
    return "\n".join(out) + "\n"


def generate_rules(name: str, iocs: Iterable[dict[str, Any]], techniques: Iterable[str] = (), **kw: Any) -> dict[str, Any]:
    ind = sanitize_indicators(iocs)
    techniques = list(techniques)
    return {"threat": name, "indicator_counts": {k: len(v) for k, v in ind.items()},
            "sigma": generate_sigma(name, ind, techniques, **{k: v for k, v in kw.items() if k in ("level", "references", "today")}),
            "yara": generate_yara(name, ind, techniques, today=kw.get("today"))}
