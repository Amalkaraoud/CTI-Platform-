"""
ONYX CTI - export connectors toward partner systems (standard library only).

Implements the "Exportation vers partenaires" box of the architecture:

  * STIX 2.1 bundle builder (deterministic ids, x_onyx_* custom properties, TLP marking)
  * TAXII 2.1 push   -> any TAXII 2.1 server, including OpenCTI's TAXII endpoint
  * MISP             -> POST /events/add (MISP automation API)
  * Splunk HEC       -> POST /services/collector/event  (feeds Splunk SIEM)

Every sender takes the destination explicitly (no hidden configuration), accepts only http(s) URLs,
sets a timeout, and returns a small result dict instead of raising on remote HTTP errors.
Remote-server behaviour is verified against local stand-in servers in tests/test_export.py; a run
against a real MISP, OpenCTI or Splunk instance has NOT been performed.
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlparse

_NS = uuid.UUID("0a7d6f3e-2b1c-4e55-8c1e-5d9c2b7a0c11")
TLP = {   # STIX 2.1 marking-definition ids defined by the specification
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
_PATTERN = {"ipv4": "[ipv4-addr:value = '{v}']", "domain": "[domain-name:value = '{v}']",
            "url": "[url:value = '{v}']", "md5": "[file:hashes.MD5 = '{v}']",
            "sha1": "[file:hashes.'SHA-1' = '{v}']", "sha256": "[file:hashes.'SHA-256' = '{v}']"}
_MISP_TYPE = {"ipv4": "ip-dst", "domain": "domain", "url": "url", "md5": "md5", "sha1": "sha1", "sha256": "sha256"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def build_bundle(indicators: Iterable[dict[str, Any]], tlp: str = "amber", source: str = "onyx",
                 now: str | None = None) -> dict[str, Any]:
    """STIX 2.1 bundle of Indicator objects. Same (type, value) -> same id, so re-exports are idempotent."""
    ts = now or _now()
    objs, seen = [], set()
    for i in indicators:
        t, v = str(i.get("type", "")).lower(), str(i.get("value", ""))
        if t not in _PATTERN or not v or "'" in v or "\\" in v or (t, v) in seen:
            continue                                   # unknown type, empty, or value able to break the pattern
        seen.add((t, v))
        o = {"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid5(_NS, f'{t}|{v}')}",
             "created": ts, "modified": ts, "name": f"{t}: {v}"[:200], "pattern": _PATTERN[t].format(v=v),
             "pattern_type": "stix", "valid_from": i.get("first_seen") or ts,
             "indicator_types": ["malicious-activity"], "object_marking_refs": [TLP.get(tlp, TLP["amber"])],
             "x_onyx_source": i.get("source", source)}
        for k in ("confidence", "decay_state", "decay_score"):
            if i.get(k) is not None:
                o[f"x_onyx_{k}"] = i[k]
        if isinstance(i.get("confidence"), (int, float)) and 0 <= i["confidence"] <= 100:
            o["confidence"] = int(i["confidence"])    # STIX-native 0-100 field
        objs.append(o)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def _post(url: str, body: bytes, headers: dict[str, str], timeout: float = 15.0, verify_tls: bool = True) -> dict[str, Any]:
    if urlparse(url).scheme not in ("http", "https"):
        raise ValueError("only http(s) destinations are allowed")
    ctx = None if verify_tls else ssl._create_unverified_context()   # explicit opt-out, never the default
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return {"ok": True, "status": r.status, "body": r.read(65536).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "body": e.read(4096).decode("utf-8", "replace")}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "status": 0, "body": str(e)}


def push_taxii(objects_url: str, bundle: dict[str, Any], *, token: str | None = None, username: str | None = None,
               password: str | None = None, **kw: Any) -> dict[str, Any]:
    """POST an envelope to <api-root>/collections/<id>/objects/ (TAXII 2.1 section 5.4)."""
    h = {"Content-Type": "application/taxii+json;version=2.1", "Accept": "application/taxii+json;version=2.1"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    elif username is not None:
        h["Authorization"] = "Basic " + base64.b64encode(f"{username}:{password or ''}".encode()).decode()
    return _post(objects_url, json.dumps({"objects": bundle["objects"]}).encode(), h, **kw)


def build_misp_event(name: str, indicators: Iterable[dict[str, Any]], tlp: str = "amber") -> dict[str, Any]:
    attrs, seen = [], set()
    for i in indicators:
        t, v = str(i.get("type", "")).lower(), str(i.get("value", ""))
        if t in _MISP_TYPE and v and (t, v) not in seen:
            seen.add((t, v))
            attrs.append({"type": _MISP_TYPE[t], "category": "Network activity" if t in ("ipv4", "domain", "url") else "Payload delivery",
                          "value": v, "to_ids": True})
    return {"Event": {"info": f"ONYX CTI - {name}"[:255], "threat_level_id": "2", "analysis": "1", "distribution": "0",
                      "Tag": [{"name": f"tlp:{tlp}"}], "Attribute": attrs}}


def push_misp(base_url: str, api_key: str, event: dict[str, Any], **kw: Any) -> dict[str, Any]:
    h = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}
    return _post(base_url.rstrip("/") + "/events/add", json.dumps(event).encode(), h, **kw)


def build_splunk_events(indicators: Iterable[dict[str, Any]], index: str = "threat_intel",
                        sourcetype: str = "onyx:ioc") -> bytes:
    """HEC accepts concatenated JSON objects."""
    out = []
    for i in indicators:
        out.append(json.dumps({"time": datetime.now(timezone.utc).timestamp(), "index": index, "sourcetype": sourcetype,
                               "event": {k: i.get(k) for k in ("type", "value", "source", "confidence", "decay_state") if i.get(k) is not None}}))
    return "\n".join(out).encode()


def push_splunk_hec(base_url: str, hec_token: str, payload: bytes, **kw: Any) -> dict[str, Any]:
    h = {"Authorization": f"Splunk {hec_token}", "Content-Type": "application/json"}
    return _post(base_url.rstrip("/") + "/services/collector/event", payload, h, **kw)
