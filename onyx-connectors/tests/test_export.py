"""Export connectors against local stand-in HTTP servers (real sockets, real HTTP). No MISP/OpenCTI/Splunk is contacted."""
import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("export", Path(__file__).resolve().parents[1] / "onyx_connectors/export.py")
ex = importlib.util.module_from_spec(spec); sys.modules["export"] = ex; spec.loader.exec_module(ex)

INDS = [{"type": "ipv4", "value": "8.8.4.4", "confidence": 80, "decay_state": "valid", "decay_score": 0.91},
        {"type": "domain", "value": "evil.example.com"}, {"type": "sha256", "value": "a" * 64},
        {"type": "domain", "value": "evil.example.com"},                        # duplicate
        {"type": "url", "value": "http://x/'; DROP"},                           # would break the pattern
        {"type": "weird", "value": "zzz"}]


class _Srv:
    def __init__(self, status=200):
        self.seen, outer = [], self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.seen.append({"path": self.path, "headers": dict(self.headers), "body": self.rfile.read(n)})
                self.send_response(status); self.end_headers(); self.wfile.write(b'{"done":true}')
            def log_message(self, *a): pass
        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
    def close(self): self.httpd.shutdown()


@pytest.fixture
def srv():
    s = _Srv(); yield s; s.close()


def test_bundle_is_stix_shaped_idempotent_and_safe():
    b = ex.build_bundle(INDS, tlp="red", now="2026-11-17T00:00:00.000Z")
    assert b["type"] == "bundle" and len(b["objects"]) == 3                   # dup, unsafe and unknown dropped
    o = b["objects"][0]
    assert o["pattern"] == "[ipv4-addr:value = '8.8.4.4']" and o["spec_version"] == "2.1"
    assert o["object_marking_refs"] == [ex.TLP["red"]] and o["confidence"] == 80
    assert o["x_onyx_decay_state"] == "valid" and o["x_onyx_decay_score"] == 0.91 and o["x_onyx_source"] == "onyx"
    again = ex.build_bundle(INDS, now="2026-11-18T00:00:00.000Z")
    assert [x["id"] for x in again["objects"]] == [x["id"] for x in b["objects"]]


def test_taxii_push_headers_and_envelope(srv):
    r = ex.push_taxii(srv.url + "/taxii2/root/collections/abc/objects/", ex.build_bundle(INDS), token="tok")
    assert r["ok"] and r["status"] == 200
    got = srv.seen[0]
    assert got["path"] == "/taxii2/root/collections/abc/objects/"
    assert got["headers"]["Content-Type"] == "application/taxii+json;version=2.1" and got["headers"]["Authorization"] == "Bearer tok"
    assert len(json.loads(got["body"])["objects"]) == 3


def test_misp_event_and_push(srv):
    ev = ex.build_misp_event("APT X", INDS, tlp="green")
    types = [a["type"] for a in ev["Event"]["Attribute"]]
    assert types == ["ip-dst", "domain", "sha256", "url"]   # MISP has no pattern language: the url stays and ev["Event"]["Tag"] == [{"name": "tlp:green"}]
    r = ex.push_misp(srv.url + "/", "KEY123", ev)
    assert r["ok"] and srv.seen[0]["path"] == "/events/add" and srv.seen[0]["headers"]["Authorization"] == "KEY123"
    assert json.loads(srv.seen[0]["body"])["Event"]["info"] == "ONYX CTI - APT X"


def test_splunk_hec(srv):
    payload = ex.build_splunk_events(INDS[:2])
    r = ex.push_splunk_hec(srv.url, "hectok", payload)
    got = srv.seen[0]
    assert r["ok"] and got["path"] == "/services/collector/event" and got["headers"]["Authorization"] == "Splunk hectok"
    lines = [json.loads(l) for l in got["body"].decode().split("\n")]
    assert lines[0]["event"]["value"] == "8.8.4.4" and lines[0]["sourcetype"] == "onyx:ioc"


def test_remote_errors_do_not_raise_and_bad_schemes_are_refused():
    bad = _Srv(status=403)
    try:
        r = ex.push_misp(bad.url, "k", ex.build_misp_event("x", INDS))
        assert r == {"ok": False, "status": 403, "body": '{"done":true}'}
    finally:
        bad.close()
    assert ex.push_splunk_hec("http://127.0.0.1:1", "t", b"{}")["ok"] is False          # connection refused
    with pytest.raises(ValueError):
        ex.push_taxii("file:///etc/passwd", ex.build_bundle(INDS))
