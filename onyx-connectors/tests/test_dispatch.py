"""Export dispatch: environment-only destinations, state filtering. Real HTTP goes to a local stand-in server."""
import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

base = Path(__file__).resolve().parents[1] / "onyx_connectors"
pkg = importlib.util.module_from_spec(importlib.util.spec_from_loader("onyx_connectors", loader=None))
pkg.__path__ = [str(base)]; sys.modules["onyx_connectors"] = pkg
for name in ("export", "dispatch"):
    sp = importlib.util.spec_from_file_location(f"onyx_connectors.{name}", base / f"{name}.py")
    m = importlib.util.module_from_spec(sp); sys.modules[f"onyx_connectors.{name}"] = m; sp.loader.exec_module(m)
dispatch = sys.modules["onyx_connectors.dispatch"]

IOCS = [{"type": "ipv4", "value": "198.51.100.9", "decay_state": "VALID"},
        {"type": "domain", "value": "old.example", "decay_state": "OBSOLETE"},
        {"type": "domain", "value": "new.example"}]


def test_no_destination_is_skipped():
    r = dispatch.dispatch(IOCS, {})
    assert r["status"] == "skipped" and r["indicators"] == 2


def test_partial_config_is_not_a_destination():
    assert dispatch.configured_destinations({"ONYX_EXPORT_MISP_URL": "http://x"}) == []


def test_pushes_only_active_indicators_to_configured_server():
    got = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200); self.end_headers(); self.wfile.write(b"{}")
        def log_message(self, *a): pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = dispatch.dispatch(IOCS, {"ONYX_EXPORT_TAXII_URL": f"http://127.0.0.1:{srv.server_port}/objects/"})
    finally:
        srv.shutdown()
    assert r["status"] == "ok" and r["indicators"] == 2
    assert {o["name"] for o in got[0]["objects"]} == {"ipv4: 198.51.100.9", "domain: new.example"}
