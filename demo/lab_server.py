#!/usr/bin/env python3
"""
ONYX Signal Lab server (stdlib only).

Serves the lab page and a tiny JSON API whose handlers call the SAME facade as the
REST router (onyx_api/services/analysis.py), hence the same engines.

    python3 demo/lab_server.py [--port 8765]

Binds to 127.0.0.1 only. No data is stored, no outbound request is made.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "demo" / "ONYX_Signal_Lab.html"
MAX_BODY = 64 * 1024

spec = importlib.util.spec_from_file_location("onyx_analysis", ROOT / "onyx-api/onyx_api/services/analysis.py")
analysis = importlib.util.module_from_spec(spec)
sys.modules["onyx_analysis"] = analysis
spec.loader.exec_module(analysis)


class Handler(BaseHTTPRequestHandler):
    server_version = "OnyxLab/1"

    def _send(self, code: int, payload, ctype="application/json; charset=utf-8"):
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if u.path in ("/", "/index.html"):
                if not PAGE.exists():
                    subprocess.run([sys.executable, str(ROOT / "demo/build_demo.py")], check=True)
                return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            if u.path == "/api/meta":
                return self._send(200, analysis.meta())
            if u.path == "/api/matrix":
                return self._send(200, analysis.matrix(analysis.load_actors(), q.get("level", "technique")))
            return self._send(404, {"error": "not found"})
        except analysis.ValidationError as e:
            return self._send(422, {"error": str(e)})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n > MAX_BODY:
                return self._send(413, {"error": "body too large"})
            body = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(body, dict):
                return self._send(422, {"error": "JSON object expected"})
            route = {"/api/assess": analysis.assess, "/api/curve": analysis.curve}.get(urlparse(self.path).path)
            if route is None:
                return self._send(404, {"error": "not found"})
            return self._send(200, route(body))
        except (analysis.ValidationError, json.JSONDecodeError) as e:
            return self._send(422, {"error": str(e)})

    def log_message(self, fmt, *args):  # quiet
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print(f"ONYX Signal Lab: http://127.0.0.1:{a.port}/   (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
