"""End-to-end test of the Signal Lab server: real HTTP, real engines."""
import importlib.util
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

_p = Path(__file__).resolve().parents[2] / "demo" / "lab_server.py"
_s = importlib.util.spec_from_file_location("lab_server", _p)
L = importlib.util.module_from_spec(_s)
_s.loader.exec_module(L)


@pytest.fixture(scope="module")
def base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), L.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def call(url, body=None):
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_meta_and_assess_roundtrip(base):
    assert call(base + "/api/meta")[1]["convergence_threshold"] == 0.65
    code, r = call(base + "/api/assess", {"ioc_type": "ipv4", "host_type": "tor_exit", "hours_since_seen": 48, "source": "circl_misp"})
    assert code == 200 and r["decay"] == pytest.approx(0.5, abs=1e-4)


def test_bad_input_is_422_not_500(base):
    assert call(base + "/api/assess", {"ioc_type": "nope"})[0] == 422
    assert call(base + "/api/curve", {"ioc_type": "ipv4", "points": 10**6})[0] == 422


def test_unknown_route_and_matrix(base):
    assert call(base + "/api/nothing")[0] == 404
    code, m = call(base + "/api/matrix?level=parent")
    assert code == 200 and len(m["actors"]) == 12
    assert call(base + "/api/matrix?level=bogus")[0] == 422


def test_body_size_limit(base):
    req = urllib.request.Request(base + "/api/assess", data=b"{" + b" " * 70000 + b"}", headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 413
