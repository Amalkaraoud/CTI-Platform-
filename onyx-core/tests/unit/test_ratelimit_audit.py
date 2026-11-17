"""Rate limiter, audit trail and the ASGI middleware that uses them. Standard library + pytest only."""
import asyncio
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


rl = _load("onyx_core.ratelimit", "onyx-core/onyx_core/ratelimit.py")
au = _load("onyx_core.audit", "onyx-core/onyx_core/audit.py")
# the middleware imports onyx_core.audit / onyx_core.ratelimit: provide the package stubs it needs
import types
pkg = types.ModuleType("onyx_core"); pkg.__path__ = []
sys.modules.setdefault("onyx_core", pkg)
sys.modules["onyx_core.audit"] = au
sys.modules["onyx_core.ratelimit"] = rl
mw = _load("onyx_api_middleware", "onyx-api/onyx_api/middleware.py")


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


def test_budget_parse():
    d = rl.Budget(1, 1)
    assert rl.Budget.parse("120/60", d) == rl.Budget(120, 60.0)
    assert rl.Budget.parse("garbage", d) == d and rl.Budget.parse("0/10", d) == d and rl.Budget.parse("5/-1", d) == d


def test_sliding_window_blocks_then_recovers():
    c = Clock(); lim = rl.SlidingWindowLimiter(clock=c); b = rl.Budget(3, 10)
    assert [lim.check("k", b)[0] for _ in range(3)] == [True] * 3
    ok, retry = lim.check("k", b)
    assert not ok and 0 < retry <= 10
    assert lim.check("other", b)[0]                    # keys are independent
    c.t = 10.1
    assert lim.check("k", b)[0]                        # the window slid


def test_limiter_memory_is_bounded():
    c = Clock(); lim = rl.SlidingWindowLimiter(clock=c, max_keys=100); b = rl.Budget(1, 1)
    for i in range(500):
        c.t += 2; lim.check(f"ip{i}", b)
    assert len(lim._hits) <= 101


def test_audit_scrubs_secrets_and_never_raises(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("ONYX_AUDIT_LOG", str(path))
    ev = au.audit("auth.login", "failure", actor="alice", client_ip="1.2.3.4",
                  details={"password": "hunter2", "nested": {"api_key": "k", "ok": 1}, "Authorization": "Bearer x"})
    line = json.loads(path.read_text().strip())
    assert line["details"]["password"] == "[redacted]" and line["details"]["Authorization"] == "[redacted]"
    assert line["details"]["nested"] == {"api_key": "[redacted]", "ok": 1}
    assert "hunter2" not in path.read_text() and ev["outcome"] == "failure"
    monkeypatch.setenv("ONYX_AUDIT_LOG", str(tmp_path / "missing_dir" / "x.log"))
    au.audit("x", "success")                           # unwritable sink must not raise


async def _call(app, path="/api/v1/iocs", method="GET", ip="9.9.9.9"):
    sent = []
    async def receive(): return {"type": "http.request", "body": b""}
    async def send(m): sent.append(m)
    await app({"type": "http", "path": path, "method": method, "client": (ip, 1)}, receive, send)
    return sent


async def _ok_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"{}"})


def test_middleware_throttles_login_but_not_other_ips(tmp_path, monkeypatch):
    monkeypatch.setenv("ONYX_AUDIT_LOG", str(tmp_path / "a.jsonl"))
    app = mw.RateLimitAuditMiddleware(_ok_app, env={"ONYX_AUTH_RATE_LIMIT": "2/60", "ONYX_RATE_LIMIT": "100/60"})
    codes = [asyncio.run(_call(app, "/api/v1/auth/login", "POST"))[0]["status"] for _ in range(3)]
    assert codes == [200, 200, 429]
    assert asyncio.run(_call(app, "/api/v1/auth/login", "POST", ip="8.8.8.8"))[0]["status"] == 200
    blocked = asyncio.run(_call(app, "/api/v1/auth/login", "POST"))
    assert dict(blocked[0]["headers"])[b"retry-after"]
    events = [json.loads(l) for l in (tmp_path / "a.jsonl").read_text().splitlines()]
    assert {"throttled", "success"} <= {e["outcome"] for e in events}


def test_middleware_passes_websocket_scopes_through():
    seen = []
    async def app(scope, receive, send): seen.append(scope["type"])
    m = mw.RateLimitAuditMiddleware(app)
    asyncio.run(m({"type": "websocket", "path": "/ws"}, None, None))
    assert seen == ["websocket"]
