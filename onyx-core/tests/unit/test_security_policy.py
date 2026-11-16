"""Tests for onyx_core.security_policy (stdlib only; loaded by path)."""
import importlib.util
import sys
from pathlib import Path

import pytest

_p = Path(__file__).resolve().parents[2] / "onyx_core" / "security_policy.py"
_spec = importlib.util.spec_from_file_location("security_policy", _p)
sp = importlib.util.module_from_spec(_spec)
sys.modules["security_policy"] = sp
_spec.loader.exec_module(sp)

STRONG = sp.generate_secret()
STRONG2 = sp.generate_secret()
fake_hash = lambda p: "$2b$12$" + "x" * 53   # stand-in for bcrypt


def audit(**kw):
    base = dict(env="production", debug=False, jwt_secret=STRONG, secret_key=STRONG2,
                cors_origins=["https://onyx.example"], service_passwords={"REDIS_PASSWORD": STRONG})
    base.update(kw)
    return sp.audit(**base)


# ---- secrets -------------------------------------------------------------
@pytest.mark.parametrize("v", ["", None, "change-me-to-another-64-char-random-hex-string",
                               "<generate-a-64-char-random-hex-string>", "onyx_redis_secret_2026",
                               "short", "a" * 64, "onyx_admin_2026!"])
def test_weak_values_detected(v):
    assert sp.is_weak_secret(v)


def test_generated_secret_is_accepted():
    assert not sp.is_weak_secret(sp.generate_secret())


# ---- audit / enforce -----------------------------------------------------
def test_clean_production_config_has_no_finding():
    assert audit() == []


def test_production_with_default_jwt_secret_aborts():
    f = audit(jwt_secret="change-me-to-another-64-char-random-hex-string")
    with pytest.raises(sp.InsecureConfiguration):
        sp.enforce(f, "production")


def test_development_only_warns():
    f = audit(env="development", jwt_secret="", secret_key="")
    assert f and all(x.severity == "WARNING" for x in f)
    sp.enforce(f, "development")   # must not raise


def test_production_debug_is_critical():
    assert any(x.key == "ONYX_DEBUG" and x.severity == "CRITICAL" for x in audit(debug=True))


def test_same_secret_for_jwt_and_secret_key_is_flagged():
    assert audit(jwt_secret=STRONG, secret_key=STRONG)


def test_default_service_password_flagged():
    assert any(x.key == "REDIS_PASSWORD" for x in audit(service_passwords={"REDIS_PASSWORD": "onyx_redis_secret_2026"}))


# ---- CORS ----------------------------------------------------------------
def test_wildcard_never_served():
    origins, creds = sp.resolve_cors(["*", "https://a.example"], "production")
    assert "*" not in origins and origins == ["https://a.example"] and creds


def test_production_has_no_implicit_localhost():
    assert sp.resolve_cors([], "production") == ([], False)


def test_development_adds_local_dashboard_and_allows_credentials():
    origins, creds = sp.resolve_cors(["*"], "development")
    assert "http://localhost:3000" in origins and creds


def test_trailing_slash_normalised():
    assert sp.resolve_cors(["https://a.example/"], "production")[0] == ["https://a.example"]


# ---- bootstrap accounts --------------------------------------------------
def test_no_account_in_production_without_configuration():
    users, gen = sp.load_bootstrap_users({}, environment="production", hash_password=fake_hash)
    assert users == {} and gen == {}


def test_development_generates_random_admin_once():
    u1, g1 = sp.load_bootstrap_users({}, environment="development", hash_password=fake_hash)
    u2, g2 = sp.load_bootstrap_users({}, environment="development", hash_password=fake_hash)
    assert set(u1) == {"admin"} and len(g1["admin"]) >= 16 and g1["admin"] != g2["admin"]


def test_configured_plain_password_is_hashed_and_roles_mapped():
    env = {"ONYX_BOOTSTRAP_ADMIN_PASSWORD": "a-long-enough-pass", "ONYX_BOOTSTRAP_ANALYST_PASSWORD": "another-long-pass"}
    users, gen = sp.load_bootstrap_users(env, environment="production", hash_password=lambda p: "H:" + p)
    assert users["admin"].password_hash == "H:a-long-enough-pass" and users["admin"].role == "admin"
    assert users["analyst"].role == "analyst" and gen == {}


@pytest.mark.parametrize("bad", ["short", "onyx_admin_2026!", "change-me-please-now"])
def test_weak_plain_password_rejected(bad):
    with pytest.raises(sp.InsecureConfiguration):
        sp.load_bootstrap_users({"ONYX_BOOTSTRAP_ADMIN_PASSWORD": bad}, environment="production", hash_password=fake_hash)


def test_hash_must_look_like_bcrypt():
    with pytest.raises(sp.InsecureConfiguration):
        sp.load_bootstrap_users({"ONYX_BOOTSTRAP_ADMIN_PASSWORD_HASH": "plaintext"}, environment="production", hash_password=fake_hash)


def test_repository_contains_no_known_default_credentials():
    """Regression guard: the old defaults must never come back."""
    root = Path(__file__).resolve().parents[3]
    banned = ["_secret_2026", "onyx_admin_2026!", "onyx_analyst_2026!"]
    scanned = [*root.glob("onyx-*/**/*.py"), *root.glob("scripts/*.py"), root / "docker-compose.yml",
               root / ".env.example", root / "Makefile"]
    offenders = [(str(p.relative_to(root)), b) for p in scanned if p.is_file() and "tests" not in p.parts
                 and "security_policy" not in p.name
                 for b in banned if b in p.read_text(encoding="utf-8", errors="ignore")]
    assert offenders == []
