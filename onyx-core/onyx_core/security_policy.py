"""
ONYX CTI - Security policy (stdlib only, no I/O).

One place that answers four questions, so the rules can be unit-tested without
FastAPI, pydantic or a database:

  1. Is a secret/password usable, or is it a placeholder / default / too weak?
  2. Is the overall configuration acceptable for the declared environment?
  3. Which CORS origins may be served, and may credentials be allowed?
  4. Which bootstrap accounts exist? (There are no hard-coded accounts.)

Policy
  * production: any CRITICAL finding aborts start-up (InsecureConfiguration).
  * development: findings are logged, nothing aborts, but wildcard CORS with
    credentials is still impossible.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping

MIN_SECRET_LENGTH = 32

# Substrings that mark a value as a template/default shipped in the repository.
PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "change-me", "changeme", "<generate", "your-", "_secret_2026", "_2026!",
    "password", "secret_key_here", "example",
)

DEV_ENVS = {"development", "dev", "local", "test"}
LOCAL_DEV_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"]


class InsecureConfiguration(RuntimeError):
    """Raised at start-up when production is configured with unsafe values."""


@dataclass(frozen=True)
class Finding:
    severity: str            # "CRITICAL" | "WARNING"
    key: str
    message: str


def is_placeholder(value: str | None) -> bool:
    v = (value or "").strip().lower()
    return not v or any(m in v for m in PLACEHOLDER_MARKERS)


def is_weak_secret(value: str | None, min_length: int = MIN_SECRET_LENGTH) -> bool:
    """True when the value is empty, a known placeholder, short, or has trivial variety."""
    v = (value or "").strip()
    return is_placeholder(v) or len(v) < min_length or len(set(v)) < 8


def generate_secret(nbytes: int = 32) -> str:
    return secrets.token_hex(nbytes)


def is_production(env: str | None) -> bool:
    return (env or "development").strip().lower() not in DEV_ENVS


def audit(
    *,
    env: str,
    debug: bool,
    jwt_secret: str,
    secret_key: str,
    cors_origins: Iterable[str],
    service_passwords: Mapping[str, str] | None = None,
) -> list[Finding]:
    """Evaluate a configuration. Pure function: returns findings, raises nothing."""
    out: list[Finding] = []
    prod = is_production(env)
    sev = "CRITICAL" if prod else "WARNING"

    for key, val in (("ONYX_JWT_SECRET", jwt_secret), ("ONYX_SECRET_KEY", secret_key)):
        if is_weak_secret(val):
            out.append(Finding(sev, key, f"{key} is a placeholder, default or shorter than "
                                         f"{MIN_SECRET_LENGTH} characters. Run: python scripts/gen_env.py"))
    if jwt_secret and jwt_secret == secret_key:
        out.append(Finding(sev, "ONYX_JWT_SECRET", "JWT secret must differ from ONYX_SECRET_KEY."))

    for name, pw in (service_passwords or {}).items():
        if is_placeholder(pw):
            out.append(Finding(sev, name, f"{name} is empty or a repository default."))

    origins = list(cors_origins)
    if "*" in origins:
        out.append(Finding(sev, "ONYX_API_CORS_ORIGINS",
                           "Wildcard CORS origin configured; it is ignored (explicit origins only)."))
    if prod and debug:
        out.append(Finding("CRITICAL", "ONYX_DEBUG", "Debug mode must be off in production."))
    return out


def enforce(findings: Iterable[Finding], env: str) -> None:
    """Abort start-up in production when a CRITICAL finding exists."""
    critical = [f for f in findings if f.severity == "CRITICAL"]
    if critical and is_production(env):
        lines = "\n".join(f"  - {f.key}: {f.message}" for f in critical)
        raise InsecureConfiguration(f"Refusing to start in '{env}' with insecure configuration:\n{lines}")


def resolve_cors(origins: Iterable[str] | None, env: str) -> tuple[list[str], bool]:
    """
    Return (allowed_origins, allow_credentials).

    Wildcards are always dropped. In development the local dashboard origins are
    added so the default setup works; in production only configured origins remain.
    Credentials are allowed only when an explicit origin list exists.
    """
    explicit = [o.strip().rstrip("/") for o in (origins or []) if o and o.strip() != "*"]
    if not is_production(env):
        for o in LOCAL_DEV_ORIGINS:
            if o not in explicit:
                explicit.append(o)
    return explicit, bool(explicit)


# --------------------------------------------------------------------------
# Bootstrap accounts
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class BootstrapUser:
    id: str
    username: str
    role: str                  # role name; the caller maps it to its Role enum
    password_hash: str
    email: str


def load_bootstrap_users(
    env: Mapping[str, str],
    *,
    environment: str,
    hash_password: Callable[[str], str],
) -> tuple[dict[str, BootstrapUser], dict[str, str]]:
    """
    Build the bootstrap accounts from environment variables only.

      ONYX_BOOTSTRAP_ADMIN_PASSWORD_HASH     bcrypt hash (preferred)
      ONYX_BOOTSTRAP_ADMIN_PASSWORD          plain value, hashed in memory
      ONYX_BOOTSTRAP_ANALYST_PASSWORD_HASH / ONYX_BOOTSTRAP_ANALYST_PASSWORD

    Returns (users, generated_credentials).
      * Configured accounts are returned as-is; a configured value that is a
        placeholder or shorter than 12 characters (plain form) is rejected.
      * If no admin is configured: in development a random admin password is
        generated and returned in `generated_credentials` (to be logged once);
        in production no account exists and login is impossible until configured.
    """
    users: dict[str, BootstrapUser] = {}
    generated: dict[str, str] = {}

    for username, role in (("admin", "admin"), ("analyst", "analyst")):
        prefix = f"ONYX_BOOTSTRAP_{username.upper()}_PASSWORD"
        pw_hash = (env.get(prefix + "_HASH") or "").strip()
        plain = (env.get(prefix) or "").strip()
        if pw_hash:
            if not pw_hash.startswith("$2"):
                raise InsecureConfiguration(f"{prefix}_HASH is not a bcrypt hash.")
        elif plain:
            if is_placeholder(plain) or len(plain) < 12:
                raise InsecureConfiguration(f"{prefix} is a placeholder or shorter than 12 characters.")
            pw_hash = hash_password(plain)
        elif username == "admin" and not is_production(environment):
            plain = secrets.token_urlsafe(16)
            generated[username] = plain
            pw_hash = hash_password(plain)
        else:
            continue
        users[username] = BootstrapUser(
            id=f"user-{username}-001", username=username, role=role,
            password_hash=pw_hash, email=f"{username}@onyx.local",
        )
    return users, generated
