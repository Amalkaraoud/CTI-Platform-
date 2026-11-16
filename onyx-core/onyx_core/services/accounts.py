"""
ONYX CTI - Bootstrap accounts.

Accounts come exclusively from environment variables (see security_policy.load_bootstrap_users).
Nothing is hard-coded. Built lazily so importing this module has no side effect.
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache

from passlib.context import CryptContext

from onyx_core.config import get_config
from onyx_core.security_policy import BootstrapUser, load_bootstrap_users

logger = logging.getLogger("onyx.accounts")
_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


@lru_cache(maxsize=1)
def get_bootstrap_accounts() -> dict[str, BootstrapUser]:
    users, generated = load_bootstrap_users(
        os.environ, environment=get_config().env, hash_password=_pwd.hash,
    )
    for name, pw in generated.items():
        # Development only: shown once, never persisted.
        logger.warning("DEV ONLY: generated password for '%s' = %s (set ONYX_BOOTSTRAP_%s_PASSWORD to fix it)",
                       name, pw, name.upper())
    if not users:
        logger.warning("No bootstrap account configured: login is disabled until "
                       "ONYX_BOOTSTRAP_ADMIN_PASSWORD(_HASH) is set.")
    return users
