#!/usr/bin/env python3
"""
Create .env from .env.example with freshly generated secrets (stdlib only).

  python3 scripts/gen_env.py            # create .env if absent
  python3 scripts/gen_env.py --force    # overwrite

Placeholders of the form <generate-...> and the *_PASSWORD / *_SECRET fields that
still carry a repository default are replaced by random values. API keys are left
empty: they come from the providers.
"""
import re
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC, DST = ROOT / ".env.example", ROOT / ".env"
SECRET_KEYS = re.compile(r"^(ONYX_SECRET_KEY|ONYX_JWT_SECRET|[A-Z0-9_]*PASSWORD)=(.*)$")


def main() -> int:
    if DST.exists() and "--force" not in sys.argv:
        print(".env already exists; use --force to regenerate (existing secrets would change).")
        return 0
    out = []
    for line in SRC.read_text(encoding="utf-8").splitlines():
        m = SECRET_KEYS.match(line)
        if m and not m.group(1).startswith("ONYX_BOOTSTRAP"):
            line = f"{m.group(1)}={secrets.token_hex(32)}"
        out.append(line)
    DST.write_text("\n".join(out) + "\n", encoding="utf-8")
    DST.chmod(0o600)
    print(f"wrote {DST.name} with generated secrets (mode 600). Bootstrap admin: see README, section Securite.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
