#!/usr/bin/env bash
# Create a host-side dev custody signing key in the git-ignored var/ directory (never committed).
# Then set CUSTODY_SIGNING_KEY_PATH=../var/keys/custody-dev.pem in .env (paths are relative to backend/).
# The compose stack generates its own key in the `custodykeys` volume (keygen job).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd; })"  # C:/... in Git Bash, so it survives MSYS_NO_PATHCONV
cd "$ROOT/backend"
if [[ -x .venv/Scripts/python ]]; then PY=.venv/Scripts/python; else PY=.venv/bin/python; fi
"$PY" -m app.core.signing generate --out "$ROOT/var/keys/custody-dev.pem" --if-missing
