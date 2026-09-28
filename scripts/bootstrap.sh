#!/usr/bin/env bash
# One-time developer setup: backend venv (Python 3.12) with dev extras, frontend node_modules.
# Works in Git Bash on Windows (py -3.12, .venv/Scripts) and on Linux/macOS (python3.12, .venv/bin).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/backend"

if [[ ! -d .venv ]]; then
  if command -v py >/dev/null 2>&1; then
    py -3.12 -m venv .venv
  else
    python3.12 -m venv .venv
  fi
fi
if [[ -x .venv/Scripts/python ]]; then PY=.venv/Scripts/python; else PY=.venv/bin/python; fi
"$PY" -m pip install --upgrade --quiet pip
"$PY" -m pip install --quiet -e ".[dev]"

cd "$ROOT/frontend"
npm ci --no-audit --no-fund

if [[ ! -f "$ROOT/.env" ]]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  echo "created .env from .env.example (dev placeholders)"
fi
echo "bootstrap done"
