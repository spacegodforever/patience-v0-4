#!/bin/sh
# PATIENCE local installer for macOS and Linux.
# Delegates to tools/install.py (stdlib only) so the steps stay in one tested place.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
INSTALL_PY="$ROOT/tools/install.py"

if [ ! -f "$INSTALL_PY" ]; then
  echo "PATIENCE installer: $INSTALL_PY is missing. Run this script from a PATIENCE checkout." >&2
  exit 1
fi

if [ -n "${PYTHON:-}" ]; then
  PY=$PYTHON
elif command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "PATIENCE installer: Python 3 was not found on PATH." >&2
  echo "PATIENCE needs Python 3.10 or newer (the exact floor is read from pyproject.toml)." >&2
  echo "Install Python from https://www.python.org/downloads/ and re-run $0" >&2
  exit 1
fi

exec "$PY" "$INSTALL_PY" "$@"
