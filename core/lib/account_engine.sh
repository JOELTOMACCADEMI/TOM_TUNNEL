#!/bin/bash
# TOM_TUNNEL - Bash wrapper for the central Account Engine
# Usage: account_engine.sh <command> [args...]
# This file is sourced or called by menus.

ENGINE_PY="/usr/local/lib/tom_tunnel/account_engine.py"
# Fallback to relative path during development / before install
if [[ ! -f "$ENGINE_PY" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    ENGINE_PY="${SCRIPT_DIR}/account_engine.py"
fi

if [[ ! -f "$ENGINE_PY" ]]; then
    echo "ERROR: account_engine.py not found" >&2
    exit 1
fi

# Ensure python3 is available
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required" >&2
    exit 1
fi

exec python3 "$ENGINE_PY" "$@"
