#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec /usr/bin/arch -x86_64 /usr/bin/python3 "$SCRIPT_DIR/score_request.py"
