#!/bin/sh
set -eu

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PYTHON_BIN="$("$PROJECT_DIR/scripts/check_interpreter.sh")"

exec "$PYTHON_BIN" "$PROJECT_DIR/main.py" "$@"
