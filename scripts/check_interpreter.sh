#!/bin/sh
set -u

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DEFAULT_PYTHON="$PROJECT_DIR/.venv/bin/python"
PROJECT_ENV_NAME="netguard"
MIN_PYTHON_VERSION="3.11"

resolve_python() {
  candidate="$1"

  if [ -x "$candidate" ]; then
    candidate_dir="$(CDPATH= cd -- "$(dirname -- "$candidate")" && pwd)"
    printf '%s/%s\n' "$candidate_dir" "$(basename -- "$candidate")"
    return 0
  fi

  return 1
}

python_version_ok() {
  "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1
}

python_version() {
  "$1" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' 2>/dev/null || printf unknown
}

try_candidate() {
  candidate="$(resolve_python "$1" 2>/dev/null || true)"

  if [ -n "$candidate" ] && python_version_ok "$candidate"; then
    printf '%s\n' "$candidate"
    return 0
  fi

  return 1
}

detect_python() {
  command_path=""

  if [ -n "${NETGUARD_PYTHON:-}" ]; then
    candidate="$(resolve_python "$NETGUARD_PYTHON" 2>/dev/null || true)"
    if [ -z "$candidate" ]; then
      cat >&2 <<EOF
NETGUARD_PYTHON 指定的解释器不可执行：
  $NETGUARD_PYTHON
EOF
      return 2
    fi

    if ! python_version_ok "$candidate"; then
      cat >&2 <<EOF
NETGUARD_PYTHON 指定的解释器版本不符合项目要求：
  $candidate
  Python $(python_version "$candidate")

项目要求 Python $MIN_PYTHON_VERSION 或更高版本。
EOF
      return 2
    fi

    printf '%s\n' "$candidate"
    return 0
  fi

  for candidate in \
    "$DEFAULT_PYTHON" \
    "/opt/homebrew/bin/python3.12" \
    "/opt/homebrew/bin/python3.11" \
    "/opt/homebrew/opt/python@3.12/bin/python3.12" \
    "/opt/homebrew/opt/python@3.11/bin/python3.11" \
    "/opt/homebrew/bin/python3" \
    "/usr/local/bin/python3.12" \
    "/usr/local/bin/python3.11" \
    "/usr/local/bin/python3" \
    "/usr/bin/python3"; do
    if try_candidate "$candidate"; then
      return 0
    fi
  done

  for command_name in python3 python; do
    command_path="$(command -v "$command_name" 2>/dev/null || true)"
    if [ -n "$command_path" ] && try_candidate "$command_path"; then
      return 0
    fi
  done

  return 1
}

PYTHON_BIN="$(detect_python)"
DETECT_STATUS=$?

if [ "$DETECT_STATUS" -eq 2 ]; then
  exit 1
fi

if [ -z "$PYTHON_BIN" ]; then
  cat >&2 <<EOF
未找到可用的 Python $MIN_PYTHON_VERSION+ 解释器。

已自动检查：
  $DEFAULT_PYTHON
  常见 Homebrew、系统 python3/python 路径

请先在项目根目录创建相对路径 Python 环境：
  /opt/homebrew/bin/python3.12 -m venv .venv
  ./.venv/bin/python -m pip install --upgrade pip
  ./.venv/bin/python -m pip install -e .

如果你已经有其他解释器，可临时指定：
  NETGUARD_PYTHON=/path/to/python scripts/run_netguard.sh
EOF
  exit 1
fi

printf '%s\n' "$PYTHON_BIN"
