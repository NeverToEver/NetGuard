#!/bin/sh
# NetGuard 启动（Linux / macOS）。
# 薄封装：找到一个能运行 launch.py 的 Python 后原样转交，解释器选择与版本
# 校验都在 launch.py 内完成（避免与 NetGuard.sh / check_interpreter 重复）。
set -eu

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
LAUNCH="$PROJECT_DIR/scripts/launch.py"

PY=""
if [ -n "${NETGUARD_PYTHON:-}" ] && [ -x "${NETGUARD_PYTHON}" ]; then
    PY="$NETGUARD_PYTHON"
fi

if [ -z "$PY" ] && [ -x "$PROJECT_DIR/.venv/bin/python" ]; then
    PY="$PROJECT_DIR/.venv/bin/python"
fi

if [ -z "$PY" ]; then
    for name in python3 python; do
        candidate="$(command -v "$name" 2>/dev/null || true)"
        if [ -n "$candidate" ]; then
            PY="$candidate"
            break
        fi
    done
fi

if [ -z "$PY" ]; then
    echo "未找到任何 Python 解释器。请安装 Python 3.11+ 后重试。" >&2
    exit 1
fi

exec "$PY" "$LAUNCH" "$@"
