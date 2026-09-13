#!/bin/sh
# NetGuard 一键启动（Linux / macOS）。
# 优先使用仓库内 .venv，其次 PATH 上的 python3；参数原样透传给 scripts/launch.py。
#   ./NetGuard.sh                 启动 GUI
#   ./NetGuard.sh --list-devices  列出网卡
#   ./NetGuard.sh --check         仅环境自检
#   ./NetGuard.sh --read x.pcap   离线回放
set -eu

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LAUNCH="$PROJECT_DIR/scripts/launch.py"

if [ ! -f "$LAUNCH" ]; then
    echo "未找到 $LAUNCH" >&2
    echo "请确认本脚本位于 NetGuard 仓库根目录。" >&2
    exit 1
fi

MIN_MAJOR=3
MIN_MINOR=11

version_ok() {
    "$1" -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= ($MIN_MAJOR, $MIN_MINOR) else 1)" >/dev/null 2>&1
}

PY=""

# 1) 仓库内虚拟环境
if [ -x "$PROJECT_DIR/.venv/bin/python" ] && version_ok "$PROJECT_DIR/.venv/bin/python"; then
    PY="$PROJECT_DIR/.venv/bin/python"
fi

# 2) PATH 上的 python3 / python
if [ -z "$PY" ]; then
    for name in python3 python; do
        candidate="$(command -v "$name" 2>/dev/null || true)"
        if [ -n "$candidate" ] && version_ok "$candidate"; then
            PY="$candidate"
            break
        fi
    done
fi

if [ -z "$PY" ]; then
    echo "未找到可用的 Python $MIN_MAJOR.$MIN_MINOR+ 解释器。" >&2
    echo "请安装 Python 后重试，或在项目根目录执行：" >&2
    echo "    python3 -m venv .venv" >&2
    echo "    ./.venv/bin/python -m pip install -e ." >&2
    exit 1
fi

exec "$PY" "$LAUNCH" "$@"
