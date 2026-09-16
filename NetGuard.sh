#!/bin/sh
# NetGuard 一键启动（Linux / macOS）。
# 本脚本只负责找到一个能运行 scripts/launch.py 的 Python，然后原样转交参数。
# 解释器优先级、Python 版本下限、.venv 重入、环境自检全部由 launch.py 负责
# （见 scripts/launch.py 的 select_interpreter / python_supported），
# 避免在多份脚本里各写一遍版本判断。
#
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

# 依次尝试：NETGUARD_PYTHON → 仓库内 .venv → PATH 上的 python3 / python。
# 不做版本判断：交给 launch.py，它会在版本过低时给出明确提示。
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
    echo "未找到任何 Python 解释器。" >&2
    echo "请安装 Python 3.11+ 后重试，或在项目根目录执行：" >&2
    echo "    python3 -m venv .venv" >&2
    echo "    ./.venv/bin/python -m pip install -e ." >&2
    exit 1
fi

exec "$PY" "$LAUNCH" "$@"
