import os
import sys
from pathlib import Path

os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

SRC_DIR = Path(__file__).resolve().parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from netguard.app import main
except ImportError as exc:
    print(f"无法加载 NetGuard 主程序：{exc}", file=sys.stderr)
    print("请确认从仓库根目录运行，且 src/netguard 包目录完整。", file=sys.stderr)
    raise SystemExit(1) from exc

if __name__ == "__main__":
    main()
