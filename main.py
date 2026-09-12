import os
import sys
from pathlib import Path

os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

SRC_DIR = Path(__file__).resolve().parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from netguard.app import main

if __name__ == "__main__":
    main()
