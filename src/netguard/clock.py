from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def __call__(self) -> float: ...


def system_clock() -> float:
    return time.time()
