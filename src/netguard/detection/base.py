from __future__ import annotations

from typing import Protocol

from netguard.clock import Clock
from netguard.parser.packet import PacketInfo
from netguard.rules.engine import Alert


class Detector(Protocol):
    """基于流量统计的检测器接口。

    与规则引擎不同，检测器跨数据包维护时间窗口状态，用于发现单包无法判断的
    攻击行为（如 SYN flood、端口扫描、DNS 隧道）。``observe`` 每包调用一次，
    ``reset`` 在重新开始抓包时清空窗口状态。
    """

    name: str

    def observe(self, packet: PacketInfo) -> list[Alert]: ...

    def reset(self) -> None: ...


class BaseDetector:
    name = "detector"
    kind = "anomaly"
    severity = "medium"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def _now(self, packet: PacketInfo) -> float:
        return packet.timestamp if packet.timestamp is not None else self._clock()

    def _alert(self, packet: PacketInfo, msg: str, *, severity: str | None = None) -> Alert:
        return Alert(
            timestamp=self._now(packet),
            msg=msg,
            protocol=packet.protocol,
            src=packet.src,
            dst=packet.dst,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            summary=packet.summary,
            kind=self.kind,
            severity=severity or self.severity,
            rule_id=self.name,
        )

    def reset(self) -> None:  # pragma: no cover - 子类按需覆盖
        return None
