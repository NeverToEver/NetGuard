from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Callable

from netguard.capture.pcap import RawPacket
from netguard.clock import Clock, system_clock
from netguard.detection import Detector, build_default_detectors
from netguard.parser.packet import PacketInfo, parse_packet
from netguard.rules.engine import Alert, RuleEngine
from netguard.session.tracker import SessionTracker
from netguard.statistics.traffic_stats import TrafficSnapshot, TrafficStats

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PacketEvent:
    packet: PacketInfo
    alerts: tuple[Alert, ...]


class PacketProcessor:
    """单包处理流水线：解析 → 会话重组 → 统计 → 规则/检测匹配。

    不持有线程或队列，可独立实例化并同步调用 ``process()``，便于测试与离线回放。
    仅由单一解析线程调用，因此除跨线程读取的计数器外无需额外加锁。
    """

    def __init__(
        self,
        clock: Clock = system_clock,
        detector_factory: Callable[[Clock], list[Detector]] | None = build_default_detectors,
    ) -> None:
        self.rules = RuleEngine(clock=clock)
        self.sessions = SessionTracker(clock=clock)
        self.stats = TrafficStats(clock=clock)
        self._clock = clock
        self.detectors: list[Detector] = detector_factory(clock) if detector_factory else []
        self._parse_errors = 0
        self._parse_error_lock = threading.Lock()

    @property
    def parse_errors(self) -> int:
        with self._parse_error_lock:
            return self._parse_errors

    @property
    def rule_count(self) -> int:
        return len(self.rules.rules)

    def load_rules(self, rule_text: str) -> int:
        rules = [line.strip() for line in rule_text.splitlines()]
        return self.rules.load(rules)

    def reset(self) -> None:
        self.stats = TrafficStats(clock=self._clock)
        self.sessions = SessionTracker(clock=self._clock)
        with self._parse_error_lock:
            self._parse_errors = 0
        for detector in self.detectors:
            detector.reset()

    def snapshot(self) -> TrafficSnapshot:
        return self.stats.snapshot()

    def process(self, raw: RawPacket) -> PacketEvent | None:
        """解码单个原始包并生成事件；解析失败时计入错误并返回 None。"""
        try:
            packet = parse_packet(raw.data, raw.timestamp, raw.original_length)
        except Exception:
            logger.exception("数据包解析异常")
            with self._parse_error_lock:
                self._parse_errors += 1
            return None
        session = self.sessions.update(packet)
        self.stats.update(packet, len(self.sessions.sessions))
        stream = session.stream if session else None
        matched = session.matched_rules if session else None
        alerts = list(self.rules.match(packet, stream=stream, matched=matched))
        alerts.extend(self._run_detectors(packet))
        event = PacketEvent(packet, tuple(alerts))
        if session and session.closed:
            self.sessions.cleanup(self._clock())
        return event

    def _run_detectors(self, packet: PacketInfo) -> list[Alert]:
        alerts: list[Alert] = []
        for detector in self.detectors:
            try:
                alerts.extend(detector.observe(packet))
            except Exception:
                logger.exception("检测器 %s 异常", type(detector).__name__)
        return alerts
