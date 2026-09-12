from __future__ import annotations

import threading
from collections import Counter, deque
from dataclasses import dataclass

from netguard.clock import Clock, system_clock
from netguard.parser.packet import PacketInfo


@dataclass(frozen=True)
class TrafficSnapshot:
    total_packets: int
    total_bytes: int
    protocol_counts: dict[str, int]
    active_sessions: int
    packets_per_second: float
    bytes_per_second: float


class TrafficStats:
    def __init__(self, rate_window_seconds: float = 5.0, max_protocols: int = 64, clock: Clock = system_clock) -> None:
        self.rate_window_seconds = rate_window_seconds
        self.max_protocols = max_protocols
        self._clock = clock
        self._lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts: Counter[str] = Counter()
        self._recent: deque[tuple[float, int]] = deque()
        self.active_sessions = 0

    def update(self, packet: PacketInfo, active_sessions: int = 0) -> None:
        now = packet.timestamp if packet.timestamp is not None else self._clock()
        with self._lock:
            self.total_packets += 1
            self.total_bytes += packet.length
            self.protocol_counts[packet.protocol] += 1
            if len(self.protocol_counts) > self.max_protocols:
                self.protocol_counts = Counter(dict(self.protocol_counts.most_common(self.max_protocols)))
            self.active_sessions = active_sessions
            self._recent.append((now, packet.length))
            self._trim(now)

    def snapshot(self) -> TrafficSnapshot:
        now = self._clock()
        with self._lock:
            self._trim(now)
            if not self._recent:
                return TrafficSnapshot(
                    total_packets=self.total_packets,
                    total_bytes=self.total_bytes,
                    protocol_counts=dict(self.protocol_counts),
                    active_sessions=self.active_sessions,
                    packets_per_second=0.0,
                    bytes_per_second=0.0,
                )
            elapsed = self._recent[-1][0] - self._recent[0][0] if len(self._recent) > 1 else 1.0
            elapsed = max(elapsed, 1.0)
            recent_bytes = sum(size for _, size in self._recent)
            return TrafficSnapshot(
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                protocol_counts=dict(self.protocol_counts),
                active_sessions=self.active_sessions,
                packets_per_second=len(self._recent) / elapsed,
                bytes_per_second=recent_bytes / elapsed,
            )

    def _trim(self, now: float) -> None:
        cutoff = now - self.rate_window_seconds
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()
