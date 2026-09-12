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
    #: 速率窗口内的样本条数上限：高速率下窗口只按时间裁剪会驻留数十万元组，
    #: 且 snapshot 在锁内做 O(n) 全窗口求和。有界化后速率按实际保留时间跨度
    #: 计算，仍是无偏估计；达到上限时丢弃最旧样本（与检测器 max_samples 同思路）。
    MAX_SAMPLES = 65_536

    def __init__(self, rate_window_seconds: float = 5.0, max_protocols: int = 64, clock: Clock = system_clock) -> None:
        self.rate_window_seconds = rate_window_seconds
        self.max_protocols = max_protocols
        self._clock = clock
        self._lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts: Counter[str] = Counter()
        self._recent: deque[tuple[float, int]] = deque()
        self._recent_bytes = 0
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
            self._recent_bytes += packet.length
            self._trim(now)
            recent = self._recent
            while len(recent) > self.MAX_SAMPLES:
                _, size = recent.popleft()
                self._recent_bytes -= size

    def snapshot(self) -> TrafficSnapshot:
        with self._lock:
            if not self._recent:
                return TrafficSnapshot(
                    total_packets=self.total_packets,
                    total_bytes=self.total_bytes,
                    protocol_counts=dict(self.protocol_counts),
                    active_sessions=self.active_sessions,
                    packets_per_second=0.0,
                    bytes_per_second=0.0,
                )
            # trim 基准必须与窗口数据同一时间轴：_recent 里是包时间戳。
            # 包时间戳落后于墙钟超过一个窗口宽度（典型：离线回放历史 pcap，
            # 或刚从挂起恢复）时，墙钟基准会把窗口整体清空且永远追不上——
            # 此时回退到包时间轴计算速率；正常实时抓包下用墙钟，保证空闲归零。
            clock_now = self._clock()
            latest = self._recent[-1][0]
            window_base = latest if clock_now - latest > self.rate_window_seconds else clock_now
            self._trim(window_base)
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
            # 字节数增量维护，不再锁内 O(n) 全窗口求和
            recent_bytes = self._recent_bytes
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
        recent = self._recent
        while recent and recent[0][0] < cutoff:
            _, size = recent.popleft()
            self._recent_bytes -= size
