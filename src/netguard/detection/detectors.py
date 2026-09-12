from __future__ import annotations

from collections import Counter, defaultdict, deque

from netguard.clock import Clock
from netguard.detection.base import BaseDetector
from netguard.parser.packet import PacketInfo
from netguard.rules.engine import Alert

_MAX_TRACKED_KEYS = 4096
#: 每个键在窗口内保留的最大样本数，防止高流量下窗口无界增长（内存与 O(n²) 风险）。
_MAX_SAMPLES_PER_KEY = 4096


def _evict_oldest(events: dict, max_keys: int, *linked: dict) -> None:
    """键数超上限时批量逐出最旧的 10%，避免每包 O(n) 的逐键 min 扫描。

    ``linked`` 里的字典（如 _alerted / _port_counts）与 events 按键同步删除。
    """
    overflow = len(events) - max_keys
    if overflow <= 0:
        return
    evict_count = max(overflow, max_keys // 10)
    oldest = sorted(events, key=lambda k: events[k][-1] if events[k] else 0.0)[:evict_count]
    for key in oldest:
        events.pop(key, None)
        for other in linked:
            other.pop(key, None)


def _is_tcp_syn(packet: PacketInfo) -> bool:
    if packet.protocol not in {"TCP", "HTTP"}:
        return False
    flags = set(packet.tcp.get("flags", []) or [])
    return "SYN" in flags and "ACK" not in flags


def _validate_threshold(threshold: int, max_samples: int) -> None:
    """窗口硬截断发生在阈值判断之前，阈值超过窗口容量会导致检测器永久失聪。"""
    if threshold > max_samples:
        raise ValueError(
            f"threshold ({threshold}) 不能大于 max_samples ({max_samples})："
            "窗口截断后样本数永远达不到阈值，检测器将无法告警"
        )


def _suffix(name: str) -> str:
    """取域名后缀用于聚合查询频率。

    4 级及以上标签保留末三级（``host1.tunnel.example.com`` 归入
    ``tunnel.example.com``）；恰为 3 级时取末两级——``<数据>.example.com``
    把数据编码在二级子域，是隧道最常见形态，按全名聚合永远凑不满频率阈值。
    """
    labels = name.split(".")
    if len(labels) < 3:
        return name
    if len(labels) == 3:
        return ".".join(labels[-2:])
    return ".".join(labels[-3:])


class SynFloodDetector(BaseDetector):
    """窗口内同一 (目的IP, 目的端口) 的 SYN 数量超阈值即告警。"""

    name = "syn-flood"
    severity = "high"

    def __init__(
        self,
        clock: Clock,
        *,
        window_seconds: float = 5.0,
        threshold: int = 100,
        max_keys: int = _MAX_TRACKED_KEYS,
        max_samples: int = _MAX_SAMPLES_PER_KEY,
    ) -> None:
        super().__init__(clock)
        self.window_seconds = window_seconds
        self.threshold = threshold
        _validate_threshold(threshold, max_samples)
        self.max_keys = max_keys
        self.max_samples = max_samples
        self._events: dict[tuple[str, int | None], deque[float]] = defaultdict(deque)
        self._alerted: dict[tuple[str, int | None], float] = {}

    def observe(self, packet: PacketInfo) -> list[Alert]:
        if not _is_tcp_syn(packet):
            return []
        now = self._now(packet)
        key = (packet.dst, packet.dst_port)
        window = self._events[key]
        window.append(now)
        self._trim(window, now)
        self._evict_if_needed()
        if len(window) < self.threshold:
            return []
        # 同一 (目的IP, 端口) 在一个窗口内只告警一次，避免告警风暴
        last = self._alerted.get(key)
        if last is not None and now - last < self.window_seconds:
            return []
        self._alerted[key] = now
        return [
            self._alert(
                packet,
                f"疑似 SYN Flood：{self.window_seconds:.0f}s 内 {len(window)} 个 SYN 发往 "
                f"{packet.dst}:{packet.dst_port}",
            )
        ]

    def _trim(self, window: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        while len(window) > self.max_samples:
            window.popleft()

    def _evict_if_needed(self) -> None:
        _evict_oldest(self._events, self.max_keys, self._alerted)

    def reset(self) -> None:
        self._events.clear()
        self._alerted.clear()


class PortScanDetector(BaseDetector):
    """窗口内同一源 IP 访问的不同目的端口数超阈值即告警。

    使用「计数窗口 + 端口计数表」实现 O(1) 摊销的 distinct 统计，避免每包
    重新扫描整个窗口（高流量下会退化为 O(n²)）。
    """

    name = "port-scan"
    severity = "high"

    def __init__(
        self,
        clock: Clock,
        *,
        window_seconds: float = 10.0,
        threshold: int = 20,
        max_keys: int = _MAX_TRACKED_KEYS,
        max_samples: int = _MAX_SAMPLES_PER_KEY,
    ) -> None:
        super().__init__(clock)
        self.window_seconds = window_seconds
        self.threshold = threshold
        _validate_threshold(threshold, max_samples)
        self.max_keys = max_keys
        self.max_samples = max_samples
        self._ports: dict[str, deque[tuple[float, int | None]]] = defaultdict(deque)
        self._port_counts: dict[str, Counter[int | None]] = defaultdict(Counter)
        self._alerted: dict[str, float] = {}

    def observe(self, packet: PacketInfo) -> list[Alert]:
        if packet.protocol not in {"TCP", "HTTP", "UDP", "DNS"} or packet.dst_port is None:
            return []
        now = self._now(packet)
        key = packet.src
        window = self._ports[key]
        counts = self._port_counts[key]
        window.append((now, packet.dst_port))
        counts[packet.dst_port] += 1
        cutoff = now - self.window_seconds
        while window and window[0][0] < cutoff:
            _, old_port = window.popleft()
            counts[old_port] -= 1
            if counts[old_port] <= 0:
                del counts[old_port]
        while len(window) > self.max_samples:
            _, old_port = window.popleft()
            counts[old_port] -= 1
            if counts[old_port] <= 0:
                del counts[old_port]
        self._evict_if_needed()
        distinct = len(counts)
        if distinct < self.threshold:
            return []
        last = self._alerted.get(key)
        if last is not None and now - last < self.window_seconds:
            return []
        self._alerted[key] = now
        return [
            self._alert(
                packet,
                f"疑似端口扫描：{packet.src} 在 {self.window_seconds:.0f}s 内访问 {distinct} 个端口",
            )
        ]

    def _evict_if_needed(self) -> None:
        _evict_oldest(self._ports, self.max_keys, self._port_counts, self._alerted)

    def reset(self) -> None:
        self._ports.clear()
        self._port_counts.clear()
        self._alerted.clear()


class IcmpFloodDetector(BaseDetector):
    """窗口内同一 (源IP, 目的IP) 的 ICMP 包数量超阈值即告警。"""

    name = "icmp-flood"
    severity = "high"

    def __init__(
        self,
        clock: Clock,
        *,
        window_seconds: float = 5.0,
        threshold: int = 100,
        max_keys: int = _MAX_TRACKED_KEYS,
        max_samples: int = _MAX_SAMPLES_PER_KEY,
    ) -> None:
        super().__init__(clock)
        self.window_seconds = window_seconds
        self.threshold = threshold
        _validate_threshold(threshold, max_samples)
        self.max_keys = max_keys
        self.max_samples = max_samples
        self._events: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._alerted: dict[tuple[str, str], float] = {}

    def observe(self, packet: PacketInfo) -> list[Alert]:
        if packet.protocol != "ICMP":
            return []
        now = self._now(packet)
        key = (packet.src, packet.dst)
        window = self._events[key]
        window.append(now)
        self._trim(window, now)
        self._evict_if_needed()
        if len(window) < self.threshold:
            return []
        last = self._alerted.get(key)
        if last is not None and now - last < self.window_seconds:
            return []
        self._alerted[key] = now
        return [
            self._alert(
                packet,
                f"疑似 ICMP Flood：{self.window_seconds:.0f}s 内 {len(window)} 个 ICMP 包 "
                f"从 {packet.src} 发往 {packet.dst}",
            )
        ]

    def _trim(self, window: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        while len(window) > self.max_samples:
            window.popleft()

    def _evict_if_needed(self) -> None:
        _evict_oldest(self._events, self.max_keys, self._alerted)

    def reset(self) -> None:
        self._events.clear()
        self._alerted.clear()


class BruteForceDetector(BaseDetector):
    """检测 SSH/FTP/Telnet 等明文服务的暴力破解：窗口内同一源对同一服务的高频连接。

    用 SYN（不含 ACK）计数近似连接尝试次数；同一 (源IP, 目的IP, 服务端口)
    在窗口内超过阈值即告警。
    """

    name = "brute-force"
    severity = "high"

    #: 常见明文认证服务端口
    DEFAULT_SERVICE_PORTS = (21, 22, 23, 110, 143, 3306, 3389, 5900)

    def __init__(
        self,
        clock: Clock,
        *,
        window_seconds: float = 60.0,
        threshold: int = 10,
        service_ports: tuple[int, ...] = DEFAULT_SERVICE_PORTS,
        max_keys: int = _MAX_TRACKED_KEYS,
        max_samples: int = _MAX_SAMPLES_PER_KEY,
    ) -> None:
        super().__init__(clock)
        self.window_seconds = window_seconds
        self.threshold = threshold
        _validate_threshold(threshold, max_samples)
        self.service_ports = frozenset(service_ports)
        self.max_keys = max_keys
        self.max_samples = max_samples
        self._events: dict[tuple[str, str, int], deque[float]] = defaultdict(deque)
        self._alerted: dict[tuple[str, str, int], float] = {}

    def observe(self, packet: PacketInfo) -> list[Alert]:
        if packet.dst_port not in self.service_ports:
            return []
        if not _is_tcp_syn(packet):
            return []
        now = self._now(packet)
        key = (packet.src, packet.dst, packet.dst_port)
        window = self._events[key]
        window.append(now)
        self._trim(window, now)
        self._evict_if_needed()
        if len(window) < self.threshold:
            return []
        last = self._alerted.get(key)
        if last is not None and now - last < self.window_seconds:
            return []
        self._alerted[key] = now
        return [
            self._alert(
                packet,
                f"疑似暴力破解：{self.window_seconds:.0f}s 内 {len(window)} 次连接 "
                f"{packet.dst}:{packet.dst_port}（源 {packet.src}）",
            )
        ]

    def _trim(self, window: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        while len(window) > self.max_samples:
            window.popleft()

    def _evict_if_needed(self) -> None:
        _evict_oldest(self._events, self.max_keys, self._alerted)

    def reset(self) -> None:
        self._events.clear()
        self._alerted.clear()


class DnsTunnelDetector(BaseDetector):
    """检测疑似 DNS 隧道：超长域名、超长标签或同一后缀高频查询。"""

    name = "dns-tunnel"
    severity = "medium"

    def __init__(
        self,
        clock: Clock,
        *,
        max_name_length: int = 52,
        max_label_length: int = 40,
        window_seconds: float = 10.0,
        rate_threshold: int = 50,
        max_keys: int = _MAX_TRACKED_KEYS,
        max_samples: int = _MAX_SAMPLES_PER_KEY,
    ) -> None:
        super().__init__(clock)
        self.max_name_length = max_name_length
        self.max_label_length = max_label_length
        self.window_seconds = window_seconds
        self.rate_threshold = rate_threshold
        _validate_threshold(rate_threshold, max_samples)
        self.max_keys = max_keys
        self.max_samples = max_samples
        self._suffix_events: dict[str, deque[float]] = defaultdict(deque)
        self._alerted: dict[str, float] = {}

    def observe(self, packet: PacketInfo) -> list[Alert]:
        if packet.protocol != "DNS":
            return []
        queries = packet.dns.get("queries", []) or []
        alerts: list[Alert] = []
        now = self._now(packet)
        for query in queries:
            name = str(query.get("name", "")).strip(".")
            if not name:
                continue
            longest = max((len(label) for label in name.split(".")), default=0)
            if len(name) > self.max_name_length or longest > self.max_label_length:
                # 超长域名按来源 IP 做时间窗抑制：隧道会持续发送超长查询，
                # 不抑制会对每个查询各告警一次，直接刷满事件表
                key = f"\x00long:{packet.src}"
                self._append_event(key, now)
                last = self._alerted.get(key)
                if last is not None and now - last < self.window_seconds:
                    continue
                self._alerted[key] = now
                alerts.append(
                    self._alert(
                        packet,
                        f"疑似 DNS 隧道：{packet.src} 查询超长域名 {name[:80]}"
                        f"（长度 {len(name)}，最长标签 {longest}）",
                    )
                )
                continue
            suffix = _suffix(name)
            self._append_event(suffix, now)
            window = self._suffix_events[suffix]
            if len(window) < self.rate_threshold:
                continue
            last = self._alerted.get(suffix)
            if last is not None and now - last < self.window_seconds:
                continue
            self._alerted[suffix] = now
            alerts.append(
                self._alert(
                    packet,
                    f"疑似 DNS 隧道：{self.window_seconds:.0f}s 内向 {suffix} 发起 {len(window)} 次查询",
                )
            )
        return alerts

    def _append_event(self, key: str, now: float) -> None:
        window = self._suffix_events[key]
        window.append(now)
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        while len(window) > self.max_samples:
            window.popleft()
        self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        _evict_oldest(self._suffix_events, self.max_keys, self._alerted)

    def reset(self) -> None:
        self._suffix_events.clear()
        self._alerted.clear()
