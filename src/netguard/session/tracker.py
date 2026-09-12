from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

from netguard.clock import Clock, system_clock
from netguard.parser.packet import PacketInfo


@dataclass
class Session:
    key: tuple[str, int, str, int]
    started_at: float
    last_seen: float
    packets: int = 0
    bytes_seen: int = 0
    closed: bool = False
    next_sequence: int | None = None
    fragments: dict[int, bytes] = field(default_factory=dict)
    fragment_bytes: int = 0
    stream: bytearray = field(default_factory=bytearray)
    http_events: list[str] = field(default_factory=list)
    http_scan_offset: int = 0
    #: 搜索水位（只用于 find 起点，避免长流每包全量重扫）；head 提取仍从
    #: http_scan_offset 开始，二者分离才能既省扫描又不截断跨包 HTTP 头
    http_search_floor: int = 0
    matched_rules: set[str] = field(default_factory=set)


class SessionTracker:
    #: 流截断的批量水位：达到上限后不是每包都复制裁剪，而是每超出这么多
    #: 字节才裁一次（把每包 O(stream) 的 memcpy 摊销成低频批量操作）
    STREAM_TRIM_CHUNK = 256 * 1024

    def __init__(
        self,
        timeout_seconds: float = 120.0,
        max_stream_bytes: int = 2_000_000,
        max_fragments: int = 200,
        max_fragment_bytes: int = 1_000_000,
        max_http_events: int = 50,
        max_sessions: int = 10_000,
        clock: Clock = system_clock,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_stream_bytes = max_stream_bytes
        self.max_fragments = max_fragments
        # 碎片缓冲只限"条数"时，单条最大 payload(snaplen) 让每会话最坏可驻留
        # 200×64KB≈13MB；字节预算封住恶意乱序注入下的内存放大
        self.max_fragment_bytes = max_fragment_bytes
        self.max_http_events = max_http_events
        self.max_sessions = max_sessions
        self._clock = clock
        self.sessions: dict[tuple[str, int, str, int], Session] = {}
        self._cleanup_counter = 0
        self._cleanup_interval = 100

    def update(self, packet: PacketInfo) -> Session | None:
        key = packet.session_key
        if key is None:
            return None
        now = packet.timestamp if packet.timestamp is not None else self._clock()
        session = self.sessions.get(key)
        if session is None:
            if len(self.sessions) >= self.max_sessions:
                # 批量逐出最旧的 10%：每包对全表做 O(n) min 扫描在高新建
                # 流速率（端口扫描/蠕虫）下 CPU 退化显著
                evict_count = max(1, self.max_sessions // 10)
                oldest = sorted(self.sessions.values(), key=lambda s: s.last_seen)[:evict_count]
                for stale in oldest:
                    self.sessions.pop(stale.key, None)
            session = Session(key=key, started_at=now, last_seen=now)
            self.sessions[key] = session
        session.last_seen = now
        session.packets += 1
        session.bytes_seen += packet.length
        flags = set(packet.tcp.get("flags", []))
        seq = packet.tcp.get("sequence")
        payload = packet.payload
        if isinstance(seq, int) and payload:
            self._append_fragment(session, seq, payload)
        should_cleanup = False
        if flags.intersection({"FIN", "RST"}):
            session.closed = True
            should_cleanup = True
        self._cleanup_counter += 1
        if should_cleanup or self._cleanup_counter >= self._cleanup_interval:
            self.cleanup(now)
            self._cleanup_counter = 0
        return session

    def cleanup(self, now: float | None = None) -> None:
        current = self._clock() if now is None else now
        expired = [
            key
            for key, session in self.sessions.items()
            if session.closed or current - session.last_seen > self.timeout_seconds
        ]
        for key in expired:
            self.sessions.pop(key, None)

    @staticmethod
    def _seq_lt(a: int, b: int) -> bool:
        """TCP 序列号比较（处理回绕）。若 a < b 则返回 True。"""
        return ((a - b) & 0xFFFFFFFF) > 0x7FFFFFFF

    @staticmethod
    def _seq_sub(a: int, b: int) -> int:
        """TCP 序列号无符号减法（处理回绕）。返回 (a - b) & 0xFFFFFFFF。"""
        return (a - b) & 0xFFFFFFFF

    def _append_fragment(self, session: Session, sequence: int, payload: bytes) -> None:
        if session.next_sequence is None:
            session.next_sequence = sequence
        if self._seq_lt(sequence, session.next_sequence):
            overlap = self._seq_sub(session.next_sequence, sequence)
            if overlap >= len(payload):
                return
            payload = payload[overlap:]
            sequence = session.next_sequence
        session.fragments[sequence] = payload
        session.fragment_bytes += len(payload)
        while session.next_sequence in session.fragments:
            part = session.fragments.pop(session.next_sequence)
            session.fragment_bytes -= len(part)
            session.stream.extend(part)
            session.next_sequence = (session.next_sequence + len(part)) & 0xFFFFFFFF
            if len(session.stream) > self.max_stream_bytes + min(
                self.STREAM_TRIM_CHUNK, max(1, self.max_stream_bytes // 4)
            ):
                water = self.max_stream_bytes
                removed = len(session.stream) - water
                session.stream = session.stream[-water:]
                session.http_scan_offset = max(0, session.http_scan_offset - removed)
                session.http_search_floor = max(0, session.http_search_floor - removed)
                logger.debug("会话流截断：丢弃 %d 字节（session=%s）", removed, session.key)
            self._detect_http_events(session)
        if (
            len(session.fragments) >= self.max_fragments
            or session.fragment_bytes > self.max_fragment_bytes
        ):
            self.sessions.pop(session.key, None)

    def _detect_http_events(self, session: Session) -> None:
        stream = session.stream
        marker = b"\r\n\r\n"
        search_from = max(session.http_scan_offset, session.http_search_floor)
        while True:
            marker_pos = stream.find(marker, search_from)
            if marker_pos == -1:
                # 搜索水位推进到保守位置：完整分隔符只能从 len-3 之前开始，
                # 跨包边界出现的分隔符下次调用仍能找到；避免永不出现分隔符
                # 的长流（SSH/加密流量）每包从旧位置全量重扫
                conservative = max(0, len(stream) - len(marker) + 1)
                if conservative > session.http_search_floor:
                    session.http_search_floor = conservative
                return
            head = stream[session.http_scan_offset : marker_pos].lstrip(b"\r\n").decode("iso-8859-1", errors="replace")
            first = head.split("\r\n", 1)[0]
            if first and (first.startswith("HTTP/") or first.split(" ", 1)[0].isalpha()):
                if not session.http_events or session.http_events[-1] != first:
                    session.http_events.append(first)
                    if len(session.http_events) > self.max_http_events:
                        session.http_events.pop(0)
            session.http_scan_offset = marker_pos + len(marker)
            session.http_search_floor = session.http_scan_offset
            search_from = session.http_scan_offset
