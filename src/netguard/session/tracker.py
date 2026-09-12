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
    stream: bytearray = field(default_factory=bytearray)
    http_events: list[str] = field(default_factory=list)
    http_scan_offset: int = 0


class SessionTracker:
    def __init__(
        self,
        timeout_seconds: float = 120.0,
        max_stream_bytes: int = 2_000_000,
        max_fragments: int = 200,
        max_http_events: int = 50,
        max_sessions: int = 10_000,
        clock: Clock = system_clock,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_stream_bytes = max_stream_bytes
        self.max_fragments = max_fragments
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
                oldest = min(self.sessions.values(), key=lambda s: s.last_seen, default=None)
                if oldest:
                    self.sessions.pop(oldest.key, None)
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
        while session.next_sequence in session.fragments:
            part = session.fragments.pop(session.next_sequence)
            session.stream.extend(part)
            session.next_sequence = (session.next_sequence + len(part)) & 0xFFFFFFFF
            if len(session.stream) > self.max_stream_bytes:
                removed = len(session.stream) - self.max_stream_bytes
                session.stream = session.stream[-self.max_stream_bytes:]
                session.http_scan_offset = max(0, session.http_scan_offset - removed)
                logger.debug("会话流截断：丢弃 %d 字节（session=%s）", removed, session.key)
            self._detect_http_events(session)
        if len(session.fragments) >= self.max_fragments:
            self.sessions.pop(session.key, None)

    def _detect_http_events(self, session: Session) -> None:
        stream = session.stream
        marker = b"\r\n\r\n"
        search_from = session.http_scan_offset
        while True:
            marker_pos = stream.find(marker, search_from)
            if marker_pos == -1:
                return
            head = stream[search_from:marker_pos].lstrip(b"\r\n").decode("iso-8859-1", errors="replace")
            first = head.split("\r\n", 1)[0]
            if first and (first.startswith("HTTP/") or first.split(" ", 1)[0].isalpha()):
                if not session.http_events or session.http_events[-1] != first:
                    session.http_events.append(first)
                    if len(session.http_events) > self.max_http_events:
                        session.http_events.pop(0)
            session.http_scan_offset = marker_pos + len(marker)
            search_from = session.http_scan_offset
