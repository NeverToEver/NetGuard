from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from typing import Callable

from netguard.capture.pcap import PcapBackend, RawPacket, create_backend
from netguard.parser.packet import PacketInfo, parse_packet
from netguard.rules.engine import Alert, RuleEngine
from netguard.session.tracker import SessionTracker
from netguard.statistics.traffic_stats import TrafficStats

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PacketEvent:
    packet: PacketInfo
    alerts: tuple[Alert, ...]


class PacketPipeline:
    def __init__(self, max_queue: int = 10_000) -> None:
        self.raw_queue: queue.Queue[RawPacket] = queue.Queue(maxsize=max_queue)
        self.event_queue: queue.Queue[PacketEvent] = queue.Queue(maxsize=max_queue)
        self._backend: PcapBackend | None = None
        self._backend_lock = threading.Lock()
        self.rules = RuleEngine()
        self.sessions = SessionTracker()
        self.stats = TrafficStats()
        self.on_packet: Callable[[PacketEvent], None] | None = None
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._dropped_count = 0
        self._dropped_lock = threading.Lock()
        self._max_dropped = 2_147_483_647
        self._drop_log_interval = 500
        self._parse_error_count = 0
        self._parse_error_lock = threading.Lock()
        self._capture_error: str | None = None
        self._capture_error_lock = threading.Lock()

    @property
    def dropped_packets(self) -> int:
        with self._dropped_lock:
            return self._dropped_count

    @property
    def parse_errors(self) -> int:
        with self._parse_error_lock:
            return self._parse_error_count

    @property
    def capture_error(self) -> str | None:
        with self._capture_error_lock:
            return self._capture_error

    def _increment_dropped(self) -> int:
        with self._dropped_lock:
            if self._dropped_count < self._max_dropped:
                self._dropped_count += 1
            return self._dropped_count

    def load_rules(self, rule_text: str) -> int:
        rules = [line.strip() for line in rule_text.splitlines()]
        return self.rules.load(rules)

    @property
    def backend(self) -> PcapBackend:
        with self._backend_lock:
            if self._backend is None:
                self._backend = create_backend()
            return self._backend

    def list_devices(self):
        return self.backend.list_devices()

    def start(self, device: str, bpf_filter: str = "") -> None:
        self.stop()
        self.reset_state()
        self._stop.clear()
        self.backend.open(device, bpf_filter)
        capture_thread = threading.Thread(target=self._capture_worker, name="netguard-capture", daemon=True)
        parse_thread = threading.Thread(target=self._parse_worker, name="netguard-parse", daemon=True)
        self._threads = [capture_thread, parse_thread]
        for thread in self._threads:
            thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._backend_lock:
            backend = self._backend
            if backend is not None:
                backend.stop()
        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=2.0)
                if thread.is_alive():
                    logger.warning("线程 %s 未在超时内结束，强制放弃", thread.name)
        self._threads = []
        if backend is not None:
            backend.close()
        self._drain_queues()

    def reset_state(self) -> None:
        self.stats = TrafficStats()
        self.sessions = SessionTracker()
        with self._dropped_lock:
            self._dropped_count = 0
        with self._parse_error_lock:
            self._parse_error_count = 0
        with self._capture_error_lock:
            self._capture_error = None
        self._drain_queues()

    def inject_test_packet(self, data: bytes, timestamp: float | None = None) -> None:
        raw = RawPacket(
            timestamp=timestamp or time.time(),
            data=data,
            captured_length=len(data),
            original_length=len(data),
        )
        try:
            self.raw_queue.put(raw, timeout=0.1)
        except queue.Full as exc:
            self._increment_dropped()
            raise RuntimeError("测试发包队列已满，请降低发包频率或先停止自动发包") from exc

    def _drain_queues(self) -> None:
        for q in (self.raw_queue, self.event_queue):
            while True:
                try:
                    q.get_nowait()
                except queue.Empty:
                    break

    def pump(self, max_events: int = 200) -> list[PacketEvent]:
        events: list[PacketEvent] = []
        for _ in range(max_events):
            try:
                event = self.event_queue.get_nowait()
            except queue.Empty:
                break
            events.append(event)
            if self.on_packet:
                try:
                    self.on_packet(event)
                except Exception:
                    logger.exception("on_packet 回调异常")
        return events

    def _capture_worker(self) -> None:
        def enqueue(raw: RawPacket) -> None:
            try:
                self.raw_queue.put(raw, timeout=0.1)
            except queue.Full:
                dropped = self._increment_dropped()
                if dropped % self._drop_log_interval == 1:
                    logger.warning("原始数据包队列已满 (%d)，丢弃数据包", self.raw_queue.maxsize)
        try:
            self.backend.capture_loop(enqueue)
        except Exception as exc:
            logger.exception("抓包循环异常终止")
            detail = str(exc) or exc.__class__.__name__
            with self._capture_error_lock:
                self._capture_error = f"抓包循环异常终止：{detail}"
            self._stop.set()

    def _parse_worker(self) -> None:
        while not self._stop.is_set():
            try:
                raw = self.raw_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self._process_raw_packet(raw)

    def _process_raw_packet(self, raw: RawPacket) -> None:
        try:
            packet = parse_packet(raw.data, raw.timestamp, raw.original_length)
        except Exception:
            logger.exception("数据包解析异常")
            with self._parse_error_lock:
                self._parse_error_count += 1
            return
        session = self.sessions.update(packet)
        self.stats.update(packet, len(self.sessions.sessions))
        alerts = tuple(self.rules.match(packet))
        event = PacketEvent(packet, alerts)
        try:
            self.event_queue.put(event, timeout=0.1)
        except queue.Full:
            dropped = self._increment_dropped()
            if dropped % self._drop_log_interval == 1:
                logger.warning("事件队列已满 (%d)，丢弃数据包", self.event_queue.maxsize)
        if session and session.closed:
            self.sessions.cleanup(time.time())
