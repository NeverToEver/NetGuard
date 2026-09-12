from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from typing import Callable

from netguard.capture.pcap import PcapBackend, RawPacket
from netguard.capture.source import CaptureSource
from netguard.processing import PacketEvent, PacketProcessor

logger = logging.getLogger(__name__)

__all__ = ["PacketEvent", "PacketPipeline", "PipelineStatus"]


@dataclass(frozen=True)
class PipelineStatus:
    """供界面读取的只读状态快照，避免 GUI 直接穿透到内部组件。"""

    total_packets: int
    total_bytes: int
    protocol_counts: dict[str, int]
    active_sessions: int
    packets_per_second: float
    bytes_per_second: float
    dropped_packets: int
    parse_errors: int
    capture_error: str | None
    rule_count: int


class PacketPipeline:
    """采集与处理的编排门面：串联 CaptureSource、PacketProcessor 与事件队列。

    公开接口保持向后兼容（``start``/``stop``/``pump``/``load_rules`` 等），并新增
    :meth:`status` 作为界面读取状态的统一入口。
    """

    def __init__(
        self,
        max_queue: int = 10_000,
        source: CaptureSource | None = None,
        processor: PacketProcessor | None = None,
    ) -> None:
        self.source = source or CaptureSource(max_queue=max_queue)
        self.processor = processor or PacketProcessor()
        self.event_queue: queue.Queue[PacketEvent] = queue.Queue(maxsize=max_queue)
        self.on_packet: Callable[[PacketEvent], None] | None = None
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._dropped_events = 0
        self._dropped_lock = threading.Lock()
        self._max_dropped = 2_147_483_647
        self._drop_log_interval = 500

    # --- 兼容旧接口的转发属性 -------------------------------------------------

    @property
    def raw_queue(self) -> queue.Queue[RawPacket]:
        return self.source.raw_queue

    @property
    def rules(self):
        return self.processor.rules

    @property
    def sessions(self):
        return self.processor.sessions

    @property
    def stats(self):
        return self.processor.stats

    @property
    def backend(self) -> PcapBackend:
        return self.source.backend

    @property
    def dropped_packets(self) -> int:
        with self._dropped_lock:
            event_drops = self._dropped_events
        return self.source.dropped_packets + event_drops

    @property
    def parse_errors(self) -> int:
        return self.processor.parse_errors

    @property
    def capture_error(self) -> str | None:
        return self.source.capture_error

    @property
    def rule_count(self) -> int:
        return self.processor.rule_count

    @property
    def replay_finished(self) -> bool:
        """文件回放模式且文件已读完（用于让 CLI 在回放结束后退出）。"""
        return self.source.replay_finished

    # --- 生命周期 -------------------------------------------------------------

    def _increment_event_dropped(self) -> int:
        with self._dropped_lock:
            if self._dropped_events < self._max_dropped:
                self._dropped_events += 1
            return self._dropped_events

    def load_rules(self, rule_text: str) -> int:
        return self.processor.load_rules(rule_text)

    def list_devices(self):
        return self.source.list_devices()

    def start(self, device: str, bpf_filter: str = "") -> None:
        self.stop()
        self.reset_state()
        self._stop.clear()
        self.source.start(device, bpf_filter)
        self._start_parse_thread()

    def start_file(self, path: str) -> None:
        """离线回放 pcap 文件（无需 libpcap 或管理员权限）。"""
        self.stop()
        self.reset_state()
        self._stop.clear()
        self.source.start_file(path)
        self._start_parse_thread()

    def _start_parse_thread(self) -> None:
        parse_thread = threading.Thread(target=self._parse_worker, name="netguard-parse", daemon=True)
        self._threads = [parse_thread]
        parse_thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.source.stop()
        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=2.0)
                if thread.is_alive():
                    logger.warning("线程 %s 未在超时内结束，强制放弃", thread.name)
        self._threads = []
        self._drain_queues()

    def reset_state(self) -> None:
        self.processor.reset()
        with self._dropped_lock:
            self._dropped_events = 0
        self.source.reset()
        self._drain_queues()

    def inject_test_packet(self, data: bytes, timestamp: float | None = None) -> None:
        raw = RawPacket(
            timestamp=timestamp or time.time(),
            data=data,
            captured_length=len(data),
            original_length=len(data),
        )
        if not self.source.enqueue_raw(raw):
            raise RuntimeError("测试发包队列已满，请降低发包频率或先停止自动发包")

    def _drain_queues(self) -> None:
        self.source.drain_queue()
        while True:
            try:
                self.event_queue.get_nowait()
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

    def drain_and_wait(self, timeout: float = 5.0) -> list[PacketEvent]:
        """回放结束后：等待解析线程清空队列，返回剩余全部事件。

        仅用于离线回放等有明确结束点的场景。
        """
        deadline = time.monotonic() + timeout
        collected: list[PacketEvent] = []
        while time.monotonic() < deadline:
            collected.extend(self.pump(1000))
            if self.replay_finished and self.source.raw_queue.empty() and self.event_queue.empty():
                break
            time.sleep(0.01)
        collected.extend(self.pump(1000))
        return collected

    def status(self) -> PipelineStatus:
        snap = self.processor.snapshot()
        return PipelineStatus(
            total_packets=snap.total_packets,
            total_bytes=snap.total_bytes,
            protocol_counts=dict(snap.protocol_counts),
            active_sessions=snap.active_sessions,
            packets_per_second=snap.packets_per_second,
            bytes_per_second=snap.bytes_per_second,
            dropped_packets=self.dropped_packets,
            parse_errors=self.processor.parse_errors,
            capture_error=self.source.capture_error,
            rule_count=self.processor.rule_count,
        )

    # --- 处理线程 -------------------------------------------------------------

    def _parse_worker(self) -> None:
        while not self._stop.is_set():
            try:
                raw = self.source.raw_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            event = self.processor.process(raw)
            if event is None:
                continue
            try:
                self.event_queue.put(event, timeout=0.1)
            except queue.Full:
                dropped = self._increment_event_dropped()
                if dropped % self._drop_log_interval == 1:
                    logger.warning("事件队列已满 (%d)，丢弃数据包", self.event_queue.maxsize)
