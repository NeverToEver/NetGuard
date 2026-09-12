from __future__ import annotations

import logging
import queue
import threading
from pathlib import Path
from typing import Callable

from netguard.capture.pcap import CaptureDevice, PcapBackend, RawPacket, create_backend
from netguard.capture.pcap_file import PcapFileError, read_pcap

logger = logging.getLogger(__name__)


class CaptureSource:
    """抓包来源：封装 pcap 后端、原始包队列与抓包线程。

    负责后端生命周期、原始包入队与采集侧丢包/错误统计；解码与检测由
    :class:`netguard.processing.PacketProcessor` 承担，二者互不依赖，便于替换后端。
    """

    def __init__(
        self,
        max_queue: int = 10_000,
        backend_factory: Callable[[], PcapBackend] = create_backend,
    ) -> None:
        self.raw_queue: queue.Queue[RawPacket] = queue.Queue(maxsize=max_queue)
        self._backend_factory = backend_factory
        self._backend: PcapBackend | None = None
        self._backend_lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._dropped_count = 0
        self._dropped_lock = threading.Lock()
        self._max_dropped = 2_147_483_647
        self._drop_log_interval = 500
        self._capture_error: str | None = None
        self._capture_error_lock = threading.Lock()
        self._is_file_mode = False
        self._replay_finished = threading.Event()

    @property
    def is_file_mode(self) -> bool:
        return self._is_file_mode

    @property
    def replay_finished(self) -> bool:
        """文件回放模式且文件已全部读取完毕。"""
        return self._is_file_mode and self._replay_finished.is_set()

    @property
    def dropped_packets(self) -> int:
        with self._dropped_lock:
            return self._dropped_count

    @property
    def capture_error(self) -> str | None:
        with self._capture_error_lock:
            return self._capture_error

    @property
    def backend(self) -> PcapBackend:
        with self._backend_lock:
            if self._backend is None:
                self._backend = self._backend_factory()
            return self._backend

    def list_devices(self) -> list[CaptureDevice]:
        return self.backend.list_devices()

    def increment_dropped(self) -> int:
        with self._dropped_lock:
            if self._dropped_count < self._max_dropped:
                self._dropped_count += 1
            return self._dropped_count

    def enqueue_raw(self, raw: RawPacket, *, count_drop: bool = True) -> bool:
        """入队原始包；队列满时返回 False（``count_drop`` 控制是否计入丢包）。"""
        try:
            self.raw_queue.put(raw, timeout=0.1)
            return True
        except queue.Full:
            if count_drop:
                dropped = self.increment_dropped()
                if dropped % self._drop_log_interval == 1:
                    logger.warning("原始数据包队列已满 (%d)，丢弃数据包", self.raw_queue.maxsize)
            return False

    def start(self, device: str, bpf_filter: str = "") -> None:
        self.stop()
        self.reset()
        self._is_file_mode = False
        self._stop.clear()
        self.backend.open(device, bpf_filter)
        thread = threading.Thread(target=self._capture_worker, name="netguard-capture", daemon=True)
        self._threads = [thread]
        thread.start()

    def start_file(self, path: str | Path) -> None:
        """离线回放：在抓包线程中读取 pcap 文件并按原始时间戳入队。

        不依赖 libpcap，便于无网卡/无权限环境下实验与回归。读完文件后线程自然结束。
        """
        self.stop()
        self.reset()
        self._is_file_mode = True
        self._replay_finished.clear()
        self._stop.clear()
        thread = threading.Thread(
            target=self._file_worker, args=(str(path),), name="netguard-replay", daemon=True
        )
        self._threads = [thread]
        thread.start()

    def _file_worker(self, path: str) -> None:
        try:
            for raw in read_pcap(path):
                if self._stop.is_set():
                    return
                if not self.enqueue_raw(raw):
                    # 队列打满时短暂退避等待解析线程消费，且不重复计丢包
                    while not self._stop.is_set() and not self.enqueue_raw(raw, count_drop=False):
                        self._stop.wait(0.05)
                    if self._stop.is_set():
                        return
        except PcapFileError as exc:
            logger.error("pcap 回放失败：%s", exc)
            with self._capture_error_lock:
                self._capture_error = f"pcap 回放失败：{exc}"
        except OSError as exc:
            logger.exception("pcap 文件读取异常")
            with self._capture_error_lock:
                self._capture_error = f"pcap 文件读取异常：{exc}"
        finally:
            self._replay_finished.set()

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

    def reset(self) -> None:
        with self._dropped_lock:
            self._dropped_count = 0
        with self._capture_error_lock:
            self._capture_error = None
        self.drain_queue()

    def drain_queue(self) -> None:
        while True:
            try:
                self.raw_queue.get_nowait()
            except queue.Empty:
                break

    def _capture_worker(self) -> None:
        try:
            self.backend.capture_loop(self.enqueue_raw)
        except Exception as exc:
            logger.exception("抓包循环异常终止")
            detail = str(exc) or exc.__class__.__name__
            with self._capture_error_lock:
                self._capture_error = f"抓包循环异常终止：{detail}"
            self._stop.set()
