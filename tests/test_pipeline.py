from __future__ import annotations

import threading
import time

from netguard.capture.pcap import RawPacket
from netguard.pipeline import PacketPipeline
from netguard.trafficgen import TEMPLATES

_GOOD_FRAME = next(t for t in TEMPLATES if t.id == "http-get").build()


def _raw(ts: float, data: bytes) -> RawPacket:
    return RawPacket(ts, data, len(data), len(data))


def _wait_until(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_parse_worker_survives_processor_exception() -> None:
    """处理链路抛异常只跳过该包，解析线程不能死亡。"""
    pipeline = PacketPipeline()
    original = pipeline.processor.process
    calls = {"n": 0}

    def flaky(raw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return original(raw)

    pipeline.processor.process = flaky
    for i in range(3):
        assert pipeline.source.enqueue_raw(_raw(1.0 + i * 0.01, _GOOD_FRAME))
    pipeline._start_parse_thread()
    try:
        assert _wait_until(lambda: pipeline.status().total_packets == 2)
    finally:
        pipeline.stop()
    assert pipeline.status().total_packets == 2


def test_stop_dispatches_remaining_events() -> None:
    """stop() 清空队列前先把已解析事件经 on_packet 派发，尾部告警不丢失。"""
    pipeline = PacketPipeline()
    received: list[object] = []
    pipeline.on_packet = received.append
    for i in range(5):
        assert pipeline.source.enqueue_raw(_raw(1.0 + i * 0.01, _GOOD_FRAME))
    pipeline._start_parse_thread()
    assert _wait_until(lambda: pipeline.event_queue.qsize() >= 5)
    # 直接 stop，不经 pump：队列里的 5 条事件必须全部送达 on_packet
    pipeline.stop()
    assert len(received) == 5


def test_drain_and_wait_replays_to_completion_regardless_of_timeout(tmp_path) -> None:
    """大文件回放不被 timeout 截断：timeout 只是无进展看门狗。"""
    from netguard.capture.pcap_file import write_pcap

    packets = [_raw(1.0 + i * 0.001, _GOOD_FRAME) for i in range(2000)]
    path = tmp_path / "big.pcap"
    write_pcap(path, packets)

    pipeline = PacketPipeline()
    pipeline.start_file(str(path))
    try:
        collected = pipeline.drain_and_wait(timeout=0.0)
    finally:
        pipeline.stop()
    assert len(collected) == 2000


def test_stopped_parse_thread_is_not_revived_by_restart() -> None:
    """旧一代解析线程持有独立的 stop 事件，stop 后不会被新 start 误唤醒。"""
    pipeline = PacketPipeline()
    pipeline._start_parse_thread()
    old_thread = pipeline._threads[0]
    pipeline.stop()
    assert not old_thread.is_alive()

    # 模拟 join 超时放弃：线程仍存活时直接开新代
    pipeline2 = PacketPipeline()
    pipeline2._start_parse_thread()
    zombie = pipeline2._threads[0]
    pipeline2._parse_stop.set()  # 等价 stop 的置位步骤
    pipeline2._threads = []  # 等价 join 超时后的放弃
    pipeline2._parse_stop = threading.Event()
    pipeline2.source.enqueue_raw(_raw(1.0, _GOOD_FRAME))
    pipeline2._start_parse_thread()
    try:
        assert _wait_until(lambda: not zombie.is_alive(), timeout=3.0)
        assert pipeline2._threads[0] is not zombie
    finally:
        pipeline2.stop()
