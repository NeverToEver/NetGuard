from __future__ import annotations

import struct

import pytest

from netguard.capture.pcap import RawPacket
from netguard.capture.pcap_file import (
    PcapFileError,
    iter_pcap_safe,
    read_header,
    read_pcap,
    write_pcap,
)


def make_packet(timestamp: float, payload: bytes) -> RawPacket:
    return RawPacket(
        timestamp=timestamp,
        data=payload,
        captured_length=len(payload),
        original_length=len(payload) + 4,
    )


def test_write_then_read_roundtrip(tmp_path) -> None:
    packets = [
        make_packet(1.5, b"\xaa\xbb\xcc"),
        make_packet(2.25, b"\x11\x22\x33\x44"),
    ]
    path = tmp_path / "out.pcap"
    count = write_pcap(path, packets)

    assert count == 2
    read_back = list(read_pcap(path))
    assert len(read_back) == 2
    assert read_back[0].data == b"\xaa\xbb\xcc"
    assert read_back[0].original_length == 7
    assert read_back[1].data == b"\x11\x22\x33\x44"
    assert read_back[0].timestamp == pytest.approx(1.5)
    assert read_back[1].timestamp == pytest.approx(2.25)


def test_nanosecond_roundtrip(tmp_path) -> None:
    path = tmp_path / "ns.pcap"
    write_pcap(path, [make_packet(1.123456, b"x")], nanosecond=True)

    header = read_header(path)
    assert header.nanosecond is True
    assert next(iter(read_pcap(path))).timestamp == pytest.approx(1.123456, abs=1e-6)


def test_read_big_endian_file(tmp_path) -> None:
    path = tmp_path / "be.pcap"
    with open(path, "wb") as handle:
        handle.write(b"\xa1\xb2\xc3\xd4")  # 大端微秒 magic
        handle.write(struct.pack(">HHiIII", 2, 4, 0, 0, 65535, 1))
        handle.write(struct.pack(">IIII", 3, 500_000, 4, 4))
        handle.write(b"abcd")

    header = read_header(path)
    assert header.byte_order == ">"
    packet = next(iter(read_pcap(path)))
    assert packet.timestamp == pytest.approx(3.5)
    assert packet.data == b"abcd"


def test_rejects_non_pcap_file(tmp_path) -> None:
    path = tmp_path / "junk.bin"
    path.write_bytes(b"not a pcap file at all")
    with pytest.raises(PcapFileError):
        read_header(path)


def test_truncated_record_raises(tmp_path) -> None:
    path = tmp_path / "trunc.pcap"
    write_pcap(path, [make_packet(1.0, b"abcdefgh")])
    data = path.read_bytes()
    path.write_bytes(data[:-3])  # 截断最后一个包的载荷

    with pytest.raises(PcapFileError):
        list(read_pcap(path))


def test_iter_pcap_safe_tolerates_truncated_file(tmp_path) -> None:
    path = tmp_path / "trunc2.pcap"
    write_pcap(path, [make_packet(1.0, b"abcdefgh")])
    data = path.read_bytes()
    path.write_bytes(data[:-3])

    assert list(iter_pcap_safe(path)) == []


def test_empty_file_is_rejected(tmp_path) -> None:
    path = tmp_path / "empty.pcap"
    path.write_bytes(b"")
    with pytest.raises(PcapFileError):
        read_header(path)


def test_pipeline_replays_pcap_file(tmp_path) -> None:
    """离线回放端到端：文件 → CaptureSource → PacketProcessor。"""
    from netguard.pipeline import PacketPipeline
    from netguard.trafficgen import TEMPLATES

    builders = [t.build for t in TEMPLATES if t.category == "normal"]
    packets = [
        make_packet(1.0 + i * 0.01, builders[i % len(builders)]())
        for i in range(10)
    ]
    packets = [RawPacket(p.timestamp, p.data, len(p.data), len(p.data)) for p in packets]
    path = tmp_path / "replay.pcap"
    write_pcap(path, packets)

    pipeline = PacketPipeline()
    events = []
    pipeline.on_packet = events.append
    pipeline.start_file(str(path))
    collected = pipeline.drain_and_wait(timeout=5.0)
    pipeline.stop()

    assert pipeline.replay_finished is True
    assert len(collected) == 10
    assert all(event.packet.protocol for event in collected)


def test_write_pcap_clamps_data_to_declared_caplen(tmp_path) -> None:
    """captured_length < len(data) 时必须截断数据体，写出的文件可完整回读。"""
    frame = b"\x00" * 60
    raw = RawPacket(1.0, frame, captured_length=20, original_length=100)
    path = tmp_path / "mismatch.pcap"
    assert write_pcap(path, [raw]) == 1
    packets = list(read_pcap(path))
    assert len(packets) == 1
    assert packets[0].data == frame[:20]
    assert packets[0].captured_length == 20


def test_read_pcap_rejects_non_ethernet_linktype(tmp_path) -> None:
    """Linux SLL (113) 等非 Ethernet 链路类型必须显式报错，不能静默乱码。"""
    path = tmp_path / "sll.pcap"
    with open(path, "wb") as handle:
        handle.write(b"\xd4\xc3\xb2\xa1")
        handle.write(struct.pack("<HHiIII", 2, 4, 0, 0, 262_144, 113))
        handle.write(struct.pack("<IIII", 1, 0, 4, 4))
        handle.write(b"\x00" * 4)
    with pytest.raises(PcapFileError, match="链路类型"):
        list(read_pcap(path))
    # iter_pcap_safe 停止迭代而非抛异常
    assert list(iter_pcap_safe(path)) == []
