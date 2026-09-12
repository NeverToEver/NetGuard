from __future__ import annotations

from netguard.detection import (
    DnsTunnelDetector,
    PortScanDetector,
    SynFloodDetector,
    build_default_detectors,
)
from netguard.parser.packet import PacketInfo


class FakeClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def tcp_packet(
    *,
    flags: list[str] | None = None,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    src_port: int = 40000,
    dst_port: int = 80,
    timestamp: float = 0.0,
    protocol: str = "TCP",
) -> PacketInfo:
    return PacketInfo(
        timestamp=timestamp,
        length=54,
        raw=b"",
        protocol=protocol,
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        summary="test",
        tcp={"sequence": 1, "flags": flags or ["SYN"], "payload_length": 0},
    )


def dns_packet(name: str, timestamp: float = 0.0) -> PacketInfo:
    return PacketInfo(
        timestamp=timestamp,
        length=100,
        raw=b"",
        protocol="DNS",
        src="10.0.0.1",
        dst="10.0.0.2",
        src_port=53000,
        dst_port=53,
        summary=f"DNS {name}",
        dns={"queries": [{"name": name}]},
    )


# --- SYN flood ---

def test_syn_flood_triggers_at_threshold() -> None:
    clock = FakeClock()
    detector = SynFloodDetector(clock, window_seconds=5.0, threshold=5)

    alerts = []
    for i in range(5):
        alerts = detector.observe(tcp_packet(flags=["SYN"], src_port=1000 + i, timestamp=float(i) * 0.1))

    assert len(alerts) == 1
    assert alerts[0].kind == "anomaly"
    assert alerts[0].severity == "high"
    assert "SYN Flood" in alerts[0].msg


def test_syn_flood_ignores_syn_ack_and_non_syn() -> None:
    clock = FakeClock()
    detector = SynFloodDetector(clock, window_seconds=5.0, threshold=3)

    for i in range(10):
        assert detector.observe(tcp_packet(flags=["SYN", "ACK"], src_port=1000 + i)) == []
    for i in range(10):
        assert detector.observe(tcp_packet(flags=["ACK"], src_port=2000 + i)) == []


def test_syn_flood_window_expiry_resets_count() -> None:
    clock = FakeClock()
    detector = SynFloodDetector(clock, window_seconds=1.0, threshold=5)

    for i in range(4):
        detector.observe(tcp_packet(timestamp=0.0))
    # 超过窗口后早期 SYN 应过期
    alerts = detector.observe(tcp_packet(timestamp=10.0))
    assert alerts == []


def test_syn_flood_alerts_only_once_per_window() -> None:
    clock = FakeClock()
    detector = SynFloodDetector(clock, window_seconds=5.0, threshold=3)

    count = 0
    for i in range(10):
        count += len(detector.observe(tcp_packet(timestamp=float(i) * 0.01)))
    assert count == 1


# --- Port scan ---

def test_port_scan_triggers_on_distinct_ports() -> None:
    clock = FakeClock()
    detector = PortScanDetector(clock, window_seconds=10.0, threshold=5)

    alerts = []
    for port in range(1, 6):
        alerts = detector.observe(tcp_packet(flags=["SYN"], dst_port=port, timestamp=float(port) * 0.1))

    assert len(alerts) == 1
    assert "端口扫描" in alerts[0].msg


def test_port_scan_repeated_same_port_does_not_trigger() -> None:
    clock = FakeClock()
    detector = PortScanDetector(clock, window_seconds=10.0, threshold=5)

    for i in range(20):
        assert detector.observe(tcp_packet(dst_port=80, timestamp=float(i) * 0.1)) == []


# --- DNS tunnel ---

def test_dns_tunnel_flags_overlong_name() -> None:
    clock = FakeClock()
    detector = DnsTunnelDetector(clock, max_name_length=40)

    label = "a" * 50
    alerts = detector.observe(dns_packet(f"{label}.example.com"))

    assert len(alerts) == 1
    assert "DNS 隧道" in alerts[0].msg


def test_dns_tunnel_flags_query_burst_to_same_suffix() -> None:
    clock = FakeClock()
    detector = DnsTunnelDetector(clock, window_seconds=10.0, rate_threshold=5)

    alerts = []
    for i in range(5):
        alerts = detector.observe(dns_packet(f"host{i}.tunnel.example.com", timestamp=float(i) * 0.1))

    assert len(alerts) == 1
    assert "tunnel.example.com" in alerts[0].msg


def test_dns_tunnel_ignores_normal_queries() -> None:
    clock = FakeClock()
    detector = DnsTunnelDetector(clock, window_seconds=10.0, rate_threshold=5)

    assert detector.observe(dns_packet("www.example.com")) == []


# --- 集成 ---

def test_build_default_detectors_exposes_all() -> None:
    detectors = build_default_detectors(FakeClock())
    assert {d.name for d in detectors} == {"syn-flood", "port-scan", "dns-tunnel"}


def test_detectors_reset_clears_state() -> None:
    clock = FakeClock()
    detector = SynFloodDetector(clock, window_seconds=5.0, threshold=3)
    for _ in range(3):
        detector.observe(tcp_packet())
    detector.reset()
    assert detector.observe(tcp_packet()) == []


def test_port_scan_window_is_bounded_under_high_volume() -> None:
    clock = FakeClock()
    detector = PortScanDetector(clock, window_seconds=10.0, threshold=1000, max_samples=100)

    # 时间戳不前进时，窗口不应无限增长（否则 distinct 统计退化为 O(n²)）
    for _ in range(1000):
        detector.observe(tcp_packet(dst_port=80, timestamp=0.0))

    window = detector._ports["10.0.0.1"]
    assert len(window) <= 100
    assert len(detector._port_counts["10.0.0.1"]) <= 100
