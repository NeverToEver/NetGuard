from __future__ import annotations

import pytest

from netguard.detection import DnsTunnelDetector, SynFloodDetector
from netguard.parser.packet import PacketInfo
from netguard.rules.engine import RuleEngine, RuleParseError, parse_rule


class FakeClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def tcp_packet(
    *,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 80,
    payload: bytes = b"",
    timestamp: float = 1.0,
) -> PacketInfo:
    return PacketInfo(
        timestamp=timestamp,
        length=54 + len(payload),
        raw=payload,
        protocol="TCP",
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        summary="test",
        payload=payload,
        tcp={"flags": ["ACK"], "payload_length": len(payload)},
    )


def udp_packet(
    *,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    src_port: int = 53000,
    dst_port: int = 53,
    payload: bytes = b"",
    timestamp: float = 1.0,
) -> PacketInfo:
    return PacketInfo(
        timestamp=timestamp,
        length=100,
        raw=payload,
        protocol="DNS",
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        summary="DNS",
        payload=payload,
    )


def dns_packet(name: str, timestamp: float = 0.0, src: str = "10.0.0.1") -> PacketInfo:
    return PacketInfo(
        timestamp=timestamp,
        length=100,
        raw=b"",
        protocol="DNS",
        src=src,
        dst="10.0.0.2",
        src_port=53000,
        dst_port=53,
        summary=f"DNS {name}",
        dns={"queries": [{"name": name}]},
    )


# --- Snort 冒号方言 ---

def test_colon_option_syntax_is_supported() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (content:"GET"; msg:"http get";)')
    assert rule.content == b"GET"
    assert rule.msg == "http get"


def test_colon_syntax_value_with_semicolon_and_colon() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (content:"a;b:c"; msg:"x";)')
    assert rule.content == b"a;b:c"


def test_flag_option_without_value_is_accepted() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (content:"GET"; nocase; msg:"x";)')
    assert rule.nocase is True


def test_empty_content_is_treated_as_absent() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (content:""; msg:"x";)')
    assert rule.content is None


def test_unbalanced_quote_is_rejected() -> None:
    with pytest.raises(RuleParseError):
        parse_rule('alert tcp any any -> any 80 (content "GET;)')


def test_snort_variable_is_rejected_loudly() -> None:
    with pytest.raises(RuleParseError):
        parse_rule('alert tcp $HOME_NET any -> any 80 (msg:"m";)')
    engine = RuleEngine()
    assert engine.load(['alert tcp $EXTERNAL_NET any -> any 80 (msg:"m";)']) == 1


# --- 不支持选项的可见提示 ---

def test_unsupported_options_reported_but_rule_loads() -> None:
    issues: list[str] = []
    rule = parse_rule(
        'alert tcp any any -> any 80 (content:"GET"; flags:"S"; dsize:>100; sid:1; rev:2;)',
        issues,
    )
    assert rule.content == b"GET"
    names = " ".join(issues)
    assert "flags" in names and "dsize" in names
    assert "sid" not in names and "rev" not in names


# --- 端口与地址子集 ---

def test_port_range_matches() -> None:
    engine = RuleEngine(['alert tcp any any -> any 80:90 (msg:"m";)'])
    assert engine.match(tcp_packet(dst_port=85))
    assert not engine.match(tcp_packet(dst_port=79))
    assert not engine.match(tcp_packet(dst_port=91))


def test_open_ended_port_range_and_list() -> None:
    engine = RuleEngine(['alert tcp any any -> any :1024 (msg:"m";)', 'alert udp any any -> any [53,5353] (msg:"m";)'])
    assert engine.match(tcp_packet(dst_port=443))
    assert not engine.match(tcp_packet(dst_port=4040))


def test_negated_port_matches() -> None:
    engine = RuleEngine(['alert tcp any any -> any !80 (msg:"m";)'])
    assert engine.match(tcp_packet(dst_port=81))
    assert not engine.match(tcp_packet(dst_port=80))


def test_negated_address_matches() -> None:
    engine = RuleEngine(['alert tcp !10.0.0.0/8 any -> any any (msg:"m";)'])
    assert engine.match(tcp_packet(src="192.168.1.5"))
    assert not engine.match(tcp_packet(src="10.0.0.1"))


def test_address_list_matches() -> None:
    engine = RuleEngine(['alert tcp [10.0.0.0/8,192.168.0.0/16] any -> any any (msg:"m";)'])
    assert engine.match(tcp_packet(src="10.0.0.1"))
    assert engine.match(tcp_packet(src="192.168.1.5"))
    assert not engine.match(tcp_packet(src="8.8.8.8"))


# --- nocase ---

def test_nocase_matches_case_insensitively() -> None:
    payload = b"get / HTTP/1.1\r\n\r\n"
    with_nocase = RuleEngine(['alert tcp any any -> any 80 (content "GET"; nocase; msg:"m";)'])
    without = RuleEngine(['alert tcp any any -> any 80 (content "GET"; msg:"m";)'])
    packet = tcp_packet(payload=payload)
    assert with_nocase.match(packet)
    assert not without.match(packet)


# --- 无会话协议的内容告警抑制 ---

def test_udp_content_alerts_are_rate_limited_per_flow() -> None:
    engine = RuleEngine(['alert udp any any -> any 53 (content "example"; msg:"dns";)'])
    packet = udp_packet(payload=b"example.com")

    assert len(engine.match(packet)) == 1
    # 同一五元组窗口内逐包告警被抑制
    assert engine.match(packet) == []
    assert engine.match(packet) == []
    # 窗口过后恢复告警
    later = udp_packet(payload=b"example.com", timestamp=1.0 + 2.0)
    assert len(engine.match(later)) == 1
    # 不同五元组不受抑制
    other = udp_packet(src="10.0.0.9", payload=b"example.com")
    assert len(engine.match(other)) == 1


# --- DnsTunnel 修复 ---

def test_dns_tunnel_long_name_alerts_are_suppressed_per_source() -> None:
    detector = DnsTunnelDetector(FakeClock(), max_name_length=40)
    total = []
    for i in range(20):
        total.extend(detector.observe(dns_packet(f"{'a' * 50}.example.com")))
    assert len(total) == 1


def test_dns_tunnel_three_label_names_aggregate_for_rate() -> None:
    detector = DnsTunnelDetector(FakeClock(), window_seconds=10.0, rate_threshold=5)
    alerts = []
    for i in range(5):
        alerts.extend(detector.observe(dns_packet(f"host{i}.example.com", timestamp=float(i) * 0.1)))
    assert len(alerts) == 1
    assert "example.com" in alerts[0].msg


def test_threshold_greater_than_max_samples_is_rejected() -> None:
    with pytest.raises(ValueError):
        SynFloodDetector(FakeClock(), threshold=100, max_samples=50)


# --- 建议引擎转义 ---

def test_suggestion_content_backslash_neutralized() -> None:
    from netguard.rules.suggestions import _clean_option_text

    cleaned = _clean_option_text("GET /a\\", max_length=80)
    rule = parse_rule(f'alert tcp any any -> any 80 (content "{cleaned}"; msg "m";)')
    assert rule.content == b"GET /a"
    assert rule.msg == "m"
