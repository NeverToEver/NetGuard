from __future__ import annotations

import struct

from netguard.parser import parse_packet
from netguard.rules.suggestions import generate_rule_suggestions


def ethernet(payload: bytes) -> bytes:
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack("!H", 0x0800) + payload


def ipv4(payload: bytes, proto: int = 6) -> bytes:
    total = 20 + len(payload)
    return (
        struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
        + payload
    )


def tcp(payload: bytes, src_port: int = 12345, dst_port: int = 80) -> bytes:
    return struct.pack("!HHIIHHHH", src_port, dst_port, 1, 0, (5 << 12) | 0x18, 1024, 0, 0) + payload


def udp(payload: bytes, src_port: int = 53000, dst_port: int = 53) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def test_generate_http_rule_suggestions() -> None:
    packet = parse_packet(ethernet(ipv4(tcp(b"GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"))))

    suggestions = generate_rule_suggestions([packet])

    rules = [item.rule for item in suggestions]
    assert any('content "GET"' in rule for rule in rules)
    assert any('content "GET /admin HTTP/1.1"' in rule for rule in rules)
    assert suggestions[0].match_count == 1


def test_generate_dns_rule_suggestions() -> None:
    dns = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    packet = parse_packet(ethernet(ipv4(udp(dns), proto=17)))

    suggestions = generate_rule_suggestions([packet])

    assert any('content "example"' in item.rule for item in suggestions)
    assert any('msg "检测到 DNS 流量"' in item.rule for item in suggestions)


def test_generate_rule_suggestions_empty_without_supported_packets() -> None:
    assert generate_rule_suggestions([]) == []
