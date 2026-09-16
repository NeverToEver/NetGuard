from __future__ import annotations

import struct

from netguard.parser.packet import parse_packet
from netguard.trafficgen import TEMPLATES, _checksum


def _ip_header_checksum_ok(raw: bytes) -> bool:
    ihl = (raw[14] & 0x0F) * 4
    header = raw[14 : 14 + ihl]
    zeroed = header[:10] + b"\x00\x00" + header[12:]
    return struct.unpack("!H", header[10:12])[0] == _checksum(zeroed)


def _l4_checksum_ok(raw: bytes, proto: int) -> bool:
    ihl = (raw[14] & 0x0F) * 4
    l4 = raw[14 + ihl :]
    pseudo = raw[14 + 12 : 14 + 20] + b"\x00" + bytes([proto]) + struct.pack("!H", len(l4))
    return _checksum(pseudo + l4) == 0


def _template_bytes(template_id: str) -> bytes:
    return next(t for t in TEMPLATES if t.id == template_id).build()


def test_templates_carry_valid_ip_checksum() -> None:
    for tid in ("http-get", "dns-query", "icmp-echo", "abn-ip-len"):
        assert _ip_header_checksum_ok(_template_bytes(tid)), tid


def test_templates_carry_valid_transport_checksum() -> None:
    assert _l4_checksum_ok(_template_bytes("http-get"), proto=6)
    assert _l4_checksum_ok(_template_bytes("dns-query"), proto=17)
    icmp = _template_bytes("icmp-echo")
    ihl = (icmp[14] & 0x0F) * 4
    segment = icmp[14 + ihl :]
    assert struct.unpack("!H", segment[2:4])[0] == _checksum(segment[:2] + b"\x00\x00" + segment[4:])


def test_templates_still_parse_after_checksum_change() -> None:
    for template in TEMPLATES:
        info = parse_packet(template.build())
        assert info.raw == template.build() or template.category == "abnormal"


def test_abn_eth_template_is_six_bytes() -> None:
    assert len(_template_bytes("abn-eth")) == 6
