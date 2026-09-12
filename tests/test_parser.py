from __future__ import annotations

import struct

from netguard.parser import parse_packet, hex_dump, PacketInfo


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack("!H", ethertype) + payload


def ipv4(
    payload: bytes,
    proto: int = 6,
    src: bytes = b"\x0a\x00\x00\x01",
    dst: bytes = b"\x0a\x00\x00\x02",
    fragment: int = 0,
) -> bytes:
    total = 20 + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, fragment, 64, proto, 0, src, dst) + payload


def tcp(
    payload: bytes,
    src_port: int = 12345,
    dst_port: int = 80,
    seq: int = 1,
    flags: int = 0x18,
) -> bytes:
    return struct.pack("!HHIIHHHH", src_port, dst_port, seq, 0, (5 << 12) | flags, 1024, 0, 0) + payload


def udp(payload: bytes, src_port: int = 53000, dst_port: int = 53) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


# --- HTTP tests ---

def test_parse_http_packet() -> None:
    raw = ethernet(ipv4(tcp(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")))
    packet = parse_packet(raw, timestamp=1.25)
    assert packet.protocol == "HTTP"
    assert packet.src == "10.0.0.1"
    assert packet.dst_port == 80
    assert packet.http["method"] == "GET"
    assert packet.http["headers"]["host"] == "example.com"


def test_parse_http_response() -> None:
    raw = ethernet(ipv4(tcp(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n", dst_port=12345, src_port=80)))
    packet = parse_packet(raw)
    assert packet.protocol == "HTTP"
    assert packet.http["type"] == "response"
    assert packet.http["status"] == "200"


def test_parse_http_on_port_8080() -> None:
    raw = ethernet(ipv4(tcp(b"GET /api HTTP/1.1\r\n\r\n", dst_port=8080)))
    packet = parse_packet(raw)
    assert packet.protocol == "HTTP"


def test_parse_http_on_port_8000() -> None:
    raw = ethernet(ipv4(tcp(b"POST /data HTTP/1.1\r\n\r\n", dst_port=8000)))
    packet = parse_packet(raw)
    assert packet.protocol == "HTTP"


def test_http_port_payload_without_http_version_stays_tcp() -> None:
    raw = ethernet(ipv4(tcp(b"HELLO WORLD\r\n\r\n", dst_port=80)))
    packet = parse_packet(raw)
    assert packet.protocol == "TCP"
    assert not packet.http


# --- DNS tests ---

def test_parse_dns_query() -> None:
    dns = (
        struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        + b"\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )
    raw = ethernet(ipv4(udp(dns), proto=17))
    packet = parse_packet(raw)
    assert packet.protocol == "DNS"
    assert packet.dns["queries"][0]["name"] == "example.com"


def test_parse_dns_response() -> None:
    dns = (
        struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        + b"\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 300, 4)
        + b"\x01\x02\x03\x04"
    )
    raw = ethernet(ipv4(udp(dns, src_port=53, dst_port=53000), proto=17))
    packet = parse_packet(raw)
    assert packet.protocol == "DNS"
    assert packet.dns["answers"] == 1


def test_parse_dns_truncated_header() -> None:
    raw = ethernet(ipv4(udp(b"\x00\x01"), proto=17))
    packet = parse_packet(raw)
    assert any(i.layer == "dns" for i in packet.issues)


# --- TCP flag tests ---

def test_parse_tcp_syn_packet() -> None:
    raw = ethernet(ipv4(tcp(b"", flags=0x002)))
    packet = parse_packet(raw)
    assert packet.protocol == "TCP"
    assert "SYN" in packet.tcp["flags"]


def test_parse_tcp_rst_packet() -> None:
    raw = ethernet(ipv4(tcp(b"", flags=0x004)))
    packet = parse_packet(raw)
    assert "RST" in packet.tcp["flags"]


def test_parse_tcp_fin_packet() -> None:
    raw = ethernet(ipv4(tcp(b"", flags=0x001)))
    packet = parse_packet(raw)
    assert "FIN" in packet.tcp["flags"]


def test_parse_tcp_synack_packet() -> None:
    raw = ethernet(ipv4(tcp(b"", flags=0x012)))
    packet = parse_packet(raw)
    assert "SYN" in packet.tcp["flags"]
    assert "ACK" in packet.tcp["flags"]


def test_parse_tcp_all_flags() -> None:
    raw = ethernet(ipv4(tcp(b"", flags=0x1FF)))
    packet = parse_packet(raw)
    assert len(packet.tcp["flags"]) == 9


# --- Edge case tests ---

def test_truncated_packet_returns_issue() -> None:
    packet = parse_packet(b"\x00\x01")
    assert packet.issues
    assert packet.issues[0].layer == "ethernet"


def test_parse_packet_preserves_zero_original_length() -> None:
    packet = parse_packet(ethernet(b"", ethertype=0x86DD), original_length=0)
    assert packet.length == 0


def test_unknown_ethertype_is_safe() -> None:
    packet = parse_packet(ethernet(b"payload", ethertype=0x86DD))
    assert packet.protocol == "OTHER"
    assert not packet.issues


def test_truncated_ipv4_header() -> None:
    raw = ethernet(b"\x45\x00")
    packet = parse_packet(raw)
    assert any(i.layer == "ip" for i in packet.issues)


def test_non_ipv4_packet() -> None:
    raw = ethernet(b"", ethertype=0x0806)
    packet = parse_packet(raw)
    assert packet.protocol == "OTHER"
    assert packet.summary.startswith("EtherType")


def test_udp_packet_without_dns() -> None:
    raw = ethernet(ipv4(udp(b"hello", src_port=12345, dst_port=12346), proto=17))
    packet = parse_packet(raw)
    assert packet.protocol == "UDP"
    assert not packet.dns


def test_truncated_udp_header() -> None:
    raw = ethernet(ipv4(b"\x00\x01", proto=17))
    packet = parse_packet(raw)
    assert any(i.layer == "udp" for i in packet.issues)


def test_truncated_tcp_header() -> None:
    raw = ethernet(ipv4(b"\x00\x01", proto=6))
    packet = parse_packet(raw)
    assert any(i.layer == "tcp" for i in packet.issues)


def test_ipv4_with_unknown_protocol() -> None:
    raw = ethernet(ipv4(b"", proto=99))
    packet = parse_packet(raw)
    assert packet.summary.startswith("IPv4 协议号")


def test_ipv4_with_icmp_protocol() -> None:
    raw = ethernet(ipv4(b"\x08\x00\xf7\xff\x00\x00\x00\x00", proto=1))
    packet = parse_packet(raw)
    assert packet.protocol == "ICMP"
    assert packet.ip["protocol"] == 1


def test_ipv4_non_initial_fragment_is_not_parsed_as_tcp_header() -> None:
    raw = ethernet(ipv4(tcp(b"GET / HTTP/1.1\r\n\r\n"), fragment=1))
    packet = parse_packet(raw)
    assert packet.protocol == "OTHER"
    assert not packet.tcp
    assert packet.ip["fragment_offset"] == 8


def test_ipv4_invalid_total_length() -> None:
    raw = ethernet(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 2, 1, 0, 64, 6, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02"))
    packet = parse_packet(raw)
    assert any("总长度" in i.message for i in packet.issues)


def test_ipv4_truncated_options() -> None:
    raw = ethernet(struct.pack("!BBHHHBBH4s4s", 0x4F, 0, 40, 1, 0, 64, 6, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02"))
    packet = parse_packet(raw)
    assert any(i.layer == "ip" for i in packet.issues)


def test_tcp_payload_on_non_http_port() -> None:
    raw = ethernet(ipv4(tcp(b"SSH-2.0-OpenSSH", dst_port=22)))
    packet = parse_packet(raw)
    assert packet.protocol == "TCP"
    assert not packet.http


def test_tcp_invalid_data_offset() -> None:
    raw = ethernet(ipv4(struct.pack("!HHIIHHHH", 12345, 80, 1, 0, (3 << 12) | 0x010, 1024, 0, 0)))
    packet = parse_packet(raw)
    assert any("数据偏移" in i.message for i in packet.issues)


def test_tcp_options_truncated() -> None:
    raw = ethernet(ipv4(struct.pack("!HHIIHHHH", 12345, 80, 1, 0, (8 << 12) | 0x010, 1024, 0, 0)))
    packet = parse_packet(raw)
    assert any(i.layer == "tcp" for i in packet.issues)


def test_hex_dump_output() -> None:
    result = hex_dump(b"Hello", width=16)
    assert "48 65 6c 6c 6f" in result
    assert "Hello" in result


def test_hex_dump_wide_output() -> None:
    data = b"\x00\x01\x02\x03" * 10
    result = hex_dump(data, width=8)
    assert result.count("\n") >= 4


def test_session_key_returns_none_for_udp() -> None:
    pkt = PacketInfo(timestamp=0, length=10, raw=b"", protocol="UDP", src_port=1, dst_port=2)
    assert pkt.session_key is None


def test_session_key_returns_tuple_for_tcp() -> None:
    pkt = PacketInfo(timestamp=0, length=10, raw=b"", protocol="TCP",
                     src="1.2.3.4", dst="5.6.7.8", src_port=80, dst_port=443)
    assert pkt.session_key == ("1.2.3.4", 80, "5.6.7.8", 443)


# --- 非标准端口协议识别 ---

def _tcp_raw(src_port: int, dst_port: int, payload: bytes) -> bytes:
    tcp = struct.pack("!HHIIHHHH", src_port, dst_port, 1, 0, (5 << 12) | 0x18, 1024, 0, 0) + payload
    ip_total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total, 1, 0, 64, 6, 0,
                     b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    return b"\xaa" * 12 + b"\x08\x00" + ip + tcp


def _udp_raw(src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    ip_total = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total, 1, 0, 64, 17, 0,
                     b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    return b"\xaa" * 12 + b"\x08\x00" + ip + udp


def test_http_detected_on_non_standard_port() -> None:
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    info = parse_packet(_tcp_raw(50000, 8888, payload), timestamp=1.0)
    assert info.protocol == "HTTP"
    assert info.http["method"] == "GET"
    assert info.http["headers"]["host"] == "example.com"


def test_http_response_detected_on_non_standard_port() -> None:
    payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    info = parse_packet(_tcp_raw(8888, 50000, payload), timestamp=1.0)
    assert info.protocol == "HTTP"
    assert info.http["type"] == "response"


def test_random_binary_payload_stays_tcp() -> None:
    info = parse_packet(_tcp_raw(50000, 8888, bytes(range(64))), timestamp=1.0)
    assert info.protocol == "TCP"
    assert not info.http


def test_dns_detected_on_non_standard_port() -> None:
    name = b"\x03www\x07example\x03com\x00"
    payload = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    info = parse_packet(_udp_raw(53000, 5353, payload), timestamp=1.0)
    assert info.protocol == "DNS"
    assert info.dns["queries"][0]["name"] == "www.example.com"


def test_random_udp_payload_stays_udp() -> None:
    info = parse_packet(_udp_raw(53000, 5353, bytes(range(32))), timestamp=1.0)
    assert info.protocol == "UDP"
    assert not info.dns


def test_http_first_line_is_truncated() -> None:
    huge = b"GET /" + b"A" * 60_000 + b" HTTP/1.1\r\nHost: example.com\r\n\r\n"
    info = parse_packet(ethernet(ipv4(tcp(huge, dst_port=80))))
    assert len(info.summary) <= 512
    assert info.http["first_line"] == info.summary
    assert info.summary.startswith("GET /AAA")


def test_http_header_value_truncated() -> None:
    payload = b"GET / HTTP/1.1\r\nX-Long: " + b"B" * 5000 + b"\r\n\r\n"
    info = parse_packet(ethernet(ipv4(tcp(payload, dst_port=80))))
    assert len(info.http["headers"]["x-long"]) <= 512


# --- VLAN (802.1Q / QinQ) ---

def _vlan_tag(vid: int) -> bytes:
    # 802.1Q 头 = TPID(0x8100) + TCI；解析器读 TCI 后取下 2 字节为内层 EtherType
    return struct.pack("!HH", 0x8100, vid)


def _tagged_frame(*tags: bytes, ethertype: int = 0x0800, payload: bytes = b"") -> bytes:
    macs = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66"
    frame = macs + b"".join(tags) + struct.pack("!H", ethertype) + payload
    return frame


def test_vlan_tagged_tcp_packet_parses() -> None:
    inner = ipv4(tcp(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
    frame = _tagged_frame(_vlan_tag(100), payload=inner)
    info = parse_packet(frame)
    assert info.protocol == "HTTP"
    assert info.ethernet["vlan_tags"] == [100]
    assert info.dst_port == 80


def test_qinq_double_tagged_packet_parses() -> None:
    inner = ipv4(tcp(b"", flags=0x002))
    frame = _tagged_frame(
        struct.pack("!HH", 0x88A8, 200),  # 外层 802.1ad TPID+TCI
        _vlan_tag(300),                   # 内层 802.1Q TPID+TCI
        payload=inner,
    )
    info = parse_packet(frame)
    assert info.protocol == "TCP"
    assert info.ethernet["vlan_tags"] == [200, 300]
    assert set(info.tcp["flags"]) == {"SYN"}


def test_truncated_vlan_tag_returns_issue() -> None:
    frame = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x81\x00\x0a"
    info = parse_packet(frame)
    assert info.issues and "802.1Q" in info.issues[0].message


def test_vlan_packet_with_unknown_inner_ethertype() -> None:
    frame = _tagged_frame(_vlan_tag(100), ethertype=0x86DD, payload=b"\x00" * 8)
    info = parse_packet(frame)
    assert info.ethernet["ethertype"] == 0x86DD
    assert "0x86dd" in info.summary
