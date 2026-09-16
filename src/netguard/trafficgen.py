from __future__ import annotations

import logging
import struct
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PacketTemplate:
    id: str
    name: str
    protocol: str
    category: str  # "normal" or "abnormal"
    description: str
    build: Callable[[], bytes]


def _eth(payload: bytes) -> bytes:
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack("!H", 0x0800) + payload


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _patch_l4_checksum(packet: bytes, proto: int) -> bytes:
    """按 IPv4 伪首部补算 TCP/UDP 校验和；ICMP 直接对整条消息计算。"""
    if not packet or len(packet) < 22:
        return packet
    segment = packet[20:]
    if proto == 1:
        checksum = _checksum(segment)
        return packet[:22] + struct.pack("!H", checksum) + packet[24:]
    if proto not in (6, 17):
        return packet
    pseudo = packet[12:20] + b"\x00" + bytes([proto]) + struct.pack("!H", len(segment))
    checksum = _checksum(pseudo + segment)
    if proto == 17 and checksum == 0:
        checksum = 0xFFFF  # UDP 校验和算出 0 时按规范发送 0xFFFF
    pos = 20 + (16 if proto == 6 else 6)
    return packet[:pos] + struct.pack("!H", checksum) + packet[pos + 2 :]


def _ipv4(payload: bytes, proto: int = 6, total_len_override: int | None = None) -> bytes:
    total = total_len_override if total_len_override is not None else 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return _patch_l4_checksum(header + payload, proto)


def _tcp(payload: bytes, src_port: int = 12345, dst_port: int = 80, flags: int = 0x18, data_offset: int = 5) -> bytes:
    return struct.pack("!HHIIHHHH", src_port, dst_port, 1, 0, (data_offset << 12) | flags, 1024, 0, 0) + payload


def _udp(payload: bytes, src_port: int = 53000, dst_port: int = 53, length_override: int | None = None) -> bytes:
    udp_len = length_override if length_override is not None else 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload


def _dns_query() -> bytes:
    return struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)


def _dns_response() -> bytes:
    return (
        struct.pack("!HHHHHH", 0xABCD, 0x8180, 1, 1, 0, 0)
        + b"\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 0, 4)
        + b"\x01\x02\x03\x04"
    )


TEMPLATES: list[PacketTemplate] = [
    # --- Normal packets ---
    PacketTemplate(
        "http-get",
        "HTTP GET 请求",
        "HTTP",
        "normal",
        "标准 HTTP GET 请求到 80 端口",
        lambda: _eth(_ipv4(_tcp(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))),
    ),
    PacketTemplate(
        "http-post",
        "HTTP POST 请求",
        "HTTP",
        "normal",
        "标准 HTTP POST 请求到 80 端口",
        lambda: _eth(_ipv4(_tcp(b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"))),
    ),
    PacketTemplate(
        "http-resp",
        "HTTP 响应",
        "HTTP",
        "normal",
        "HTTP 200 响应从 80 端口返回",
        lambda: _eth(_ipv4(_tcp(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n", src_port=80, dst_port=12345))),
    ),
    PacketTemplate(
        "dns-query",
        "DNS 查询",
        "DNS",
        "normal",
        "标准 DNS A 记录查询到 53 端口",
        lambda: _eth(_ipv4(_udp(_dns_query()), proto=17)),
    ),
    PacketTemplate(
        "dns-resp",
        "DNS 响应",
        "DNS",
        "normal",
        "标准 DNS 响应从 53 端口返回",
        lambda: _eth(_ipv4(_udp(_dns_response(), src_port=53, dst_port=53000), proto=17)),
    ),
    PacketTemplate(
        "tcp-syn", "TCP SYN", "TCP", "normal", "TCP SYN 握手包（无载荷）", lambda: _eth(_ipv4(_tcp(b"", flags=0x002)))
    ),
    PacketTemplate(
        "tcp-rst", "TCP RST", "TCP", "normal", "TCP RST 重置包", lambda: _eth(_ipv4(_tcp(b"", flags=0x004)))
    ),
    PacketTemplate(
        "tcp-fin", "TCP FIN", "TCP", "normal", "TCP FIN 结束包", lambda: _eth(_ipv4(_tcp(b"", flags=0x001)))
    ),
    PacketTemplate(
        "tcp-synack",
        "TCP SYN-ACK",
        "TCP",
        "normal",
        "TCP SYN-ACK 握手响应包",
        lambda: _eth(_ipv4(_tcp(b"", flags=0x012))),
    ),
    PacketTemplate(
        "udp-plain",
        "UDP 普通包",
        "UDP",
        "normal",
        "UDP 数据报到 8080 端口",
        lambda: _eth(_ipv4(_udp(b"hello udp", dst_port=8080), proto=17)),
    ),
    PacketTemplate(
        "icmp-echo",
        "ICMP Echo",
        "ICMP",
        "normal",
        "ICMP Echo Request (ping)",
        lambda: _eth(_ipv4(struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping!", proto=1)),
    ),
    PacketTemplate(
        "icmp-reply",
        "ICMP Echo Reply",
        "ICMP",
        "normal",
        "ICMP Echo Reply (ping 响应)",
        lambda: _eth(_ipv4(struct.pack("!BBHHH", 0, 0, 0, 1, 1) + b"pong!", proto=1)),
    ),
    PacketTemplate(
        "http-alt-port",
        "HTTP 非标准端口",
        "HTTP",
        "normal",
        "HTTP 请求到非标准端口 8888（验证内容探测识别）",
        lambda: _eth(_ipv4(_tcp(b"GET / HTTP/1.1\r\nHost: alt.example.com\r\n\r\n", dst_port=8888))),
    ),
    PacketTemplate(
        "dns-alt-port",
        "DNS 非标准端口",
        "DNS",
        "normal",
        "DNS 查询走非标准端口 5353（验证内容探测识别）",
        lambda: _eth(_ipv4(_udp(_dns_query(), dst_port=5353), proto=17)),
    ),
    PacketTemplate(
        "ssh-conn",
        "SSH 连接尝试",
        "TCP",
        "normal",
        "到 22 端口的 TCP SYN（连续勾选发送可触发暴力破解告警）",
        lambda: _eth(_ipv4(_tcp(b"", src_port=20000, dst_port=22, flags=0x02))),
    ),
    # --- Abnormal packets ---
    PacketTemplate(
        "abn-eth",
        "截断 Ethernet",
        "ETHERNET",
        "abnormal",
        "Ethernet 帧头部不完整（仅前 6 字节目的 MAC）",
        lambda: _eth(b"")[:6],
    ),
    PacketTemplate(
        "abn-ip-hdr",
        "截断 IPv4 头",
        "IP",
        "abnormal",
        "IPv4 头部被截断，缺少必要字段",
        lambda: _eth(struct.pack("!BB", 0x45, 0)),
    ),
    PacketTemplate(
        "abn-ip-len",
        "无效 IPv4 长度",
        "IP",
        "abnormal",
        "IPv4 总长度字段与实际不符",
        lambda: _eth(_ipv4(_tcp(b"GET / HTTP/1.1\r\n\r\n"), total_len_override=9999)),
    ),
    PacketTemplate(
        "abn-tcp-hdr",
        "截断 TCP 头",
        "TCP",
        "abnormal",
        "TCP 头部被截断",
        lambda: _eth(_ipv4(struct.pack("!HH", 12345, 80))),
    ),
    PacketTemplate(
        "abn-tcp-off",
        "无效 TCP 偏移",
        "TCP",
        "abnormal",
        "TCP 数据偏移字段无效（过小）",
        lambda: _eth(_ipv4(_tcp(b"data", data_offset=2))),
    ),
    PacketTemplate(
        "abn-udp-hdr",
        "截断 UDP 头",
        "UDP",
        "abnormal",
        "UDP 头部被截断",
        lambda: _eth(_ipv4(struct.pack("!H", 53), proto=17)),
    ),
    PacketTemplate(
        "abn-udp-len",
        "无效 UDP 长度",
        "UDP",
        "abnormal",
        "UDP 长度字段与实际不符",
        lambda: _eth(_ipv4(_udp(b"data", dst_port=8080, length_override=9999), proto=17)),
    ),
    PacketTemplate(
        "abn-dns-hdr",
        "截断 DNS 头",
        "DNS",
        "abnormal",
        "DNS 头部被截断",
        lambda: _eth(_ipv4(_udp(b"\x00\x01"), proto=17)),
    ),
    PacketTemplate(
        "abn-http",
        "畸形 HTTP",
        "HTTP",
        "abnormal",
        "端口 80 但内容不是有效 HTTP",
        lambda: _eth(_ipv4(_tcp(b"NOT_HTTP\r\n\r\n", dst_port=80))),
    ),
    PacketTemplate(
        "abn-nonip",
        "非 IPv4 包",
        "ETHERNET",
        "abnormal",
        "EtherType 为无效值 0xFFFF，模拟未支持的协议类型",
        lambda: b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack("!H", 0xFFFF) + b"\x00" * 40,
    ),
]


class TrafficGenerator:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.running = False
        self.last_error: str | None = None

    def start(
        self, inject_fn: Callable[[bytes], None], templates: Sequence[PacketTemplate], interval: float = 3.0
    ) -> None:
        if self.running:
            return
        template_list = tuple(templates)
        if not template_list:
            logger.warning("测试发包器未选择模板，启动请求已忽略")
            return
        self._stop.clear()
        self.running = True
        self.last_error = None
        self._thread = threading.Thread(
            target=self._run,
            args=(inject_fn, template_list, interval),
            name="netguard-trafficgen",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=1.0)
        self._thread = None

    def _run(self, inject_fn: Callable[[bytes], None], templates: Sequence[PacketTemplate], interval: float) -> None:
        idx = 0
        while not self._stop.is_set():
            template = templates[idx % len(templates)]
            try:
                inject_fn(template.build())
            except Exception as exc:
                logger.exception("测试发包失败：%s", template.name)
                self.last_error = str(exc) or exc.__class__.__name__
                self.running = False
                self._stop.set()
                break
            idx += 1
            self._stop.wait(interval)
