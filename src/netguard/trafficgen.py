"""合成数据包构造与发包器。

两个用途：

1. **合成流量模板**（``TEMPLATES``）——GUI 的"测试发包"、基准测试与样本数据
   都基于它，覆盖 15 种正常流量与 10 种畸形/截断包。
2. **底层构造器**（``build_ethernet`` / ``build_ipv4`` / ``build_tcp`` /
   ``build_udp`` 等）——供需要自定义源/目的端口、标志位或构造攻击流量的调用方
   复用，避免各处手写 ``struct.pack``。``scripts/benchmark.py``、
   ``scripts/build_sample_pcap.py`` 与检测器测试都复用这一层。

``build_ipv4`` 会按 IPv4 伪首部补算 TCP/UDP 校验和，因此构造出的包能被本项目的
解析器正常接受。
"""

from __future__ import annotations

import logging
import struct
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass

logger = logging.getLogger(__name__)

__all__ = [
    "TEMPLATES",
    "PacketTemplate",
    "TrafficGenerator",
    "build_dns_query",
    "build_dns_response",
    "build_ethernet",
    "build_ipv4",
    "build_tcp",
    "build_udp",
]


@dataclass(frozen=True)
class PacketTemplate:
    id: str
    name: str
    protocol: str
    category: str  # "normal" or "abnormal"
    description: str
    build: Callable[[], bytes]


def build_ethernet(payload: bytes) -> bytes:
    """用固定 MAC 与 IPv4 EtherType 封装载荷。"""
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


def build_ipv4(payload: bytes, proto: int = 6, total_len_override: int | None = None) -> bytes:
    """构造 IPv4 数据报（固定 10.0.0.1 → 10.0.0.2，TTL 64）。

    ``proto`` 为 IP 协议号（1=ICMP，6=TCP，17=UDP）。``total_len_override`` 用于
    故意制造长度字段与实际不符的畸形包。
    """
    total = total_len_override if total_len_override is not None else 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto, 0, b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return _patch_l4_checksum(header + payload, proto)


def build_tcp(
    payload: bytes, src_port: int = 12345, dst_port: int = 80, flags: int = 0x18, data_offset: int = 5
) -> bytes:
    """构造 TCP 段。``flags`` 为 TCP 标志位（0x02=SYN，0x12=SYN-ACK，0x18=PSH+ACK）。"""
    return struct.pack("!HHIIHHHH", src_port, dst_port, 1, 0, (data_offset << 12) | flags, 1024, 0, 0) + payload


def build_udp(payload: bytes, src_port: int = 53000, dst_port: int = 53, length_override: int | None = None) -> bytes:
    """构造 UDP 数据报；``length_override`` 用于制造长度字段不符的畸形包。"""
    udp_len = length_override if length_override is not None else 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload


def build_dns_query() -> bytes:
    """构造对 example.com 的 DNS A 记录查询。"""
    return struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)


def build_dns_response() -> bytes:
    """构造 example.com 的 DNS A 记录响应（1.2.3.4）。"""
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
        lambda: build_ethernet(build_ipv4(build_tcp(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))),
    ),
    PacketTemplate(
        "http-post",
        "HTTP POST 请求",
        "HTTP",
        "normal",
        "标准 HTTP POST 请求到 80 端口",
        lambda: build_ethernet(
            build_ipv4(build_tcp(b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"))
        ),
    ),
    PacketTemplate(
        "http-resp",
        "HTTP 响应",
        "HTTP",
        "normal",
        "HTTP 200 响应从 80 端口返回",
        lambda: build_ethernet(
            build_ipv4(build_tcp(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n", src_port=80, dst_port=12345))
        ),
    ),
    PacketTemplate(
        "dns-query",
        "DNS 查询",
        "DNS",
        "normal",
        "标准 DNS A 记录查询到 53 端口",
        lambda: build_ethernet(build_ipv4(build_udp(build_dns_query()), proto=17)),
    ),
    PacketTemplate(
        "dns-resp",
        "DNS 响应",
        "DNS",
        "normal",
        "标准 DNS 响应从 53 端口返回",
        lambda: build_ethernet(build_ipv4(build_udp(build_dns_response(), src_port=53, dst_port=53000), proto=17)),
    ),
    PacketTemplate(
        "tcp-syn",
        "TCP SYN",
        "TCP",
        "normal",
        "TCP SYN 握手包（无载荷）",
        lambda: build_ethernet(build_ipv4(build_tcp(b"", flags=0x002))),
    ),
    PacketTemplate(
        "tcp-rst",
        "TCP RST",
        "TCP",
        "normal",
        "TCP RST 重置包",
        lambda: build_ethernet(build_ipv4(build_tcp(b"", flags=0x004))),
    ),
    PacketTemplate(
        "tcp-fin",
        "TCP FIN",
        "TCP",
        "normal",
        "TCP FIN 结束包",
        lambda: build_ethernet(build_ipv4(build_tcp(b"", flags=0x001))),
    ),
    PacketTemplate(
        "tcp-synack",
        "TCP SYN-ACK",
        "TCP",
        "normal",
        "TCP SYN-ACK 握手响应包",
        lambda: build_ethernet(build_ipv4(build_tcp(b"", flags=0x012))),
    ),
    PacketTemplate(
        "udp-plain",
        "UDP 普通包",
        "UDP",
        "normal",
        "UDP 数据报到 8080 端口",
        lambda: build_ethernet(build_ipv4(build_udp(b"hello udp", dst_port=8080), proto=17)),
    ),
    PacketTemplate(
        "icmp-echo",
        "ICMP Echo",
        "ICMP",
        "normal",
        "ICMP Echo Request (ping)",
        lambda: build_ethernet(build_ipv4(struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping!", proto=1)),
    ),
    PacketTemplate(
        "icmp-reply",
        "ICMP Echo Reply",
        "ICMP",
        "normal",
        "ICMP Echo Reply (ping 响应)",
        lambda: build_ethernet(build_ipv4(struct.pack("!BBHHH", 0, 0, 0, 1, 1) + b"pong!", proto=1)),
    ),
    PacketTemplate(
        "http-alt-port",
        "HTTP 非标准端口",
        "HTTP",
        "normal",
        "HTTP 请求到非标准端口 8888（验证内容探测识别）",
        lambda: build_ethernet(
            build_ipv4(build_tcp(b"GET / HTTP/1.1\r\nHost: alt.example.com\r\n\r\n", dst_port=8888))
        ),
    ),
    PacketTemplate(
        "dns-alt-port",
        "DNS 非标准端口",
        "DNS",
        "normal",
        "DNS 查询走非标准端口 5353（验证内容探测识别）",
        lambda: build_ethernet(build_ipv4(build_udp(build_dns_query(), dst_port=5353), proto=17)),
    ),
    PacketTemplate(
        "ssh-conn",
        "SSH 连接尝试",
        "TCP",
        "normal",
        "到 22 端口的 TCP SYN（连续勾选发送可触发暴力破解告警）",
        lambda: build_ethernet(build_ipv4(build_tcp(b"", src_port=20000, dst_port=22, flags=0x02))),
    ),
    # --- Abnormal packets ---
    PacketTemplate(
        "abn-eth",
        "截断 Ethernet",
        "ETHERNET",
        "abnormal",
        "Ethernet 帧头部不完整（仅前 6 字节目的 MAC）",
        lambda: build_ethernet(b"")[:6],
    ),
    PacketTemplate(
        "abn-ip-hdr",
        "截断 IPv4 头",
        "IP",
        "abnormal",
        "IPv4 头部被截断，缺少必要字段",
        lambda: build_ethernet(struct.pack("!BB", 0x45, 0)),
    ),
    PacketTemplate(
        "abn-ip-len",
        "无效 IPv4 长度",
        "IP",
        "abnormal",
        "IPv4 总长度字段与实际不符",
        lambda: build_ethernet(build_ipv4(build_tcp(b"GET / HTTP/1.1\r\n\r\n"), total_len_override=9999)),
    ),
    PacketTemplate(
        "abn-tcp-hdr",
        "截断 TCP 头",
        "TCP",
        "abnormal",
        "TCP 头部被截断",
        lambda: build_ethernet(build_ipv4(struct.pack("!HH", 12345, 80))),
    ),
    PacketTemplate(
        "abn-tcp-off",
        "无效 TCP 偏移",
        "TCP",
        "abnormal",
        "TCP 数据偏移字段无效（过小）",
        lambda: build_ethernet(build_ipv4(build_tcp(b"data", data_offset=2))),
    ),
    PacketTemplate(
        "abn-udp-hdr",
        "截断 UDP 头",
        "UDP",
        "abnormal",
        "UDP 头部被截断",
        lambda: build_ethernet(build_ipv4(struct.pack("!H", 53), proto=17)),
    ),
    PacketTemplate(
        "abn-udp-len",
        "无效 UDP 长度",
        "UDP",
        "abnormal",
        "UDP 长度字段与实际不符",
        lambda: build_ethernet(build_ipv4(build_udp(b"data", dst_port=8080, length_override=9999), proto=17)),
    ),
    PacketTemplate(
        "abn-dns-hdr",
        "截断 DNS 头",
        "DNS",
        "abnormal",
        "DNS 头部被截断",
        lambda: build_ethernet(build_ipv4(build_udp(b"\x00\x01"), proto=17)),
    ),
    PacketTemplate(
        "abn-http",
        "畸形 HTTP",
        "HTTP",
        "abnormal",
        "端口 80 但内容不是有效 HTTP",
        lambda: build_ethernet(build_ipv4(build_tcp(b"NOT_HTTP\r\n\r\n", dst_port=80))),
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
