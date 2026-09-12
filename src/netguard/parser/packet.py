from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Any


HTTP_PORTS = {80, 8000, 8080}


@dataclass(frozen=True)
class ParseIssue:
    layer: str
    message: str


@dataclass
class PacketInfo:
    timestamp: float
    length: int
    raw: bytes
    protocol: str = "OTHER"
    src: str = ""
    dst: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    summary: str = ""
    ethernet: dict[str, Any] = field(default_factory=dict)
    ip: dict[str, Any] = field(default_factory=dict)
    tcp: dict[str, Any] = field(default_factory=dict)
    udp: dict[str, Any] = field(default_factory=dict)
    http: dict[str, Any] = field(default_factory=dict)
    dns: dict[str, Any] = field(default_factory=dict)
    icmp: dict[str, Any] = field(default_factory=dict)
    payload: bytes = b""
    issues: list[ParseIssue] = field(default_factory=list)

    @property
    def session_key(self) -> tuple[str, int, str, int] | None:
        if self.protocol not in {"TCP", "HTTP"} or self.src_port is None or self.dst_port is None:
            return None
        return (self.src, self.src_port, self.dst, self.dst_port)


def parse_packet(raw: bytes, timestamp: float = 0.0, original_length: int | None = None) -> PacketInfo:
    info = PacketInfo(timestamp=timestamp, length=len(raw) if original_length is None else original_length, raw=raw)
    if len(raw) < 14:
        return _issue(info, "ethernet", "Ethernet 头部被截断")

    dst_mac, src_mac, ethertype = raw[:6], raw[6:12], struct.unpack("!H", raw[12:14])[0]
    info.ethernet = {
        "dst_mac": _mac(dst_mac),
        "src_mac": _mac(src_mac),
        "ethertype": ethertype,
    }
    if ethertype != 0x0800:
        info.summary = f"EtherType 0x{ethertype:04x}"
        return info
    return _parse_ipv4(info, raw, 14)


def _parse_ipv4(info: PacketInfo, raw: bytes, offset: int) -> PacketInfo:
    if len(raw) < offset + 20:
        return _issue(info, "ip", "IPv4 头部被截断")
    first = raw[offset]
    version = first >> 4
    ihl = (first & 0x0F) * 4
    if version != 4:
        return _issue(info, "ip", f"不支持的 IP 版本 {version}")
    if ihl < 20:
        return _issue(info, "ip", f"无效的 IPv4 头部长度 {ihl}")
    if len(raw) < offset + ihl:
        return _issue(info, "ip", "IPv4 选项被截断")
    total_length = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
    if total_length < ihl:
        return _issue(info, "ip", f"无效的 IPv4 总长度 {total_length}")
    available = min(total_length, len(raw) - offset)
    if available < total_length:
        info.issues.append(ParseIssue("ip", "IPv4 数据包被截断"))
    fragment_field = struct.unpack("!H", raw[offset + 6 : offset + 8])[0]
    fragment_offset = (fragment_field & 0x1FFF) * 8
    more_fragments = bool(fragment_field & 0x2000)
    proto = raw[offset + 9]
    src = str(ipaddress.IPv4Address(raw[offset + 12 : offset + 16]))
    dst = str(ipaddress.IPv4Address(raw[offset + 16 : offset + 20]))
    info.src = src
    info.dst = dst
    info.ip = {
        "version": version,
        "ihl": ihl,
        "total_length": total_length,
        "ttl": raw[offset + 8],
        "protocol": proto,
        "src": src,
        "dst": dst,
        "fragment_offset": fragment_offset,
        "more_fragments": more_fragments,
    }
    payload_offset = offset + ihl
    payload_end = offset + available
    if fragment_offset:
        info.payload = raw[payload_offset:payload_end]
        info.summary = f"IPv4 分片 offset={fragment_offset}"
        return info
    if proto == 6:
        return _parse_tcp(info, raw[payload_offset:payload_end])
    if proto == 17:
        return _parse_udp(info, raw[payload_offset:payload_end])
    if proto == 1:
        return _parse_icmp(info, raw[payload_offset:payload_end])
    info.summary = f"IPv4 协议号 {proto}"
    return info


def _parse_tcp(info: PacketInfo, data: bytes) -> PacketInfo:
    info.protocol = "TCP"
    if len(data) < 20:
        return _issue(info, "tcp", "TCP 头部被截断")
    src_port, dst_port, seq, ack, offset_flags, window = struct.unpack("!HHIIHH", data[:16])
    data_offset = ((offset_flags >> 12) & 0xF) * 4
    if data_offset < 20:
        return _issue(info, "tcp", f"无效的 TCP 数据偏移 {data_offset}")
    if len(data) < data_offset:
        return _issue(info, "tcp", "TCP 选项被截断")
    flags_value = offset_flags & 0x01FF
    payload = data[data_offset:]
    flags = _tcp_flags(flags_value)
    info.src_port = src_port
    info.dst_port = dst_port
    info.payload = payload
    info.tcp = {
        "src_port": src_port,
        "dst_port": dst_port,
        "sequence": seq,
        "acknowledgement": ack,
        "flags": flags,
        "window": window,
        "payload_length": len(payload),
    }
    if payload and (src_port in HTTP_PORTS or dst_port in HTTP_PORTS):
        _parse_http(info, payload)
    elif payload and _looks_like_http(payload):
        # 非标准端口上的 HTTP：按内容探测（请求行/状态行），端口判断仍是快速路径
        _parse_http(info, payload)
    info.summary = info.summary or f"TCP {src_port} -> {dst_port} {','.join(flags) or 'NONE'}"
    return info


_HTTP_METHODS = (
    b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS",
    b"PATCH", b"CONNECT", b"TRACE",
)


def _looks_like_http(payload: bytes) -> bool:
    """基于首行内容探测 HTTP，用于识别运行在非标准端口上的 HTTP 服务。"""
    first = payload.split(b"\r\n", 1)[0]
    if first.startswith(b"HTTP/"):
        return True
    method, _, rest = first.partition(b" ")
    return method in _HTTP_METHODS and rest.rstrip().endswith((b"HTTP/1.0", b"HTTP/1.1", b"HTTP/2", b"HTTP/3"))


def _parse_udp(info: PacketInfo, data: bytes) -> PacketInfo:
    info.protocol = "UDP"
    if len(data) < 8:
        return _issue(info, "udp", "UDP 头部被截断")
    src_port, dst_port, udp_len, checksum = struct.unpack("!HHHH", data[:8])
    if udp_len < 8:
        return _issue(info, "udp", f"无效的 UDP 长度 {udp_len}")
    if len(data) < udp_len:
        info.issues.append(ParseIssue("udp", "UDP 数据报被截断"))
    payload = data[8:min(udp_len, len(data))]
    info.src_port = src_port
    info.dst_port = dst_port
    info.payload = payload
    info.udp = {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": udp_len,
        "checksum": checksum,
        "payload_length": len(payload),
    }
    if src_port == 53 or dst_port == 53:
        _parse_dns(info, payload)
    elif payload and _looks_like_dns(payload):
        # 非标准端口上的 DNS：按报文结构探测，端口 53 仍是快速路径
        _parse_dns(info, payload)
    info.summary = info.summary or f"UDP {src_port} -> {dst_port}"
    return info


def _looks_like_dns(payload: bytes) -> bool:
    """基于报文结构探测 DNS：标志位合法且首个查询名能以 0 终止、不带指针。"""
    if len(payload) < 13:
        return False
    flags = payload[2:4]
    opcode = (flags[0] >> 3) & 0x0F
    if opcode > 5:  # query/status/notify/update 之外的操作码视为非 DNS
        return False
    if flags[1] & 0x0F > 5:  # rcode 超出常见范围
        return False
    qdcount, _, _, _ = struct.unpack("!HHHH", payload[4:12])
    if qdcount < 1 or qdcount > 20:
        return False
    offset = 12
    for _ in range(64):  # 域名标签数上限，防止异常数据死循环
        if offset >= len(payload):
            return False
        length = payload[offset]
        if length == 0:
            return offset + 5 <= len(payload)  # 0 终止符 + qtype/qclass
        if length & 0xC0 or length > 63:
            return False
        offset += 1 + length
    return False


def _parse_icmp(info: PacketInfo, data: bytes) -> PacketInfo:
    info.protocol = "ICMP"
    if len(data) < 4:
        return _issue(info, "icmp", "ICMP 头部被截断")
    icmp_type = data[0]
    icmp_code = data[1]
    checksum = struct.unpack("!H", data[2:4])[0]
    type_names = {
        0: "Echo Reply", 3: "Dest Unreachable", 5: "Redirect",
        8: "Echo Request", 11: "Time Exceeded",
    }
    type_name = type_names.get(icmp_type, f"Type {icmp_type}")
    info.icmp = {
        "type": icmp_type, "code": icmp_code,
        "checksum": checksum, "type_name": type_name,
    }
    if icmp_type in (0, 8) and len(data) >= 8:
        ident, seq = struct.unpack("!HH", data[4:8])
        info.icmp["identifier"] = ident
        info.icmp["sequence"] = seq
        info.payload = data[8:]
    else:
        info.payload = data[4:]
    info.summary = f"ICMP {type_name} (code={icmp_code})"
    return info


def _parse_http(info: PacketInfo, payload: bytes) -> None:
    try:
        text = payload.decode("iso-8859-1", errors="replace")
    except Exception as exc:
        info.issues.append(ParseIssue("http", f"解码失败：{exc}"))
        return
    header = text.split("\r\n\r\n", 1)[0]
    lines = header.split("\r\n")
    first = lines[0] if lines else ""
    if not first:
        return
    http: dict[str, Any] = {"first_line": first, "headers": {}}
    parts = first.split()
    if len(parts) >= 3 and parts[0].startswith("HTTP/"):
        http.update({"type": "response", "version": parts[0], "status": parts[1]})
    elif len(parts) >= 3 and parts[0].isalpha() and parts[2].startswith("HTTP/"):
        http.update({"type": "request", "method": parts[0], "target": parts[1], "version": parts[2]})
    else:
        info.issues.append(ParseIssue("http", f"非 HTTP 格式数据（端口 {info.dst_port}）"))
        return
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            http["headers"][key.strip().lower()] = value.strip()
    info.http = http
    info.protocol = "HTTP"
    info.summary = first


def _parse_dns(info: PacketInfo, payload: bytes) -> None:
    if len(payload) < 12:
        info.issues.append(ParseIssue("dns", "DNS 头部被截断"))
        return
    tid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
    dns: dict[str, Any] = {
        "transaction_id": tid,
        "flags": flags,
        "queries": [],
        "answers": ancount,
    }
    offset = 12
    for _ in range(min(qdcount, 20)):
        name, offset, issue = _read_dns_name(payload, offset)
        if issue:
            info.issues.append(ParseIssue("dns", issue))
            break
        if len(payload) < offset + 4:
            info.issues.append(ParseIssue("dns", "DNS 查询问题段被截断"))
            break
        qtype, qclass = struct.unpack("!HH", payload[offset : offset + 4])
        offset += 4
        dns["queries"].append({"name": name, "type": qtype, "class": qclass})
    info.dns = dns
    info.protocol = "DNS"
    qnames = ", ".join(q["name"] for q in dns["queries"])
    info.summary = f"DNS {qnames}" if qnames else "DNS"


def _read_dns_name(payload: bytes, offset: int, depth: int = 0) -> tuple[str, int, str | None]:
    if depth > 10:
        return "", offset, "DNS 压缩指针循环"
    labels: list[str] = []
    original_offset = offset
    jumped = False
    while True:
        if offset >= len(payload):
            return ".".join(labels), offset, "DNS 名称被截断"
        length = payload[offset]
        if length == 0:
            offset += 1
            return ".".join(labels), (original_offset + 2 if jumped else offset), None
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                return ".".join(labels), offset, "DNS 压缩指针被截断"
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            if pointer >= len(payload):
                return ".".join(labels), offset + 2, "DNS 压缩指针超出范围"
            suffix, _, issue = _read_dns_name(payload, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            return ".".join(labels), offset + 2, issue
        if length & 0xC0:
            return ".".join(labels), offset, "无效的 DNS 标签长度"
        offset += 1
        if offset + length > len(payload):
            return ".".join(labels), offset, "DNS 标签被截断"
        labels.append(payload[offset : offset + length].decode("ascii", errors="replace"))
        offset += length


def hex_dump(data: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        text_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<{width * 3}} {text_part}")
    return "\n".join(lines)


def _issue(info: PacketInfo, layer: str, message: str) -> PacketInfo:
    info.issues.append(ParseIssue(layer, message))
    info.summary = f"{layer}: {message}"
    return info


def _mac(value: bytes) -> str:
    return ":".join(f"{b:02x}" for b in value)


def _tcp_flags(value: int) -> list[str]:
    names = [(0x100, "NS"), (0x080, "CWR"), (0x040, "ECE"), (0x020, "URG"), (0x010, "ACK"), (0x008, "PSH"), (0x004, "RST"), (0x002, "SYN"), (0x001, "FIN")]
    return [name for bit, name in names if value & bit]
