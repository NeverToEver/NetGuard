"""展示层数据转换：把 PacketInfo / Alert 变成界面直接可用的行与树。

放在这里而不是 GUI 类里，是为了让这些纯函数可以在无显示环境下单测——
``main_ui`` 只负责把结果塞进控件。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from netguard.gui.theme import SEVERITY_LABELS, alert_source, severity_key
from netguard.parser.packet import PacketInfo
from netguard.rules.engine import Alert

#: 协议号 → 名称（IP 首部）
_IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF"}

#: DNS 记录类型编号 → 名称
_DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    255: "ANY",
}

#: IP 首部协议号：这是“TCP”之类的短名，用于 IPv4 分组里的“协议”行
_HTTP_REQUEST_LABEL = "请求"
_HTTP_RESPONSE_LABEL = "响应"


def format_timestamp(timestamp: float) -> str:
    """把 Unix 时间戳渲染成 ``HH:MM:SS.mmm``。

    直接显示 ``1700000000.123`` 既占列宽又难读；抓包工具里人们看的是
    “第几秒发生了什么”，时刻 + 毫秒足够了。原始秒数在详情树里仍可查到。
    """
    try:
        seconds = float(timestamp)
    except (TypeError, ValueError):
        return str(timestamp)
    whole = int(seconds)
    millis = round((seconds - whole) * 1000)
    if millis >= 1000:
        whole += 1
        millis -= 1000
    stamp = time.strftime("%H:%M:%S", time.localtime(whole))
    return f"{stamp}.{millis:03d}"


def _search_text(packet: PacketInfo) -> str:
    return " ".join(
        [
            packet.protocol,
            packet.src,
            packet.dst,
            str(packet.src_port) if packet.src_port is not None else "",
            str(packet.dst_port) if packet.dst_port is not None else "",
            packet.summary,
            str(packet.http) if packet.http else "",
            str(packet.dns) if packet.dns else "",
            str(packet.icmp) if packet.icmp else "",
        ]
    ).lower()


def format_endpoint(host: str, port: int | None) -> str:
    return f"{host}:{port}" if port is not None else host


def packet_row(packet: PacketInfo) -> tuple[str, ...]:
    """数据包列表的一行：时间 / 源 / 目的 / 协议 / 长度 / 摘要。"""
    return (
        format_timestamp(packet.timestamp),
        format_endpoint(packet.src, packet.src_port),
        format_endpoint(packet.dst, packet.dst_port),
        packet.protocol,
        str(packet.length),
        packet.summary,
    )


def alert_row(alert: Alert) -> tuple[str, ...]:
    """告警表的一行：时间 / 级别 / 来源 / 信息 / 五元组。"""
    key = severity_key(alert)
    return (
        format_timestamp(alert.timestamp),
        SEVERITY_LABELS[key],
        alert_source(alert),
        alert.msg,
        f"{alert.protocol} {format_endpoint(alert.src, alert.src_port)} → {format_endpoint(alert.dst, alert.dst_port)}",
    )


def alert_detail_text(alert: Alert) -> str:
    """告警详情（用于复制到剪贴板或状态栏预览）。"""
    key = severity_key(alert)
    return (
        f"[{SEVERITY_LABELS[key]}] {alert.msg}\n"
        f"来源：{alert_source(alert)}（{alert.kind}）\n"
        f"五元组：{alert.protocol} "
        f"{format_endpoint(alert.src, alert.src_port)} → {format_endpoint(alert.dst, alert.dst_port)}\n"
        f"时间：{alert.timestamp:.3f}\n"
        f"原始摘要：{alert.summary}"
    )


@dataclass
class DetailNode:
    """协议解析树的一个节点。``value`` 为空时只显示分组标题。"""

    label: str
    value: str = ""
    kind: str = "key"
    children: list[DetailNode] = field(default_factory=list)


def _ip_protocol_name(number: object) -> str:
    if isinstance(number, int):
        name = _IP_PROTOCOLS.get(number)
        return f"{name} ({number})" if name else str(number)
    return str(number)


def _dns_type_name(number: object) -> str:
    if isinstance(number, int):
        name = _DNS_TYPES.get(number)
        return f"{name} ({number})" if name else str(number)
    return str(number)


def _ethernet_node(packet: PacketInfo) -> DetailNode | None:
    data = packet.ethernet
    if not data:
        return None
    node = DetailNode("Ethernet II", kind="group")
    if data.get("dst_mac"):
        node.children.append(DetailNode("目的 MAC", str(data["dst_mac"])))
    if data.get("src_mac"):
        node.children.append(DetailNode("源 MAC", str(data["src_mac"])))
    if "ethertype" in data:
        node.children.append(DetailNode("类型", f"0x{int(data['ethertype']):04x}"))
    for index, tag in enumerate(data.get("vlan_tags", []) or [], start=1):
        node.children.append(DetailNode(f"802.1Q 标签 {index}", f"VLAN {tag}"))
    return node


def _ip_node(packet: PacketInfo) -> DetailNode | None:
    data = packet.ip
    if not data:
        return None
    node = DetailNode("IPv4", kind="group")
    version = data.get("version")
    ihl = data.get("ihl")
    if version is not None and ihl is not None:
        node.children.append(DetailNode("版本 / 首部长度", f"{version} / {ihl}（{int(ihl) * 4} 字节）"))
    elif version is not None:
        node.children.append(DetailNode("版本", str(version)))
    for key, label in (
        ("total_length", "总长度"),
        ("ttl", "TTL"),
        ("fragment_offset", "分片偏移"),
    ):
        if data.get(key) is not None:
            node.children.append(DetailNode(label, str(data[key])))
    if data.get("protocol") is not None:
        node.children.append(DetailNode("协议", _ip_protocol_name(data["protocol"])))
    if data.get("src") or data.get("dst"):
        node.children.append(DetailNode("源 → 目的", f"{data.get('src', '')} → {data.get('dst', '')}"))
    if data.get("more_fragments"):
        node.children.append(DetailNode("更多分片", "是"))
    return node


def _tcp_node(packet: PacketInfo) -> DetailNode | None:
    data = packet.tcp
    if not data:
        return None
    node = DetailNode("TCP", kind="group")
    for key, label in (
        ("src_port", "源端口"),
        ("dst_port", "目的端口"),
        ("sequence", "序列号"),
        ("acknowledgement", "确认号"),
        ("window", "窗口"),
        ("payload_length", "载荷长度"),
    ):
        if data.get(key) is not None:
            node.children.append(DetailNode(label, str(data[key])))
    flags = data.get("flags")
    if flags:
        node.children.append(DetailNode("标志", ", ".join(str(flag) for flag in flags)))
    return node


def _udp_node(packet: PacketInfo) -> DetailNode | None:
    data = packet.udp
    if not data:
        return None
    node = DetailNode("UDP", kind="group")
    for key, label in (
        ("src_port", "源端口"),
        ("dst_port", "目的端口"),
        ("length", "长度"),
        ("checksum", "校验和"),
        ("payload_length", "载荷长度"),
    ):
        if data.get(key) is not None:
            node.children.append(DetailNode(label, str(data[key])))
    return node


def _http_node(packet: PacketInfo) -> DetailNode | None:
    data = packet.http
    if not data:
        return None
    node = DetailNode("HTTP", kind="group")
    is_response = data.get("type") == "response"
    node.children.append(DetailNode("类型", _HTTP_RESPONSE_LABEL if is_response else _HTTP_REQUEST_LABEL))
    if is_response:
        if data.get("status"):
            node.children.append(DetailNode("状态码", str(data["status"])))
        if data.get("version"):
            node.children.append(DetailNode("版本", str(data["version"])))
    else:
        if data.get("method"):
            node.children.append(DetailNode("方法", str(data["method"])))
        if data.get("target"):
            node.children.append(DetailNode("目标", str(data["target"])))
        if data.get("version"):
            node.children.append(DetailNode("版本", str(data["version"])))
    headers = data.get("headers") or {}
    if headers:
        header_node = DetailNode("请求头" if not is_response else "响应头", kind="group")
        for name, value in headers.items():
            header_node.children.append(DetailNode(str(name), str(value)))
        node.children.append(header_node)
    return node


def _dns_node(packet: PacketInfo) -> DetailNode | None:
    data = packet.dns
    if not data:
        return None
    node = DetailNode("DNS", kind="group")
    for key, label in (("transaction_id", "事务 ID"), ("flags", "标志"), ("answers", "应答记录数")):
        if data.get(key) is not None:
            value = f"0x{int(data[key]):04x}" if key == "transaction_id" else str(data[key])
            node.children.append(DetailNode(label, value))
    queries = data.get("queries") or []
    if queries:
        query_node = DetailNode(f"查询（{len(queries)} 条）", kind="group")
        for query in queries:
            query_node.children.append(
                DetailNode(
                    str(query.get("name", "")),
                    f"类型 {_dns_type_name(query.get('type'))} · 类 {query.get('class', '')}",
                )
            )
        node.children.append(query_node)
    return node


def _icmp_node(packet: PacketInfo) -> DetailNode | None:
    data = packet.icmp
    if not data:
        return None
    node = DetailNode("ICMP", kind="group")
    if data.get("type_name"):
        node.children.append(DetailNode("类型", str(data["type_name"])))
    icmp_fields = (
        ("type", "类型编号"),
        ("code", "代码"),
        ("checksum", "校验和"),
        ("identifier", "标识符"),
        ("sequence", "序号"),
    )
    for key, label in icmp_fields:
        if data.get(key) is not None:
            node.children.append(DetailNode(label, str(data[key])))
    return node


def build_detail_tree(packet: PacketInfo) -> list[DetailNode]:
    """把数据包展开成逐层协议树，供详情面板渲染。

    顺序与抓包工具的习惯一致：帧信息 → 链路层 → 网络层 → 传输层 → 应用层 → 解析问题。
    """
    frame = DetailNode("帧信息", kind="group")
    frame.children.append(DetailNode("捕获时间", format_timestamp(packet.timestamp)))
    frame.children.append(DetailNode("帧长度", f"{packet.length} 字节"))
    frame.children.append(DetailNode("协议", packet.protocol))
    if packet.summary:
        frame.children.append(DetailNode("摘要", packet.summary))

    nodes: list[DetailNode] = [frame]
    for builder in (_ethernet_node, _ip_node, _tcp_node, _udp_node, _http_node, _dns_node, _icmp_node):
        node = builder(packet)
        if node is not None:
            nodes.append(node)

    if packet.issues:
        problems = DetailNode(f"解析问题（{len(packet.issues)}）", kind="group")
        for issue in packet.issues:
            problems.children.append(DetailNode(issue.layer, issue.message, kind="problem"))
        nodes.append(problems)
    return nodes


def _format_packet(packet: PacketInfo) -> str:
    """纯文本形式的完整解析结果，用于复制到剪贴板与导出。"""
    lines = [f"摘要：{packet.summary}", ""]
    for node in build_detail_tree(packet):
        lines.append(node.label)
        for child in node.children:
            lines.append(f"  {child.label}: {child.value}")
        lines.append("")
    return "\n".join(lines)


#: 十六进制视图单次渲染的字节上限。超出部分会截断——否则一个 64KB 的
#: 巨型帧要塞进 Text 控件上万行，滚动会明显卡顿，而尾部字节本来也看不清。
MAX_HEX_BYTES = 4096


def hex_rows(data: bytes, width: int = 16) -> list[tuple[str, str, str]]:
    """把原始字节切成 (偏移, 十六进制, ASCII) 三段，供带标签的十六进制视图使用。

    与 ``parser.packet.hex_dump`` 的区别是这里保留字段边界，
    让 GUI 可以给偏移、字节、ASCII 分别上色，而不是拿到一整块纯文本。
    """
    rows: list[tuple[str, str, str]] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        # 第 8 字节后加一个空隙，和常见十六进制编辑器的视觉分组保持一致
        groups = []
        for index in range(0, width, 8):
            piece = chunk[index : index + 8]
            if piece:
                groups.append(" ".join(f"{byte:02x}" for byte in piece))
        hex_text = "  ".join(groups)
        ascii_text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        rows.append((f"{offset:08x}", hex_text, ascii_text))
    return rows
