from __future__ import annotations

from netguard.parser.packet import PacketInfo


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


def _format_packet(packet: PacketInfo) -> str:
    sections = [
        ("Ethernet（以太网）", packet.ethernet),
        ("IP（网际协议）", packet.ip),
        ("TCP（传输控制协议）", packet.tcp),
        ("UDP（用户数据报协议）", packet.udp),
        ("HTTP（超文本传输协议）", packet.http),
        ("DNS（域名系统）", packet.dns),
        ("ICMP", packet.icmp),
    ]
    lines = [f"摘要：{packet.summary}", ""]
    for title, data in sections:
        if data:
            lines.append(title)
            for key, value in data.items():
                lines.append(f"  {key}: {value}")
            lines.append("")
    if packet.issues:
        lines.append("问题")
        for issue in packet.issues:
            lines.append(f"  {issue.layer}: {issue.message}")
    return "\n".join(lines)

