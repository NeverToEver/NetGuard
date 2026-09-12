from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from netguard.parser.packet import HTTP_PORTS, PacketInfo
from netguard.rules.engine import parse_rule


@dataclass(frozen=True)
class RuleSuggestion:
    title: str
    description: str
    rule: str
    match_count: int


@dataclass(frozen=True)
class _Candidate:
    priority: int
    title: str
    description: str
    rule: str


_MAX_SUGGESTION_PACKETS = 500


def generate_rule_suggestions(packets: Iterable[PacketInfo], limit: int = 8) -> list[RuleSuggestion]:
    packet_list = [packet for packet in packets if packet.protocol in {"TCP", "UDP", "HTTP", "DNS"}]
    if not packet_list:
        return []
    if len(packet_list) > _MAX_SUGGESTION_PACKETS:
        packet_list = packet_list[-_MAX_SUGGESTION_PACKETS:]

    candidates: list[_Candidate] = []
    for packet in packet_list:
        candidates.extend(_packet_candidates(packet))

    suggestions: dict[str, RuleSuggestion] = {}
    priorities: dict[str, int] = {}
    for candidate in candidates:
        if candidate.rule in suggestions:
            priorities[candidate.rule] = min(priorities[candidate.rule], candidate.priority)
            continue
        match_count = _count_matches(candidate.rule, packet_list)
        if match_count == 0:
            continue
        suggestions[candidate.rule] = RuleSuggestion(
            title=candidate.title,
            description=candidate.description,
            rule=candidate.rule,
            match_count=match_count,
        )
        priorities[candidate.rule] = candidate.priority

    return sorted(
        suggestions.values(),
        key=lambda item: (priorities[item.rule], -item.match_count, item.rule),
    )[:limit]


def _packet_candidates(packet: PacketInfo) -> list[_Candidate]:
    if packet.protocol == "HTTP":
        return _http_candidates(packet)
    if packet.protocol == "DNS":
        return _dns_candidates(packet)
    return _generic_candidates(packet)


def _http_candidates(packet: PacketInfo) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    method = str(packet.http.get("method", "")).strip()
    first_line = str(packet.http.get("first_line", "")).strip()
    host_line = _http_header_line(packet, "host")

    if method:
        candidates.append(
            _content_candidate(
                10,
                "HTTP 方法匹配",
                f"匹配 {method} 请求方法，适合演示常见明文 HTTP 请求。",
                packet,
                method,
                f"检测到 HTTP {method} 请求",
            )
        )
    if first_line:
        candidates.append(
            _content_candidate(
                20,
                "HTTP 首行匹配",
                "匹配完整 HTTP 请求/响应首行，误报更少。",
                packet,
                first_line,
                "检测到指定 HTTP 首行",
            )
        )
    if host_line:
        host = host_line.split(":", 1)[1].strip() if ":" in host_line else host_line
        candidates.append(
            _content_candidate(
                30,
                "HTTP Host 匹配",
                f"匹配 Host 头 {host}，适合针对某个站点生成告警。",
                packet,
                host_line,
                f"检测到 HTTP Host {host}",
            )
        )
    candidates.append(_port_candidate(70, "HTTP 端口匹配", "只按 TCP 端口匹配，范围更宽。", packet, "检测到 HTTP 端口流量"))
    candidates.extend(_generic_payload_candidates(packet, start_priority=80))
    return candidates


def _dns_candidates(packet: PacketInfo) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for query in packet.dns.get("queries", []):
        name = str(query.get("name", "")).strip(".")
        keyword = _dns_keyword(name)
        if keyword:
            candidates.append(
                _content_candidate(
                    10,
                    "DNS 域名关键字匹配",
                    f"匹配 DNS 查询中的 {keyword}，适合演示域名访问告警。",
                    packet,
                    keyword,
                    f"检测到 DNS 查询 {name}",
                )
            )
    candidates.append(_port_candidate(40, "DNS 端口匹配", "只按 UDP 53 端口匹配，可覆盖普通 DNS 查询。", packet, "检测到 DNS 流量"))
    return candidates


def _generic_candidates(packet: PacketInfo) -> list[_Candidate]:
    return [
        _port_candidate(50, f"{packet.protocol} 端口匹配", "按协议和端口匹配当前流量。", packet, f"检测到 {packet.protocol} 流量"),
        *_generic_payload_candidates(packet, start_priority=60),
    ]


def _content_candidate(
    priority: int,
    title: str,
    description: str,
    packet: PacketInfo,
    content: str,
    msg: str,
) -> _Candidate:
    proto, src_port, dst_port = _rule_endpoint(packet)
    safe_content = _clean_option_text(content, max_length=80)
    safe_msg = _clean_option_text(msg, max_length=80)
    rule = f'alert {proto} any {src_port} -> any {dst_port} (content "{safe_content}"; msg "{safe_msg}";)'
    return _Candidate(priority, title, description, rule)


def _port_candidate(priority: int, title: str, description: str, packet: PacketInfo, msg: str) -> _Candidate:
    proto, src_port, dst_port = _rule_endpoint(packet)
    safe_msg = _clean_option_text(msg, max_length=80)
    rule = f'alert {proto} any {src_port} -> any {dst_port} (msg "{safe_msg}";)'
    return _Candidate(priority, title, description, rule)


def _generic_payload_candidates(packet: PacketInfo, start_priority: int) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for offset, keyword in enumerate(_payload_keywords(packet.payload)[:2]):
        candidates.append(
            _content_candidate(
                start_priority + offset,
                "Payload 关键字匹配",
                f"匹配载荷中的可读关键字 {keyword}。",
                packet,
                keyword,
                f"检测到关键字 {keyword}",
            )
        )
    return candidates


def _rule_endpoint(packet: PacketInfo) -> tuple[str, str, str]:
    proto = "tcp" if packet.protocol in {"TCP", "HTTP"} else "udp"
    service_ports = {53, *HTTP_PORTS}
    if packet.dst_port in service_ports:
        return proto, "any", str(packet.dst_port)
    if packet.src_port in service_ports:
        return proto, str(packet.src_port), "any"
    if packet.dst_port is not None:
        return proto, "any", str(packet.dst_port)
    if packet.src_port is not None:
        return proto, str(packet.src_port), "any"
    return proto, "any", "any"


def _http_header_line(packet: PacketInfo, header: str) -> str | None:
    try:
        text = packet.payload.decode("iso-8859-1", errors="ignore")
    except Exception:
        return None
    prefix = f"{header.lower()}:"
    for line in text.splitlines():
        if line.lower().startswith(prefix):
            return line.strip()
    return None


def _dns_keyword(name: str) -> str | None:
    labels = [label for label in name.split(".") if len(label) >= 3]
    if not labels:
        return None
    return max(labels, key=len)


def _payload_keywords(payload: bytes) -> list[str]:
    try:
        text = payload.decode("iso-8859-1", errors="ignore")
    except Exception:
        return []
    keywords: list[str] = []
    for match in re.finditer(r"[A-Za-z0-9_./:-]{4,80}", text):
        value = match.group(0).strip(".:-_/")
        if len(value) < 4 or value.isdigit() or value in keywords:
            continue
        keywords.append(value)
    return keywords


def _clean_option_text(value: str, max_length: int) -> str:
    cleaned = "".join(ch for ch in value.replace('"', "'").replace(";", ",") if ch >= " ")
    return cleaned[:max_length]


def _count_matches(rule_text: str, packets: list[PacketInfo]) -> int:
    rule = parse_rule(rule_text)
    rule_proto = rule.protocol
    rule_src_port = rule.src_port
    rule_dst_port = rule.dst_port
    content = rule.content
    count = 0
    for p in packets:
        proto = p.protocol.upper()
        if rule_proto != "ANY" and rule_proto != proto:
            if not (rule_proto == "TCP" and proto == "HTTP") and not (rule_proto == "UDP" and proto == "DNS"):
                continue
        if rule_src_port != "any":
            if p.src_port is None:
                continue
            try:
                if int(rule_src_port) != p.src_port:
                    continue
            except ValueError:
                continue
        if rule_dst_port != "any":
            if p.dst_port is None:
                continue
            try:
                if int(rule_dst_port) != p.dst_port:
                    continue
            except ValueError:
                continue
        if content is not None and content not in p.payload and content not in p.raw:
            continue
        count += 1
    return count
