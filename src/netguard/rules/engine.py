from __future__ import annotations

import re
import threading
from dataclasses import dataclass
import ipaddress

from netguard.clock import Clock, system_clock
from netguard.parser.packet import PacketInfo


class RuleParseError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    action: str
    protocol: str
    src: str
    src_port: str
    direction: str
    dst: str
    dst_port: str
    content: bytes | None
    msg: str


@dataclass(frozen=True)
class Alert:
    timestamp: float
    msg: str
    protocol: str
    src: str
    dst: str
    src_port: int | None
    dst_port: int | None
    summary: str
    kind: str = "rule"
    severity: str = "medium"
    rule_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "kind": self.kind,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "msg": self.msg,
            "protocol": self.protocol,
            "src": self.src,
            "src_port": self.src_port,
            "dst": self.dst,
            "dst_port": self.dst_port,
            "summary": self.summary,
        }


DEFAULT_RULES = 'alert tcp any any -> any 80 (content "GET"; msg "检测到 HTTP GET 请求";)'

_RULE_RE = re.compile(
    r"^(?P<action>\w+)\s+(?P<proto>\w+)\s+(?P<src>\S+)\s+(?P<src_port>\S+)\s+"
    r"(?P<direction><>|->)\s+(?P<dst>\S+)\s+(?P<dst_port>\S+)\s*\((?P<opts>.*)\)\s*$"
)


class RuleEngine:
    def __init__(self, rules: list[str] | None = None, clock: Clock = system_clock) -> None:
        self.rules: list[Rule] = []
        self.index: dict[str, tuple[Rule, ...]] = {}
        self._clock = clock
        self._lock = threading.Lock()
        if rules:
            self.load(rules)

    def load(self, rules: list[str]) -> int:
        parsed: list[Rule] = []
        failed = 0
        for rule in rules:
            stripped = rule.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                parsed.append(parse_rule(stripped))
            except RuleParseError:
                failed += 1
        _temp: dict[str, list[Rule]] = {}
        for rule in parsed:
            _temp.setdefault(rule.protocol, []).append(rule)
        index: dict[str, tuple[Rule, ...]] = {proto: tuple(rules) for proto, rules in _temp.items()}
        # 原子替换：match() 在锁内读取 self.index，此处双赋值在同一个锁内完成，不会出现半替换状态
        with self._lock:
            self.rules = parsed
            self.index = index
        return failed

    def match(
        self,
        packet: PacketInfo,
        stream: bytes | None = None,
        matched: set[str] | None = None,
    ) -> list[Alert]:
        protocol = packet.protocol.upper()
        with self._lock:
            candidates = self.index.get(protocol, ())
            if protocol != "ANY":
                any_rules = self.index.get("ANY", ())
                if any_rules:
                    candidates = candidates + any_rules
            if protocol == "HTTP":
                tcp_rules = self.index.get("TCP", ())
                if tcp_rules:
                    candidates = candidates + tcp_rules
            elif protocol == "DNS":
                udp_rules = self.index.get("UDP", ())
                if udp_rules:
                    candidates = candidates + udp_rules
        alerts: list[Alert] = []
        for rule in candidates:
            if self._matches(rule, packet):
                if matched is not None and rule.content:
                    matched.add(_rule_key(rule))
                alerts.append(self._build_alert(rule, packet))
                continue
            if self._matches_stream(rule, packet, stream, matched):
                alerts.append(self._build_alert(rule, packet))
        return alerts

    def _matches_stream(
        self,
        rule: Rule,
        packet: PacketInfo,
        stream: bytes | None,
        matched: set[str] | None,
    ) -> bool:
        """内容规则的回退匹配：在整个 TCP 会话重组流中查找。

        这能检出把关键词拆分到多个 TCP 段（或跨包）以绕过单包检测的规避手法。
        同一会话内同一规则只告警一次，避免每个后续数据包重复命中。
        """
        if not rule.content or not stream:
            return False
        if not self._endpoint_and_proto_match(rule, packet):
            return False
        key = _rule_key(rule)
        if matched is not None and key in matched:
            return False
        if rule.content not in stream:
            return False
        if matched is not None:
            matched.add(key)
        return True

    def _endpoint_and_proto_match(self, rule: Rule, packet: PacketInfo) -> bool:
        pkt_proto = packet.protocol.upper()
        if rule.protocol != "ANY" and rule.protocol != pkt_proto:
            tcp_to_http = rule.protocol == "TCP" and pkt_proto == "HTTP"
            udp_to_dns = rule.protocol == "UDP" and pkt_proto == "DNS"
            if not (tcp_to_http or udp_to_dns):
                return False
        return _endpoint_matches(rule, packet)

    def _matches(self, rule: Rule, packet: PacketInfo) -> bool:
        if not self._endpoint_and_proto_match(rule, packet):
            return False
        if rule.content and rule.content not in packet.payload and rule.content not in packet.raw:
            return False
        return True

    def _build_alert(self, rule: Rule, packet: PacketInfo) -> Alert:
        return Alert(
            timestamp=packet.timestamp if packet.timestamp is not None else self._clock(),
            msg=rule.msg,
            protocol=packet.protocol,
            src=packet.src,
            dst=packet.dst,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            summary=packet.summary,
        )


def _rule_key(rule: Rule) -> str:
    return (
        f"{rule.protocol}|{rule.src}|{rule.src_port}|{rule.direction}"
        f"|{rule.dst}|{rule.dst_port}|{rule.content!r}"
    )


def parse_rule(text: str) -> Rule:
    match = _RULE_RE.match(text.strip())
    if not match:
        raise RuleParseError(f"无效的规则语法：{text}")
    action = match.group("action").lower()
    if action != "alert":
        raise RuleParseError(f"不支持的规则动作：{action}")
    opts = _parse_options(match.group("opts"))
    content = opts.get("content")
    return Rule(
        action=action,
        protocol=match.group("proto").upper(),
        src=match.group("src"),
        src_port=match.group("src_port"),
        direction=match.group("direction"),
        dst=match.group("dst"),
        dst_port=match.group("dst_port"),
        content=content.encode("utf-8") if content is not None else None,
        msg=opts.get("msg", "NetGuard 告警"),
    )


def _parse_options(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in _split_options(text):
        if " " not in part:
            continue
        key, value = part.split(" ", 1)
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace(r"\"", '"').replace(r"\\", "\\")
        result[key.lower()] = value
    return result


def _split_options(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and in_quotes:
            current.append(char)
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
            continue
        if char == ";" and not in_quotes:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)
    part = "".join(current).strip()
    if part:
        parts.append(part)
    return parts


def _port_matches(rule_port: str, packet_port: int | None) -> bool:
    if rule_port.lower() == "any":
        return True
    if packet_port is None:
        return False
    try:
        return int(rule_port) == packet_port
    except ValueError:
        return False


def _endpoint_matches(rule: Rule, packet: PacketInfo) -> bool:
    if _endpoint_direction_matches(rule.src, rule.src_port, rule.dst, rule.dst_port, packet):
        return True
    if rule.direction == "<>":
        return _endpoint_direction_matches(rule.dst, rule.dst_port, rule.src, rule.src_port, packet)
    return False


def _endpoint_direction_matches(
    src: str,
    src_port: str,
    dst: str,
    dst_port: str,
    packet: PacketInfo,
) -> bool:
    return (
        _address_matches(src, packet.src)
        and _port_matches(src_port, packet.src_port)
        and _address_matches(dst, packet.dst)
        and _port_matches(dst_port, packet.dst_port)
    )


def _address_matches(rule_addr: str, packet_addr: str) -> bool:
    if rule_addr.lower() == "any":
        return True
    if not packet_addr:
        return False
    try:
        return ipaddress.ip_address(packet_addr) in ipaddress.ip_network(rule_addr, strict=False)
    except ValueError:
        return rule_addr == packet_addr
