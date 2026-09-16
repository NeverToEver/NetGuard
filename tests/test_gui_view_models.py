"""展示层转换的单元测试：全部是无副作用纯函数，无需 Tk 显示。"""

from __future__ import annotations

import re

from netguard.gui import view_models as vm
from netguard.parser.packet import PacketInfo, ParseIssue
from netguard.rules.engine import Alert


def make_packet(**overrides: object) -> PacketInfo:
    base: dict[str, object] = {
        "timestamp": 1_700_000_000.5,
        "length": 74,
        "raw": b"\x00\x01\x02\x03",
        "protocol": "TCP",
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "src_port": 51844,
        "dst_port": 443,
        "summary": "51844 → 443 [SYN]",
    }
    base.update(overrides)
    return PacketInfo(**base)  # type: ignore[arg-type]


# --- 时间格式 ---------------------------------------------------------------


def test_format_timestamp_is_readable_clock_time() -> None:
    assert re.fullmatch(r"\d{2}:\d{2}:\d{2}\.\d{3}", vm.format_timestamp(1_700_000_000.5))


def test_format_timestamp_rounds_millis_without_overflow() -> None:
    """0.9996 秒必须进位成下一秒的 .000，而不是产出 1000 毫秒。"""
    stamp = vm.format_timestamp(1_700_000_000.9996)
    assert stamp.endswith(".000")
    assert vm.format_timestamp(1_700_000_001.0).endswith(".000")


def test_format_timestamp_tolerates_junk() -> None:
    assert vm.format_timestamp("abc") == "abc"  # type: ignore[arg-type]


# --- 行构造 -----------------------------------------------------------------


def test_packet_row_uses_formatted_time_and_endpoints() -> None:
    row = vm.packet_row(make_packet())
    assert len(row) == 6
    assert re.fullmatch(r"\d{2}:\d{2}:\d{2}\.\d{3}", row[0])
    assert row[1] == "10.0.0.1:51844"
    assert row[2] == "10.0.0.2:443"
    assert row[3] == "TCP"
    assert row[4] == "74"


def test_packet_row_omits_port_when_absent() -> None:
    row = vm.packet_row(make_packet(src_port=None, dst_port=None))
    assert row[1] == "10.0.0.1"
    assert row[2] == "10.0.0.2"


def test_alert_row_exposes_severity_label_and_source() -> None:
    alert = Alert(
        timestamp=1.0,
        msg="疑似暴力破解",
        protocol="TCP",
        src="10.0.0.1",
        dst="10.0.0.2",
        src_port=20000,
        dst_port=22,
        summary="x",
        kind="anomaly",
        severity="high",
        rule_id="brute-force",
    )
    row = vm.alert_row(alert)
    assert row[1] == "高"
    assert row[2] == "brute-force"
    assert row[3] == "疑似暴力破解"
    assert "10.0.0.1:20000" in row[4]


def test_alert_row_labels_rule_hits_distinctly() -> None:
    alert = Alert(
        timestamp=1.0,
        msg="命中规则",
        protocol="HTTP",
        src="a",
        dst="b",
        src_port=1,
        dst_port=80,
        summary="x",
    )
    assert vm.alert_row(alert)[2] == "IDS 规则"


def test_alert_detail_text_is_multiline_summary() -> None:
    alert = Alert(
        timestamp=1.0,
        msg="m",
        protocol="TCP",
        src="a",
        dst="b",
        src_port=1,
        dst_port=2,
        summary="s",
        severity="low",
    )
    text = vm.alert_detail_text(alert)
    assert text.count("\n") == 4
    assert "低" in text


# --- 解析树 -----------------------------------------------------------------


def test_detail_tree_orders_layers_from_link_to_application() -> None:
    packet = make_packet(
        ethernet={"src_mac": "aa:bb:cc:dd:ee:ff", "dst_mac": "11:22:33:44:55:66", "ethertype": 2048},
        ip={"version": 4, "ihl": 5, "ttl": 64, "protocol": 6, "src": "10.0.0.1", "dst": "10.0.0.2"},
        tcp={"src_port": 51844, "dst_port": 443, "flags": ["SYN"], "window": 64240},
        http={"type": "request", "method": "GET", "target": "/", "version": "HTTP/1.1", "headers": {"host": "x"}},
    )
    labels = [node.label for node in vm.build_detail_tree(packet)]
    assert labels == ["帧信息", "Ethernet II", "IPv4", "TCP", "HTTP"]


def test_detail_tree_always_has_frame_group() -> None:
    labels = [node.label for node in vm.build_detail_tree(make_packet())]
    assert labels[0] == "帧信息"


def test_detail_tree_includes_summary_when_present() -> None:
    frame = vm.build_detail_tree(make_packet(summary="hello"))[0]
    assert ("摘要", "hello") in [(child.label, child.value) for child in frame.children]


def test_detail_tree_reports_parse_issues_last() -> None:
    packet = make_packet(issues=[ParseIssue(layer="tcp", message="选项截断")])
    nodes = vm.build_detail_tree(packet)
    assert nodes[-1].label.startswith("解析问题")
    assert nodes[-1].children[0].kind == "problem"
    assert nodes[-1].children[0].value == "选项截断"


def test_detail_tree_decodes_protocol_and_dns_type_names() -> None:
    packet = make_packet(
        ip={"protocol": 17},
        dns={"transaction_id": 0x1A2B, "queries": [{"name": "a.example", "type": 28, "class": 1}]},
    )
    ip_node = next(node for node in vm.build_detail_tree(packet) if node.label == "IPv4")
    assert any(child.value == "UDP (17)" for child in ip_node.children)
    dns_node = next(node for node in vm.build_detail_tree(packet) if node.label == "DNS")
    query_group = dns_node.children[-1]
    assert query_group.children[0].value.startswith("类型 AAAA (28)")


def test_detail_tree_http_response_shows_status() -> None:
    packet = make_packet(
        protocol="HTTP",
        http={"type": "response", "version": "HTTP/1.1", "status": "200 OK", "headers": {}},
    )
    http_node = next(node for node in vm.build_detail_tree(packet) if node.label == "HTTP")
    values = {child.label: child.value for child in http_node.children}
    assert values["类型"] == "响应"
    assert values["状态码"] == "200 OK"


def test_format_packet_text_contains_every_layer() -> None:
    packet = make_packet(ip={"version": 4, "ttl": 64}, tcp={"src_port": 1, "dst_port": 2})
    text = vm._format_packet(packet)
    assert "摘要：" in text
    assert "IPv4" in text
    assert "TCP" in text


# --- 十六进制视图 -----------------------------------------------------------


def test_hex_rows_splits_offset_bytes_and_ascii() -> None:
    # 16 字节一行；18 字节的请求行因此跨两行
    rows = vm.hex_rows(b"GET / HTTP/1.1\r\n\r\n")
    assert [row[0] for row in rows] == ["00000000", "00000010"]
    offset, hex_text, ascii_text = rows[0]
    assert offset == "00000000"
    assert hex_text.startswith("47 45 54 20 2f 20 48 54")
    # 第 8 字节后应有一个视觉间隙
    assert "  " in hex_text
    assert ascii_text == "GET / HTTP/1.1.."
    assert rows[1][2] == ".."


def test_hex_rows_masks_non_printable_ascii() -> None:
    rows = vm.hex_rows(bytes([0x00, 0x1F, 0x41, 0x7F, 0x80]))
    assert rows[0][2] == "..A.."


def test_hex_rows_wraps_long_input() -> None:
    rows = vm.hex_rows(bytes(40), width=16)
    assert [row[0] for row in rows] == ["00000000", "00000010", "00000020"]


def test_hex_rows_handles_empty_input() -> None:
    assert vm.hex_rows(b"") == []


# --- 搜索文本 ---------------------------------------------------------------


def test_search_text_matches_protocol_hosts_and_ports() -> None:
    text = vm._search_text(make_packet())
    for needle in ("tcp", "10.0.0.1", "51844", "443", "syn"):
        assert needle in text
