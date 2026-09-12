from __future__ import annotations

from netguard.parser.packet import PacketInfo
from netguard.rules import RuleEngine
from netguard.session import SessionTracker
from netguard.statistics import TrafficStats


def tcp_packet(
    seq: int = 1,
    payload: bytes = b"",
    flags: list[str] | None = None,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 80,
    timestamp: float = 1.0,
) -> PacketInfo:
    return PacketInfo(
        timestamp=timestamp,
        length=54 + len(payload),
        raw=payload,
        protocol="TCP",
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
        summary="test",
        tcp={"sequence": seq, "flags": flags or ["ACK"], "payload_length": len(payload)},
        payload=payload,
    )


def http_packet(payload: bytes = b"GET / HTTP/1.1\r\n\r\n") -> PacketInfo:
    return PacketInfo(
        timestamp=1.0,
        length=54 + len(payload),
        raw=payload,
        protocol="HTTP",
        src="10.0.0.1",
        dst="10.0.0.2",
        src_port=12345,
        dst_port=80,
        summary="GET / HTTP/1.1",
        http={"method": "GET", "target": "/", "first_line": "GET / HTTP/1.1"},
        payload=payload,
    )


def dns_packet() -> PacketInfo:
    return PacketInfo(
        timestamp=1.0,
        length=100,
        raw=b"",
        protocol="DNS",
        src="10.0.0.1",
        dst="10.0.0.2",
        src_port=53000,
        dst_port=53,
        summary="DNS example.com",
        dns={"queries": [{"name": "example.com"}]},
        payload=b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
    )


# --- Rule engine tests ---

def test_rule_engine_matches_content_and_port() -> None:
    engine = RuleEngine(['alert tcp any any -> any 80 (content "GET"; msg "检测到 HTTP GET 请求";)'])
    alerts = engine.match(tcp_packet(1, b"GET / HTTP/1.1\r\n\r\n"))
    assert len(alerts) == 1
    assert alerts[0].msg == "检测到 HTTP GET 请求"


def test_rule_engine_does_not_match_wrong_content() -> None:
    engine = RuleEngine(['alert tcp any any -> any 80 (content "POST"; msg "检测到 POST 请求";)'])
    assert engine.match(tcp_packet(1, b"GET / HTTP/1.1\r\n\r\n")) == []


def test_rule_engine_any_protocol_matches_tcp() -> None:
    engine = RuleEngine(['alert any any any -> any any (content "GET"; msg "匹配任意协议";)'])
    alerts = engine.match(tcp_packet(1, b"GET / HTTP/1.1\r\n\r\n"))
    assert len(alerts) == 1
    assert alerts[0].msg == "匹配任意协议"


def test_rule_engine_any_protocol_matches_http() -> None:
    engine = RuleEngine(['alert any any any -> any any (content "GET"; msg "匹配 HTTP";)'])
    alerts = engine.match(http_packet(b"GET / HTTP/1.1\r\n\r\n"))
    assert len(alerts) == 1


def test_rule_engine_tcp_rule_matches_http_packet() -> None:
    engine = RuleEngine(['alert tcp any any -> any 80 (content "GET"; msg "TCP 匹配 HTTP";)'])
    alerts = engine.match(http_packet(b"GET / HTTP/1.1\r\n\r\n"))
    assert len(alerts) == 1


def test_rule_engine_dns_rule_matches_dns_packet() -> None:
    engine = RuleEngine(['alert udp any any -> any 53 (msg "DNS 查询";)'])
    alerts = engine.match(dns_packet())
    assert len(alerts) == 1
    assert alerts[0].msg == "DNS 查询"


def test_rule_engine_direction_both_matches() -> None:
    engine = RuleEngine(['alert tcp any any <> any any (content "GET"; msg "双向";)'])
    alerts = engine.match(tcp_packet(1, b"GET / HTTP/1.1\r\n\r\n"))
    assert len(alerts) == 1


def test_rule_engine_source_address_must_match() -> None:
    engine = RuleEngine(['alert tcp 10.0.0.99 any -> any 80 (msg "源地址匹配";)'])

    assert engine.match(tcp_packet(src="10.0.0.1", dst_port=80)) == []


def test_rule_engine_destination_address_must_match() -> None:
    engine = RuleEngine(['alert tcp any any -> 10.0.0.99 80 (msg "目的地址匹配";)'])

    assert engine.match(tcp_packet(dst="10.0.0.2", dst_port=80)) == []


def test_rule_engine_forward_direction_does_not_match_reverse_addresses() -> None:
    engine = RuleEngine(['alert tcp 10.0.0.1 any -> 10.0.0.2 any (msg "单向";)'])

    assert engine.match(tcp_packet(src="10.0.0.2", dst="10.0.0.1")) == []


def test_rule_engine_bidirectional_direction_matches_reverse_addresses() -> None:
    engine = RuleEngine(['alert tcp 10.0.0.1 any <> 10.0.0.2 any (msg "双向";)'])
    alerts = engine.match(tcp_packet(src="10.0.0.2", dst="10.0.0.1"))

    assert len(alerts) == 1


def test_rule_engine_comments_are_ignored() -> None:
    engine = RuleEngine(
        ["# 这是一个注释", 'alert tcp any any -> any 80 (content "GET"; msg "测试";)']
    )
    assert len(engine.rules) == 1


def test_rule_engine_empty_rules_is_safe() -> None:
    engine = RuleEngine([])
    assert engine.match(tcp_packet(1, b"GET")) == []


def test_rule_engine_specific_source_port_matches() -> None:
    engine = RuleEngine(['alert tcp any 12345 -> any any (msg "源端口匹配";)'])
    alerts = engine.match(tcp_packet(src_port=12345))
    assert len(alerts) == 1


def test_rule_engine_specific_source_port_does_not_match() -> None:
    engine = RuleEngine(['alert tcp any 9999 -> any any (msg "不应匹配";)'])
    assert engine.match(tcp_packet(src_port=12345)) == []


def test_rule_engine_content_in_raw_bytes() -> None:
    engine = RuleEngine(['alert tcp any any -> any any (content "secret"; msg "原始匹配";)'])
    pkt = tcp_packet(payload=b"")
    pkt = PacketInfo(
        timestamp=1.0, length=60, raw=b"prefix secret suffix", protocol="TCP",
        src="10.0.0.1", dst="10.0.0.2", src_port=1, dst_port=1,
        summary="test", tcp={"sequence": 1, "flags": ["ACK"], "payload_length": 0},
    )
    alerts = engine.match(pkt)
    assert len(alerts) == 1


def test_rule_engine_malformed_rule_skipped() -> None:
    engine = RuleEngine([
        "garbage line",
        'alert tcp any any -> any 80 (content "GET"; msg "有效规则";)',
        "another bad line without parentheses",
    ])
    assert len(engine.rules) == 1
    assert engine.rules[0].msg == "有效规则"


def test_rule_engine_load_returns_failed_count() -> None:
    engine = RuleEngine()
    failed = engine.load([
        "garbage",
        'alert tcp any any -> any 80 (content "GET"; msg "ok";)',
        "more garbage",
    ])
    assert failed == 2
    assert len(engine.rules) == 1


def test_rule_engine_non_alert_action_is_rejected() -> None:
    engine = RuleEngine()
    failed = engine.load([
        'drop tcp any any -> any 80 (content "GET"; msg "unsupported";)',
        'alert tcp any any -> any 80 (content "GET"; msg "ok";)',
    ])

    assert failed == 1
    assert len(engine.rules) == 1
    assert engine.rules[0].msg == "ok"


def test_rule_engine_parses_semicolon_inside_quoted_option() -> None:
    engine = RuleEngine(['alert tcp any any -> any any (content "alpha;beta"; msg "has;semicolon";)'])
    alerts = engine.match(tcp_packet(payload=b"alpha;beta"))

    assert len(alerts) == 1
    assert alerts[0].msg == "has;semicolon"


# --- Session tracker tests ---

def test_session_tracker_reassembles_out_of_order_fragments() -> None:
    tracker = SessionTracker(timeout_seconds=60)
    tracker.update(tcp_packet(1, b"GET "))
    tracker.update(tcp_packet(9, b"TP/1.1\r\n\r\n"))
    session = tracker.update(tcp_packet(5, b"/ HT"))
    assert session is not None
    assert bytes(session.stream) == b"GET / HTTP/1.1\r\n\r\n"
    assert session.http_events[-1] == "GET / HTTP/1.1"


def test_session_tracker_cleans_closed_sessions() -> None:
    tracker = SessionTracker()
    tracker.update(tcp_packet(1, b"", ["FIN"]))
    assert tracker.sessions == {}


def test_session_tracker_rst_closes_session() -> None:
    tracker = SessionTracker()
    tracker.update(tcp_packet(1, b"hello", ["RST"]))
    assert tracker.sessions == {}


def test_session_tracker_timeout_expires_sessions() -> None:
    tracker = SessionTracker(timeout_seconds=0.01)
    tracker.update(tcp_packet(timestamp=1.0))
    assert len(tracker.sessions) == 1
    tracker.cleanup(now=100.0)
    assert tracker.sessions == {}


def test_session_tracker_cleanup_accepts_zero_timestamp() -> None:
    tracker = SessionTracker(timeout_seconds=0.01, clock=lambda: 100.0)
    tracker.update(tcp_packet(timestamp=0.0))

    tracker.cleanup(now=0.0)

    assert len(tracker.sessions) == 1


def test_session_tracker_duplicate_sequence_is_ignored() -> None:
    tracker = SessionTracker()
    tracker.update(tcp_packet(1, b"hello"))
    tracker.update(tcp_packet(1, b"hello"))
    session = tracker.sessions.get(("10.0.0.1", 12345, "10.0.0.2", 80))
    assert session is not None
    assert session.packets == 2


def test_session_tracker_overlapping_payload_trimmed() -> None:
    tracker = SessionTracker()
    tracker.update(tcp_packet(1, b"abcdef"))
    tracker.update(tcp_packet(4, b"defghi"))
    session = tracker.sessions.get(("10.0.0.1", 12345, "10.0.0.2", 80))
    assert session is not None
    assert bytes(session.stream) == b"abcdefghi"


def test_session_tracker_fragments_limit_evicts_session() -> None:
    tracker = SessionTracker(max_fragments=3)
    # First packet is consumed immediately (seq=100, next_sequence → 110)
    tracker.update(tcp_packet(100, b"x" * 10))
    # Gap packets accumulate fragments
    tracker.update(tcp_packet(200, b"x" * 10))
    tracker.update(tcp_packet(300, b"x" * 10))
    assert len(tracker.sessions) == 1  # 2 fragments stored
    tracker.update(tcp_packet(400, b"x" * 10))  # 3 fragments total → exceeds max_fragments → evicted
    assert len(tracker.sessions) == 0


def test_session_tracker_http_events_capped() -> None:
    tracker = SessionTracker(max_http_events=2)
    for i in range(5):
        pkt = tcp_packet(i * 30, f"GET /page{i} HTTP/1.1\r\n\r\n".encode())
        tracker.update(pkt)
    session = tracker.sessions.get(("10.0.0.1", 12345, "10.0.0.2", 80))
    assert session is not None
    assert len(session.http_events) <= 2


def test_session_tracker_detects_multiple_http_messages_in_one_stream() -> None:
    tracker = SessionTracker()
    first = b"GET /one HTTP/1.1\r\n\r\n"
    second = b"GET /two HTTP/1.1\r\n\r\n"

    session = tracker.update(tcp_packet(1, first + second))

    assert session is not None
    assert session.http_events == ["GET /one HTTP/1.1", "GET /two HTTP/1.1"]


def test_session_tracker_nontcp_returns_none() -> None:
    tracker = SessionTracker()
    pkt = PacketInfo(
        timestamp=1.0, length=60, raw=b"", protocol="UDP",
        src="10.0.0.1", dst="10.0.0.2", src_port=53, dst_port=53,
        summary="dns", udp={"src_port": 53, "dst_port": 53, "length": 8, "checksum": 0},
    )
    assert tracker.update(pkt) is None


def test_session_tracker_stream_truncation() -> None:
    tracker = SessionTracker(max_stream_bytes=10)
    tracker.update(tcp_packet(1, b"0123456789abcdef"))
    session = tracker.sessions.get(("10.0.0.1", 12345, "10.0.0.2", 80))
    assert session is not None
    assert len(session.stream) <= 10
    assert bytes(session.stream) == b"6789abcdef"


def test_session_tracker_max_sessions_evicts_oldest() -> None:
    tracker = SessionTracker(max_sessions=1)
    tracker.update(tcp_packet(timestamp=1.0, src="10.0.0.1", dst="10.0.0.2"))
    tracker.update(tcp_packet(timestamp=2.0, src="10.0.0.3", dst="10.0.0.4"))
    assert len(tracker.sessions) == 1
    remaining = list(tracker.sessions.keys())[0]
    assert remaining[0] == "10.0.0.3"


# --- Traffic stats tests ---

def test_traffic_stats_snapshot() -> None:
    stats = TrafficStats()
    stats.update(tcp_packet(1, b"abc"), active_sessions=2)
    snap = stats.snapshot()
    assert snap.total_packets == 1
    assert snap.total_bytes > 0
    assert snap.protocol_counts["TCP"] == 1
    assert snap.active_sessions == 2


def test_traffic_stats_empty_snapshot() -> None:
    stats = TrafficStats()
    snap = stats.snapshot()
    assert snap.total_packets == 0
    assert snap.total_bytes == 0
    assert snap.packets_per_second == 0.0
    assert snap.bytes_per_second == 0.0


def test_traffic_stats_protocol_counts_accumulate() -> None:
    stats = TrafficStats()
    stats.update(tcp_packet(payload=b"a"), active_sessions=0)
    stats.update(tcp_packet(payload=b"b"), active_sessions=0)
    snap = stats.snapshot()
    assert snap.protocol_counts["TCP"] == 2


def test_traffic_stats_rate_window_expiry() -> None:
    stats = TrafficStats(rate_window_seconds=0.01)
    stats.update(tcp_packet(timestamp=1.0), active_sessions=0)
    stats.update(tcp_packet(timestamp=100.0), active_sessions=0)
    snap = stats.snapshot()
    assert snap.total_packets == 2
    assert snap.packets_per_second <= 1.0


def test_traffic_stats_protocol_counts_capped() -> None:
    stats = TrafficStats(max_protocols=2)
    for proto in ["A", "B", "C", "D"]:
        pkt = PacketInfo(
            timestamp=1.0, length=10, raw=b"", protocol=proto,
            src="1.2.3.4", dst="5.6.7.8", src_port=1, dst_port=2,
            summary="", tcp={"sequence": 1, "flags": ["ACK"], "payload_length": 0},
        )
        stats.update(pkt)
    snap = stats.snapshot()
    assert len(snap.protocol_counts) <= 2


# --- 会话重组流检测（防拆包/分片绕过） ---

def test_stream_match_detects_keyword_split_across_segments() -> None:
    engine = RuleEngine(['alert tcp any any -> any any (content "administrator"; msg "检测到敏感关键字";)'])
    tracker = SessionTracker()

    first = tcp_packet(seq=1, payload=b"admin")
    session = tracker.update(first)
    # 首段载荷不含完整关键字
    assert engine.match(first, stream=session.stream, matched=session.matched_rules) == []

    second = tcp_packet(seq=6, payload=b"istrator")
    session = tracker.update(second)
    alerts = engine.match(second, stream=session.stream, matched=session.matched_rules)

    assert len(alerts) == 1
    assert alerts[0].msg == "检测到敏感关键字"


def test_stream_match_alerts_only_once_per_session() -> None:
    engine = RuleEngine(['alert tcp any any -> any any (content "secret"; msg "检测到 secret";)'])
    tracker = SessionTracker()

    first = tcp_packet(seq=1, payload=b"secret")
    session = tracker.update(first)
    assert len(engine.match(first, stream=session.stream, matched=session.matched_rules)) == 1

    follow_up = tcp_packet(seq=7, payload=b" more data")
    session = tracker.update(follow_up)
    assert engine.match(follow_up, stream=session.stream, matched=session.matched_rules) == []


# --- 回归：规则引擎二级端口索引与会话级 content 去重 ---

def test_port_index_keeps_only_relevant_candidates() -> None:
    rules = [f'alert tcp any any -> any {1000 + i} (msg "r{i}";)' for i in range(200)]
    engine = RuleEngine(rules)
    packet = PacketInfo(
        timestamp=1.0, length=54, raw=b"", protocol="TCP",
        src="10.0.0.1", dst="10.0.0.2", src_port=40000, dst_port=1050,
    )
    # 应只命中 1050 一条，且候选集大幅缩小（内部验证索引生效）
    alerts = engine.match(packet)
    assert len(alerts) == 1
    assert alerts[0].msg == "r50"
    candidates = engine._candidates_for("TCP", packet)
    assert len(candidates) < 10  # 200 条规则里只有 1050 桶命中


def test_port_index_bidirectional_rules_still_match() -> None:
    engine = RuleEngine(['alert tcp any 80 <> any any (msg "bidir";)'])
    packet = PacketInfo(
        timestamp=1.0, length=54, raw=b"", protocol="TCP",
        src="10.0.0.1", dst="10.0.0.2", src_port=40000, dst_port=80,
    )
    assert len(engine.match(packet)) == 1
    reverse = PacketInfo(
        timestamp=1.0, length=54, raw=b"", protocol="TCP",
        src="10.0.0.2", dst="10.0.0.1", src_port=80, dst_port=40000,
    )
    assert len(engine.match(reverse)) == 1


def test_single_packet_content_alerts_deduped_per_session() -> None:
    engine = RuleEngine(['alert tcp any any -> any 80 (content "GET"; msg "http get";)'])
    matched: set[str] = set()

    def make_packet() -> PacketInfo:
        return PacketInfo(
            timestamp=1.0, length=54, raw=b"", protocol="TCP",
            src="10.0.0.1", dst="10.0.0.2", src_port=40000, dst_port=80,
            payload=b"GET / HTTP/1.1\r\n\r\n",
        )

    assert len(engine.match(make_packet(), matched=matched)) == 1
    # 同一会话后续含关键字的包不再重复告警
    assert engine.match(make_packet(), matched=matched) == []


# --- 回归：离线回放（历史时间戳）下的会话清理与速率 ---

def test_stats_snapshot_uses_packet_timeline_for_replay() -> None:
    """回放旧 pcap（包时间戳远早于墙钟）时，速率窗口不被墙钟清空。"""
    class FakeClock:
        def __call__(self) -> float:
            return 1_800_000_000.0  # 墙钟在“未来”

    stats = TrafficStats(clock=FakeClock())
    for i in range(10):
        packet = PacketInfo(timestamp=1_000_000.0 + i * 0.1, length=100, raw=b"", protocol="TCP")
        stats.update(packet)
    # 包时间轴落后墙钟超过窗口宽度时回退到包时间轴：10 包 / 0.9s ≈ 11 pps
    snap = stats.snapshot()
    assert snap.packets_per_second > 0


def test_stats_snapshot_idle_returns_zero_rate() -> None:
    """实时抓包语义：包时间戳等于墙钟，空闲超过窗口后速率归零。"""
    class FakeClock:
        value = 1_000_000.0

        def __call__(self) -> float:
            return self.value

    clock = FakeClock()
    stats = TrafficStats(clock=clock)
    stats.update(PacketInfo(timestamp=None, length=100, raw=b"", protocol="TCP"))
    # 空闲期间 wall-clock 速率归零：通过再打一包把窗口尾推到当前时刻验证
    clock.value += 60.0  # 空闲 60 秒，超过速率窗口
    stats.update(PacketInfo(timestamp=None, length=100, raw=b"", protocol="TCP"))
    snap = stats.snapshot()
    # 旧包（60s 前）已被墙钟基准剔除，窗口只剩刚到的 1 包
    assert snap.total_packets == 2
    assert snap.packets_per_second == 1.0  # 单包窗口 elapsed=1.0 → 1 pps，而非 2/60≈0


def test_session_cleanup_after_fin_uses_packet_timestamp() -> None:
    """离线回放：FIN 触发的清理不能用墙钟，否则全部存活会话被误删。"""
    from netguard.processing import PacketProcessor
    from netguard.capture.pcap import RawPacket
    import struct

    class FakeClock:
        def __call__(self) -> float:
            return 1_800_000_000.0

    processor = PacketProcessor(clock=FakeClock())

    def tcp_frame(src: bytes, dst: bytes, src_port: int, dst_port: int, flags: int) -> bytes:
        tcp = struct.pack("!HHIIHHHH", src_port, dst_port, 1, 0, (5 << 12) | flags, 1024, 0, 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, src, dst)
        return b"\xaa" * 12 + b"\x08\x00" + ip + tcp

    a, b = b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02"
    ts = 1_000_000.0
    # 建立两条会话
    processor.process(RawPacket(ts, tcp_frame(a, b, 40001, 80, 0x02), 54, 54))
    processor.process(RawPacket(ts, tcp_frame(a, b, 40002, 81, 0x02), 54, 54))
    assert len(processor.sessions.sessions) == 2
    # 第一条会话 FIN 关闭
    processor.process(RawPacket(ts + 1, tcp_frame(a, b, 40001, 80, 0x01), 54, 54))
    # 第二条会话必须仍然存活（不能用墙钟判定超时）
    remaining = list(processor.sessions.sessions.keys())
    assert (str(__import__("ipaddress").IPv4Address(a)), 40002,
            str(__import__("ipaddress").IPv4Address(b)), 81) in remaining
