#!/usr/bin/env python3
"""NetGuard 性能与检测能力基准测试。

用合成流量（复用 netguard.trafficgen 的模板）测量：
  1. 协议解析吞吐（包/秒、字节/秒）
  2. 端到端流水线吞吐（含会话重组 + 规则匹配 + 检测器）
  3. 规则匹配延迟（单包，µs）
  4. 内存占用（处理大量数据包前后的 RSS 增量）
  5. 检测能力：对合成攻击场景的检出率与对正常流量的误报率

用法：
    python scripts/benchmark.py            # 默认规模
    python scripts/benchmark.py --packets 200000
    python scripts/benchmark.py --json out.json

结果同时打印到 stdout，并在 --markdown 时输出可粘贴到 README 的表格。
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from netguard.capture.pcap import RawPacket  # noqa: E402
from netguard.detection import (  # noqa: E402
    DnsTunnelDetector,
    PortScanDetector,
    SynFloodDetector,
)
from netguard.parser.packet import parse_packet  # noqa: E402
from netguard.rules.engine import RuleEngine  # noqa: E402
from netguard.trafficgen import (  # noqa: E402
    TEMPLATES,
    build_ethernet,
    build_ipv4,
    build_tcp,
    build_udp,
)


class ManualClock:
    """可手动推进的时钟，确保检测器窗口行为可复现。"""

    def __init__(self, value: float = 1_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _normal_templates():
    return [t for t in TEMPLATES if t.category == "normal"]


def _rss_bytes() -> int | None:
    try:
        import resource  # type: ignore

        # ru_maxrss 单位因平台而异：Linux 是 KB，macOS 是字节（getrusage(2)）。
        # 注意它是进程峰值而非当前值，"处理前后差值" 只在峰值未抬高时有意义。
        ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return ru * 1024 if sys.platform != "darwin" else ru
    except Exception:
        pass
    try:
        import ctypes
        import ctypes.wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.wintypes.DWORD),
                ("PageFaultCount", ctypes.wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.windll.kernel32
        kernel32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
        handle = kernel32.GetCurrentProcess()
        psapi = ctypes.windll.psapi
        psapi.GetProcessMemoryInfo.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            ctypes.wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = ctypes.wintypes.BOOL
        if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return int(counters.WorkingSetSize)
        return None
    except Exception:
        return None


def _fmt_bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(value) < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def bench_parse(packet_bytes: list[bytes], repeats: int) -> dict:
    start = time.perf_counter()
    for _ in range(repeats):
        for data in packet_bytes:
            parse_packet(data, timestamp=1.0, original_length=len(data))
    elapsed = time.perf_counter() - start
    count = len(packet_bytes) * repeats
    total_bytes = sum(len(d) for d in packet_bytes) * repeats
    return {
        "packets": count,
        "seconds": elapsed,
        "packets_per_second": count / elapsed,
        "bytes_per_second": total_bytes / elapsed,
        "us_per_packet": elapsed / count * 1e6,
    }


def bench_pipeline(processor, packet_bytes: list[bytes], repeats: int) -> dict:
    from netguard.capture.pcap import RawPacket as RP

    packets = [RP(1.0 + i * 1e-6, d, len(d), len(d)) for i, d in enumerate(packet_bytes)]
    start = time.perf_counter()
    for _ in range(repeats):
        for raw in packets:
            processor.process(raw)
    elapsed = time.perf_counter() - start
    count = len(packets) * repeats
    total_bytes = sum(len(d) for d in packet_bytes) * repeats
    return {
        "packets": count,
        "seconds": elapsed,
        "packets_per_second": count / elapsed,
        "bytes_per_second": total_bytes / elapsed,
    }


def bench_rule_match(engine: RuleEngine, packet_bytes: list[bytes], repeats: int) -> dict:
    packets = [parse_packet(d, timestamp=1.0) for d in packet_bytes]
    latencies: list[float] = []
    start = time.perf_counter()
    for _ in range(repeats):
        for pkt in packets:
            t = time.perf_counter()
            engine.match(pkt)
            latencies.append(time.perf_counter() - t)
    elapsed = time.perf_counter() - start
    return {
        "packets": len(packets) * repeats,
        "seconds": elapsed,
        "mean_us": statistics.mean(latencies) * 1e6,
        "median_us": statistics.median(latencies) * 1e6,
        "p99_us": sorted(latencies)[int(len(latencies) * 0.99)] * 1e6,
    }


# --- 检测能力评估 ---------------------------------------------------------


def _syn_packet(src_port: int, dst_port: int) -> bytes:
    """构造一个 Ethernet/IPv4/TCP SYN 帧（复用 trafficgen 的公开构造器）。"""
    return build_ethernet(build_ipv4(build_tcp(b"", src_port=src_port, dst_port=dst_port, flags=0x02)))


def _dns_query_packet(payload: bytes) -> bytes:
    """构造一个 Ethernet/IPv4/UDP/53 帧。"""
    return build_ethernet(build_ipv4(build_udp(payload), proto=17))


def eval_syn_flood() -> dict:
    clock = ManualClock()
    detector = SynFloodDetector(clock, window_seconds=5.0, threshold=100)
    raw = _syn_packet(40000, 80)
    detected = False
    for i in range(150):
        pkt = parse_packet(raw, timestamp=float(i) * 0.01)
        if detector.observe(pkt):
            detected = True
            break
    return {"scenario": "SYN flood (150 SYN/5s, threshold 100)", "detected": detected}


def eval_port_scan() -> dict:
    clock = ManualClock()
    detector = PortScanDetector(clock, window_seconds=10.0, threshold=20)
    detected = False
    for port in range(1, 40):
        pkt = parse_packet(_syn_packet(40000 + port, port), timestamp=float(port) * 0.01)
        if detector.observe(pkt):
            detected = True
            break
    return {"scenario": "Port scan (40 ports/10s, threshold 20)", "detected": detected}


def eval_dns_tunnel() -> dict:
    clock = ManualClock()
    detector = DnsTunnelDetector(clock, window_seconds=10.0, rate_threshold=20)
    detected = False
    for i in range(60):
        label = os.urandom(24).hex()
        qname = f"{label}.tunnel.example.com"
        name = b"".join(bytes([len(part)]) + part.encode() for part in qname.split(".")) + b"\x00"
        payload = struct.pack("!HHHHHH", i, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
        pkt = parse_packet(_dns_query_packet(payload), timestamp=float(i) * 0.01)
        if detector.observe(pkt):
            detected = True
            break
    return {"scenario": "DNS tunnel (60 long-name queries/10s, threshold 20)", "detected": detected}


def eval_false_positives(normal_bytes: list[bytes]) -> dict:
    """正常流量跑全部检测器，统计误报包数。"""
    clock = ManualClock()
    detectors = [
        SynFloodDetector(clock, window_seconds=5.0, threshold=100),
        PortScanDetector(clock, window_seconds=10.0, threshold=20),
        DnsTunnelDetector(clock, window_seconds=10.0, rate_threshold=20),
    ]
    false_alerts = 0
    for i, data in enumerate(normal_bytes):
        pkt = parse_packet(data, timestamp=float(i) * 0.001)
        for detector in detectors:
            false_alerts += len(detector.observe(pkt))
    total = len(normal_bytes)
    return {
        "packets": total,
        "false_alerts": false_alerts,
        "false_positive_rate": false_alerts / total if total else 0.0,
    }


def _reconfigure_streams() -> None:
    """Windows 控制台重定向到管道时是 ANSI 代码页（如 cp1252），中文输出会抛
    UnicodeEncodeError；放宽编码避免基准报告本身中断。"""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def main() -> int:
    _reconfigure_streams()
    parser = argparse.ArgumentParser(description="NetGuard benchmark")
    parser.add_argument("--packets", type=int, default=100_000, help="解析/流水线基准的包数量")
    parser.add_argument("--rules", type=int, default=200, help="规则匹配基准加载的规则条数")
    parser.add_argument("--json", metavar="FILE", help="将结果写入 JSON 文件")
    parser.add_argument("--markdown", action="store_true", help="额外输出 Markdown 表格")
    parser.add_argument(
        "--fail-on-miss",
        action="store_true",
        help="检测场景未命中或误报率异常时返回非 0 退出码（用于 CI 回归门禁）",
    )
    args = parser.parse_args()

    templates = _normal_templates()
    builders = [t.build for t in templates]
    packet_bytes = [builders[i % len(builders)]() for i in range(1000)]

    print("NetGuard benchmark")
    print(f"  Python {sys.version.split()[0]} / {sys.platform}")
    print(f"  合成模板 {len(templates)} 个")
    print()

    results: dict[str, object] = {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "templates": len(templates),
    }

    # 1. 解析
    parse_repeats = max(1, args.packets // len(packet_bytes))
    print(f"[1/5] 协议解析（{len(packet_bytes) * parse_repeats:,} 包）...")
    parse_result = bench_parse(packet_bytes, parse_repeats)
    results["parse"] = parse_result
    print(
        f"      {parse_result['packets_per_second']:>12,.0f} 包/秒   "
        f"{_fmt_bytes(parse_result['bytes_per_second']):>10}/秒   "
        f"{parse_result['us_per_packet']:.2f} µs/包"
    )

    # 2. 流水线（解析+会话+规则+检测）
    print(f"[2/5] 端到端流水线（{len(packet_bytes) * parse_repeats:,} 包）...")
    from netguard.processing import PacketProcessor

    processor = PacketProcessor()
    processor.load_rules(_default_rules())
    pipeline_result = bench_pipeline(processor, packet_bytes, parse_repeats)
    results["pipeline"] = pipeline_result
    print(
        f"      {pipeline_result['packets_per_second']:>12,.0f} 包/秒   "
        f"{_fmt_bytes(pipeline_result['bytes_per_second']):>10}/秒"
    )

    # 3. 规则匹配延迟
    rule_count = args.rules
    rules = _synthetic_rules(rule_count)
    engine = RuleEngine(rules)
    print(f"[3/5] 规则匹配延迟（{rule_count} 条规则）...")
    match_result = bench_rule_match(engine, packet_bytes, max(50, parse_repeats // 4))
    results["rule_match"] = match_result
    print(
        f"      平均 {match_result['mean_us']:.2f} µs   中位 {match_result['median_us']:.2f} µs   "
        f"P99 {match_result['p99_us']:.2f} µs"
    )

    # 4. 内存
    print("[4/5] 内存占用...")
    rss_before = _rss_bytes()
    processor2 = PacketProcessor()
    packets = [
        RawPacket(
            1.0 + i * 1e-6,
            packet_bytes[i % len(packet_bytes)],
            len(packet_bytes[i % len(packet_bytes)]),
            len(packet_bytes[i % len(packet_bytes)]),
        )
        for i in range(max(10_000, args.packets // 4))
    ]
    for raw in packets:
        processor2.process(raw)
    rss_after = _rss_bytes()
    rss_delta = (rss_after - rss_before) if (rss_before and rss_after) else None
    results["memory"] = {
        "rss_before": rss_before,
        "rss_after": rss_after,
        "rss_delta": rss_delta,
        "packets": len(packets),
    }
    if rss_delta is not None:
        print(f"      处理 {len(packets):,} 包，RSS 增量 {_fmt_bytes(rss_delta)}")
    else:
        print("      （当前平台无法读取 RSS，已跳过）")

    # 5. 检测能力
    print("[5/5] 检测能力评估...")
    detection = [
        eval_syn_flood(),
        eval_port_scan(),
        eval_dns_tunnel(),
    ]
    fp = eval_false_positives(packet_bytes)
    results["detection"] = detection
    results["false_positive"] = fp
    for item in detection:
        mark = "命中" if item["detected"] else "未命中"
        print(f"      [{mark}] {item['scenario']}")
    print(
        f"      正常流量误报：{fp['false_alerts']} / {fp['packets']} 包 （FPR {fp['false_positive_rate'] * 100:.3f}%）"
    )

    if args.json:
        Path(args.json).write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n结果已写入 {args.json}")

    if args.markdown:
        print("\n<!-- benchmark 结果 -->")
        print("| 项目 | 结果 |")
        print("|---|---|")
        parse_rate = f"{parse_result['packets_per_second']:,.0f} 包/秒"
        parse_bytes = _fmt_bytes(parse_result["bytes_per_second"])
        print(f"| 协议解析吞吐 | {parse_rate}（{parse_bytes}/s） |")
        print(f"| 端到端流水线 | {pipeline_result['packets_per_second']:,.0f} 包/秒 |")
        print(f"| 单包解析耗时 | {parse_result['us_per_packet']:.2f} µs |")
        match_median = match_result["median_us"]
        match_p99 = match_result["p99_us"]
        print(f"| 规则匹配（{rule_count} 条） | 中位 {match_median:.2f} µs，P99 {match_p99:.2f} µs |")
        if rss_delta is not None:
            print(f"| 内存增量（{len(packets):,} 包） | {_fmt_bytes(rss_delta)} |")
        hits = sum(1 for d in detection if d["detected"])
        print(f"| 攻击场景检出 | {hits}/{len(detection)} |")
        print(f"| 正常流量误报率 | {fp['false_positive_rate'] * 100:.3f}% |")

    if args.fail_on_miss:
        missed = [d["scenario"] for d in detection if not d["detected"]]
        if missed:
            print(f"检测未命中：{', '.join(missed)}", file=sys.stderr)
            return 1
        if fp["false_positive_rate"] > 0.05:
            print(f"误报率异常：{fp['false_positive_rate'] * 100:.3f}% > 5%", file=sys.stderr)
            return 1
    return 0


def _default_rules() -> str:
    from netguard.rules.engine import DEFAULT_RULES

    return DEFAULT_RULES


def _synthetic_rules(count: int) -> list[str]:
    rules = [_default_rules()]
    for i in range(max(0, count - 1)):
        port = 1000 + (i % 500)
        rules.append(f'alert tcp any any -> any {port} (content "marker{i}"; msg "rule {i}";)')
    return rules


if __name__ == "__main__":
    raise SystemExit(main())
