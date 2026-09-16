"""生成用于离线演示与端到端测试的示例 pcap。

为什么要单独一个脚本，而不是提交一个二进制 .pcap：
- 样本内容可读、可 review、可增量修改（二进制 diff 无从审查）；
- 样本的可复现性不依赖某个人的机器（同一脚本在任何平台产出同样字节）；
- 包构造复用 ``netguard.trafficgen`` 的公开构造器，与 GUI"测试发包"同源，
  不存在两套包构造逻辑各自漂移的问题。

用法::

    # 写到默认位置（docs/samples/sample.pcap）
    python scripts/build_sample_pcap.py

    # 写到指定文件
    python scripts/build_sample_pcap.py --output /tmp/demo.pcap

    # 只看将生成哪些场景，不写文件
    python scripts/build_sample_pcap.py --list

产物包含四个场景，覆盖手工演示常用的界面元素：

===== ==================== ==========================================
序号   场景                 对应现象
===== ==================== ==========================================
1     正常混合流量         包列表出现 HTTP/DNS/TCP/UDP/ICMP，协议列有内容
2     端口扫描             检测器报"端口扫描"告警
3     SYN flood            检测器报"SYN flood"告警
4     畸形包               解析问题面板出现截断/无效字段条目
===== ==================== ==========================================

配合内置规则（``netguard.rules.engine.DEFAULT_RULES``，仅含一条 HTTP GET 规则）
可命中 HTTP GET 内容规则告警；如需 DNS 规则告警，用 ``--rules`` 自行加载。
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from netguard.capture.pcap import RawPacket  # noqa: E402
from netguard.capture.pcap_file import write_pcap  # noqa: E402
from netguard.trafficgen import (  # noqa: E402
    TEMPLATES,
    build_ethernet,
    build_ipv4,
    build_tcp,
)

DEFAULT_OUTPUT = ROOT / "docs" / "samples" / "sample.pcap"

#: 样本起始时间戳，取一个固定值以保证输出可复现
BASE_TIMESTAMP = 1_700_000_000.0


@dataclass(frozen=True)
class Scenario:
    """一个可独立命名的样本片段。"""

    name: str
    description: str


#: 场景清单，同时作为 --list 的输出来源
SCENARIOS: tuple[Scenario, ...] = (
    Scenario("normal", "正常混合流量：各协议模板各若干包"),
    Scenario("port-scan", "端口扫描：同一源在窗口内访问 40 个不同目的端口"),
    Scenario("syn-flood", "SYN flood：窗口内 150 个 SYN 发往同一 (目的 IP, 端口)"),
    Scenario("malformed", "畸形包：截断与无效字段，用于展示解析问题面板"),
)

#: 端口扫描的源端口基数与目的端口范围，与 detection 默认阈值（10s / 20 端口）兼容
_SCAN_SRC_BASE = 40_000
_SCAN_PORT_START = 20
_SCAN_PORT_COUNT = 40
_SCAN_INTERVAL = 0.05

#: SYN flood 规模，与 detection 默认阈值（5s / 100）兼容
_FLOOD_COUNT = 150
_FLOOD_INTERVAL = 0.02
_FLOOD_DST_PORT = 80

#: 每个场景之间插入的时间间隔，避免跨场景误触发窗口型检测器
_SCENARIO_GAP = 12.0


def _build_quiet(seconds: float, start: float) -> list[RawPacket]:
    """生成一段正常流量，``seconds`` 内均匀铺开。"""
    normal = [template for template in TEMPLATES if template.category == "normal"]
    packets: list[RawPacket] = []
    step = seconds / len(normal)
    for index, template in enumerate(normal):
        data = template.build()
        packets.append(RawPacket(start + index * step, data, len(data), len(data)))
    return packets


def _build_port_scan(start: float) -> list[RawPacket]:
    """同一源端口族扫描 40 个连续目的端口，触发 PortScanDetector。"""
    packets: list[RawPacket] = []
    for offset in range(_SCAN_PORT_COUNT):
        port = _SCAN_PORT_START + offset
        segment = build_tcp(b"", src_port=_SCAN_SRC_BASE + offset, dst_port=port, flags=0x02)
        data = build_ethernet(build_ipv4(segment))
        packets.append(RawPacket(start + offset * _SCAN_INTERVAL, data, len(data), len(data)))
    return packets


def _build_syn_flood(start: float) -> list[RawPacket]:
    """150 个 SYN 发往同一 (目的 IP, 端口)，触发 SynFloodDetector。"""
    packets: list[RawPacket] = []
    for index in range(_FLOOD_COUNT):
        segment = build_tcp(
            b"",
            src_port=30_000 + (index % 500),
            dst_port=_FLOOD_DST_PORT,
            flags=0x02,
        )
        data = build_ethernet(build_ipv4(segment))
        packets.append(RawPacket(start + index * _FLOOD_INTERVAL, data, len(data), len(data)))
    return packets


def _build_malformed(start: float) -> list[RawPacket]:
    """畸形与截断包，用于展示解析问题面板。"""
    abnormal = [template for template in TEMPLATES if template.category == "abnormal"]
    packets: list[RawPacket] = []
    for index, template in enumerate(abnormal):
        data = template.build()
        packets.append(RawPacket(start + index * 0.01, data, len(data), len(data)))
    return packets


def build_sample_packets() -> list[RawPacket]:
    """按场景顺序构造完整样本，返回按时间升序的包列表。"""
    packets: list[RawPacket] = []
    cursor = BASE_TIMESTAMP

    packets.extend(_build_quiet(3.0, cursor))
    cursor += 3.0 + _SCENARIO_GAP

    packets.extend(_build_port_scan(cursor))
    cursor += _SCAN_PORT_COUNT * _SCAN_INTERVAL + _SCENARIO_GAP

    packets.extend(_build_syn_flood(cursor))
    cursor += _FLOOD_COUNT * _FLOOD_INTERVAL + _SCENARIO_GAP

    packets.extend(_build_malformed(cursor))

    packets.sort(key=lambda packet: packet.timestamp)
    return packets


def build_sample(path: str | Path, *, quiet: bool = False) -> int:
    """把样本写入 ``path``，返回写入的包数。"""
    packets = build_sample_packets()
    count = write_pcap(path, packets)
    if not quiet:
        print(f"已写入 {count} 个数据包到 {path}")
        print(f"  时间段：{packets[0].timestamp:.3f} ~ {packets[-1].timestamp:.3f}")
        for scenario in SCENARIOS:
            print(f"  {scenario.name:12} {scenario.description}")
        print("\n预览方式：")
        print(f"  python main.py --read {path}")
        print(f"  python main.py --read {path} --alerts-json alerts.json")
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="生成 NetGuard 示例 pcap（离线演示 / 端到端测试）")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help=f"输出路径（默认 {DEFAULT_OUTPUT}）")
    parser.add_argument("--list", action="store_true", help="仅列出场景，不写文件")
    args = parser.parse_args(argv)

    if args.list:
        for scenario in SCENARIOS:
            print(f"{scenario.name:12} {scenario.description}")
        return 0

    output = Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    build_sample(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
