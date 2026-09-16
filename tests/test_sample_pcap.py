"""示例 pcap 生成与端到端检出。

``scripts/build_sample_pcap.py`` 产出的样本是离线演示的正式资产：README 与
文档都引用它。本用例守住两件事：

1. 生成过程可复现且不报错（换机器/换平台产出同样的包序列）；
2. 样本确实能触发文档中宣称的检测行为——样本若失效，演示即失效，
   而 .pcap 是二进制，只有测试能保证它没悄悄变坏。
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_sample_pcap.py"
SAMPLE = ROOT / "docs" / "samples" / "sample.pcap"

if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from netguard.capture.pcap_file import read_pcap  # noqa: E402
from netguard.processing import PacketProcessor  # noqa: E402

#: 样本时间戳是历史固定值；用墙钟会让检测器的时间窗判定失效
SAMPLE_EPOCH = 1_700_000_000.0


class FrozenClock:
    """固定时钟，满足 Clock 协议（可调用，返回 float）。"""

    def __init__(self, value: float = SAMPLE_EPOCH) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _load_builder():
    spec = importlib.util.spec_from_file_location("netguard_build_sample", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    # 必须先注册到 sys.modules：脚本内含 @dataclass，dataclasses 会回查
    # sys.modules[cls.__module__] 来解析字段类型，缺失时会抛
    # AttributeError: 'NoneType' object has no attribute '__dict__'
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _collect_alerts(path: Path, rules: str | None = None) -> list[str]:
    """回放样本并收集所有告警文本。"""
    processor = PacketProcessor(clock=FrozenClock())
    if rules is not None:
        processor.load_rules(rules)
    messages: list[str] = []
    for raw in read_pcap(path):
        event = processor.process(raw)
        if event is not None:
            messages.extend(alert.msg for alert in event.alerts)
    return messages


@pytest.fixture(scope="module")
def builder():
    return _load_builder()


def test_sample_script_lists_scenarios(builder, capsys) -> None:
    assert builder.main(["--list"]) == 0
    out = capsys.readouterr().out
    for scenario in ("normal", "port-scan", "syn-flood", "malformed"):
        assert scenario in out


def test_generation_is_reproducible(builder, tmp_path) -> None:
    """同一脚本两次生成必须字节一致（时间戳固定，构造不依赖随机数）。"""
    first = tmp_path / "a.pcap"
    second = tmp_path / "b.pcap"
    builder.build_sample(first, quiet=True)
    builder.build_sample(second, quiet=True)
    assert first.read_bytes() == second.read_bytes()


def test_committed_sample_matches_current_script(builder, tmp_path) -> None:
    """已提交的样本必须与当前脚本的产物一致。

    这是防样本漂移的关键约束：若改了构造逻辑却忘记重新生成
    docs/samples/sample.pcap，仓库里躺着的就是过期样本，而"两次生成一致"
    之类的用例完全检测不到这一点。
    """
    if not SAMPLE.exists():
        pytest.fail(f"缺少样本文件 {SAMPLE}，请运行 python scripts/build_sample_pcap.py")

    fresh = tmp_path / "fresh.pcap"
    builder.build_sample(fresh, quiet=True)
    assert fresh.read_bytes() == SAMPLE.read_bytes(), (
        "docs/samples/sample.pcap 已过期，请重新运行 python scripts/build_sample_pcap.py"
    )


def test_generated_sample_matches_scenario_volume(builder, tmp_path) -> None:
    """包数等于各场景规模之和：正常 15 + 扫描 40 + flood 150 + 畸形 10。"""
    path = tmp_path / "sample.pcap"
    count = builder.build_sample(path, quiet=True)
    assert count == 15 + 40 + 150 + 10

    timestamps = [packet.timestamp for packet in read_pcap(path)]
    assert timestamps == sorted(timestamps), "样本应按时间升序写入"


def test_committed_sample_is_readable_and_parseable() -> None:
    """仓库中提交的样本可被读回，且全部包都能走完处理流水线。

    畸形包不抛异常：解析问题以包级 ``packet.issues`` 记录（契约见
    AGENTS.md「解析不抛异常」），因此 processor.parse_errors 仍为 0。
    """
    if not SAMPLE.exists():
        pytest.fail(f"缺少样本文件 {SAMPLE}，请运行 python scripts/build_sample_pcap.py")

    packets = list(read_pcap(SAMPLE))
    assert packets, "样本不应为空"

    processor = PacketProcessor(clock=FrozenClock())
    issue_count = 0
    for raw in packets:
        event = processor.process(raw)
        assert event is not None
        issue_count += len(event.packet.issues)

    assert issue_count > 0, "样本含畸形包，应产生包级解析问题"
    assert processor.parse_errors == 0, "解析问题不应升级为解析异常"


def test_sample_triggers_documented_detectors() -> None:
    """样本必须检出 SYN flood 与端口扫描——这是文档对样本的承诺。"""
    messages = " ".join(_collect_alerts(SAMPLE))
    lowered = messages.lower()
    assert "syn" in lowered, f"未检出 SYN flood：{messages[:200]}"
    assert "扫描" in messages or "scan" in lowered, f"未检出端口扫描：{messages[:200]}"


def test_sample_hits_default_http_rule() -> None:
    """样本含 HTTP GET，应命中内置规则 DEFAULT_RULES。"""
    from netguard.rules.engine import DEFAULT_RULES

    messages = " ".join(_collect_alerts(SAMPLE, rules=DEFAULT_RULES))
    assert "HTTP" in messages, f"未命中内置 HTTP 规则：{messages[:200]}"
