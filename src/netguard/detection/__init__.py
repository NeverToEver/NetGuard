"""基于流量统计的攻击检测器（跨包时间窗口）。

与 rules 包的静态单包匹配不同，这里检测 SYN flood、端口扫描、DNS 隧道等
需要时间窗口才能判定的行为，作为规则引擎的补充。
"""

from __future__ import annotations

from netguard.clock import Clock
from netguard.detection.base import BaseDetector, Detector
from netguard.detection.detectors import (
    BruteForceDetector,
    DnsTunnelDetector,
    IcmpFloodDetector,
    PortScanDetector,
    SynFloodDetector,
)

__all__ = [
    "BaseDetector",
    "BruteForceDetector",
    "Detector",
    "DnsTunnelDetector",
    "IcmpFloodDetector",
    "PortScanDetector",
    "SynFloodDetector",
    "build_default_detectors",
]

#: 每个检测器的构造参数，便于集中调整阈值。
DEFAULT_DETECTOR_CONFIG: dict[str, dict[str, float | int]] = {
    "syn-flood": {"window_seconds": 5.0, "threshold": 100},
    "port-scan": {"window_seconds": 10.0, "threshold": 20},
    "dns-tunnel": {"window_seconds": 10.0, "rate_threshold": 50},
    "icmp-flood": {"window_seconds": 5.0, "threshold": 100},
    "brute-force": {"window_seconds": 60.0, "threshold": 10},
}


def build_default_detectors(
    clock: Clock,
    overrides: dict[str, dict[str, float | int]] | None = None,
) -> list[Detector]:
    """构造默认启用的检测器集合；``overrides`` 可覆盖默认窗口/阈值。"""
    config = {name: dict(values) for name, values in DEFAULT_DETECTOR_CONFIG.items()}
    for name, values in (overrides or {}).items():
        config.setdefault(name, {}).update(values)
    return [
        SynFloodDetector(clock, **config["syn-flood"]),
        PortScanDetector(clock, **config["port-scan"]),
        DnsTunnelDetector(clock, **config["dns-tunnel"]),
        IcmpFloodDetector(clock, **config["icmp-flood"]),
        BruteForceDetector(clock, **config["brute-force"]),
    ]
