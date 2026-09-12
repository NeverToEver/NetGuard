from __future__ import annotations

import threading

from netguard.discovery import subnet as subnet_mod
from netguard.discovery.subnet import (
    HostInfo,
    _windows_device_matches,
    resolve_hosts,
)


def test_windows_device_match_is_one_directional():
    sections = [
        "Windows IP 配置\n\n以太网适配器 以太网:\n\n   连接特定的 DNS 后缀 . . . . . . . . :\n"
        "   IPv4 地址 . . . . . . . . . . . . : 192.168.1.10\n   子网掩码  . . . . . . . . . . . . : 255.255.255.0",
        "以太网适配器 以太网 2:\n\n   IPv4 地址 . . . . . . . . . . . . : 10.0.0.5\n   子网掩码  . . . . . . . . . . . . : 255.255.255.0",
    ]
    # 候选 "以太网 2" 只应匹配自己的 section，不再反向匹配到 "以太网"
    assert _windows_device_matches(sections[1], "以太网 2")
    assert not _windows_device_matches(sections[0], "以太网 2")
    assert _windows_device_matches(sections[0], "以太网")
    # 过短别名不参与匹配
    assert not _windows_device_matches(sections[0], "-a")


def test_resolve_hosts_cancel_prevents_queued_work():
    """取消后未开始的解析任务被撤销，函数尽快返回。"""
    cancel = threading.Event()
    cancel.set()
    result = resolve_hosts([f"10.0.0.{i}" for i in range(1, 50)], cancel_event=cancel)
    assert result == {}


def test_resolve_hosts_collects_results():
    import concurrent.futures

    original = subnet_mod.resolve_host
    subnet_mod.resolve_host = lambda ip, timeout=2.0: HostInfo(ip=ip, hostname=f"host-{ip}")
    try:
        result = subnet_mod.resolve_hosts(["10.0.0.1", "10.0.0.2"], max_workers=2)
    finally:
        subnet_mod.resolve_host = original
    assert result["10.0.0.1"].hostname == "host-10.0.0.1"
    assert result["10.0.0.2"].hostname == "host-10.0.0.2"


def test_ping_host_requires_echo_signature(monkeypatch):
    """退出码 0 但输出是网关 unreachable 时判定不可达。"""
    real_run = subnet_mod.subprocess.run

    class FakeProc:
        def __init__(self, returncode, stdout):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = b""

    def fake_run_unreachable(cmd, **kwargs):
        if cmd and cmd[0] != "ping":
            return real_run(cmd, **kwargs)
        return FakeProc(0, b"Reply from 192.168.1.1: Destination host unreachable.")

    monkeypatch.setattr(subnet_mod.subprocess, "run", fake_run_unreachable)
    assert subnet_mod.ping_host("10.0.0.99") is False

    def fake_run_ok(cmd, **kwargs):
        if cmd and cmd[0] != "ping":
            return real_run(cmd, **kwargs)
        return FakeProc(0, b"Reply from 10.0.0.99: bytes=32 time=1ms TTL=64")

    monkeypatch.setattr(subnet_mod.subprocess, "run", fake_run_ok)
    assert subnet_mod.ping_host("10.0.0.99") is True


def test_detect_unix_subnets_falls_back_when_ifconfig_fails(monkeypatch):
    class FakeProc:
        def __init__(self, returncode, stdout):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = b""

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd[0])
        if cmd[0] == "ifconfig":
            return FakeProc(1, b"")
        return FakeProc(0, b"inet 10.1.2.3/24 brd 10.1.2.255 scope global eth0")

    monkeypatch.setattr(subnet_mod.subprocess, "run", fake_run)
    subnets = subnet_mod._detect_unix_subnets("eth0")
    assert "ifconfig" in calls and "ip" in calls
    assert len(subnets) == 1
    assert subnets[0].cidr == "10.1.2.0/24"


def test_detect_unix_subnets_rejects_dash_interface(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise AssertionError("不应执行命令")

    monkeypatch.setattr(subnet_mod.subprocess, "run", fake_run)
    assert subnet_mod._detect_unix_subnets("-iface") == []
