from __future__ import annotations

import ipaddress
import platform
import re
from dataclasses import dataclass, replace

from netguard.capture.pcap import CaptureDevice


@dataclass(frozen=True)
class DeviceDisplay:
    device: CaptureDevice
    display_name: str
    friendly_name: str
    note: str
    ip_addresses: tuple[str, ...] = ()
    subnets: tuple[str, ...] = ()


def build_device_displays(
    devices: list[CaptureDevice],
    system: str | None = None,
) -> list[DeviceDisplay]:
    system_name = (system or platform.system()).lower()
    if system_name == "windows":
        displays = _build_windows_displays(devices)
    else:
        displays = [_build_native_display(device) for device in devices]
    return [_attach_subnets(d) for d in _dedupe_display_names(displays)]


def _dedupe_display_names(displays: list[DeviceDisplay]) -> list[DeviceDisplay]:
    counts: dict[str, int] = {}
    for display in displays:
        counts[display.display_name] = counts.get(display.display_name, 0) + 1
    return [
        replace(display, display_name=f"{display.display_name} - {display.device.name}")
        if counts[display.display_name] > 1
        else display
        for display in displays
    ]


def _attach_subnets(display: DeviceDisplay) -> DeviceDisplay:
    subnets: list[str] = []
    ips = display.ip_addresses
    masks = display.device.netmasks
    for i, ip in enumerate(ips):
        mask = masks[i] if i < len(masks) else "255.255.255.0"
        try:
            iface = ipaddress.IPv4Interface(f"{ip}/{mask}")
            net = iface.network
            subnets.append(f"{net.network_address}/{net.prefixlen}")
        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            continue
    deduped: list[str] = []
    for s in subnets:
        if s not in deduped:
            deduped.append(s)
    return DeviceDisplay(
        device=display.device,
        display_name=display.display_name,
        friendly_name=display.friendly_name,
        note=display.note,
        ip_addresses=display.ip_addresses,
        subnets=tuple(deduped),
    )


def recommend_device_display(displays: list[DeviceDisplay]) -> DeviceDisplay | None:
    if not displays:
        return None
    return max(
        enumerate(displays),
        key=lambda item: (_recommendation_score(item[1]), -item[0]),
    )[1]


def device_recommendation_reason(display: DeviceDisplay) -> str:
    text = _recommendation_text(display)
    if _has_token(text, ("loopback", "回环", "lo0", "lo interface")):
        return "回环接口，只适合本机测试"
    if _has_token(text, ("vpn", "tunnel", "tap", "tun", "utun", "隧道")):
        return "VPN/隧道接口，通常不是实验网段主网卡"
    if _has_token(text, ("virtual", "vmware", "virtualbox", "hyper-v", "docker", "bridge", "veth", "虚拟")):
        return "虚拟网卡，通常不是实验网段主网卡"
    if _has_token(text, ("wi-fi", "wifi", "wireless", "wlan", "802.11", "无线")):
        return "无线网卡，通常连接实验网段"
    if _has_token(text, ("ethernet", "gigabit", "realtek", "intel(r) ethernet", "lan", "有线")):
        return "有线网卡，适合稳定监听实验网段"
    if re.search(r"\b(en|eth|wlan)\d+\b", text):
        return "本机物理接口命名，优先尝试"
    if display.device.description.strip():
        return "带有设备描述，优先于匿名接口"
    return "可用抓包接口"


def _recommendation_score(display: DeviceDisplay) -> int:
    text = _recommendation_text(display)
    score = 0
    if display.device.description.strip():
        score += 8
    if _has_token(text, ("wi-fi", "wifi", "wireless", "wlan", "802.11", "无线")):
        score += 120
    if _has_token(text, ("ethernet", "gigabit", "realtek", "intel(r) ethernet", "lan", "有线")):
        score += 110
    if re.search(r"\b(en|eth|wlan)\d+\b", text):
        score += 70
    if _has_token(text, ("bluetooth", "蓝牙")):
        score -= 50
    if _has_token(text, ("virtual", "vmware", "virtualbox", "hyper-v", "docker", "bridge", "veth", "虚拟")):
        score -= 90
    if _has_token(text, ("vpn", "tunnel", "tap", "tun", "utun", "隧道")):
        score -= 100
    if _has_token(text, ("awdl", "llw", "ap1")):
        score -= 100
    if _has_token(text, ("loopback", "回环", "lo0", "lo interface")):
        score -= 220
    return score


def _recommendation_text(display: DeviceDisplay) -> str:
    return " ".join(
        (
            display.device.name,
            display.device.description,
            display.display_name,
            display.friendly_name,
            display.note,
        )
    ).lower()


def _has_token(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)


def _build_windows_displays(devices: list[CaptureDevice]) -> list[DeviceDisplay]:
    displays: list[DeviceDisplay] = []
    for device in devices:
        friendly = _windows_friendly_name(device)
        note = _windows_note(_windows_kind(device))
        displays.append(
            DeviceDisplay(
                device=device,
                display_name=friendly,
                friendly_name=friendly,
                note=note,
                ip_addresses=device.ip_addresses,
            )
        )
    return displays


def _build_native_display(device: CaptureDevice) -> DeviceDisplay:
    friendly = device.description or device.name
    return DeviceDisplay(
        device=device,
        display_name=friendly,
        friendly_name=friendly,
        note="本机接口",
        ip_addresses=device.ip_addresses,
    )


def _windows_friendly_name(device: CaptureDevice) -> str:
    text = (device.description or "").strip()
    if text:
        quoted = re.search(r"'([^']+)'", text)
        if quoted:
            return quoted.group(1)
        return text
    if "NPF_Loopback" in device.name:
        return "Npcap Loopback Adapter"
    guid = re.search(r"\{([^}]+)\}", device.name)
    if guid:
        return f"Windows adapter {{{guid.group(1)}}}"
    return device.name


def _windows_kind(device: CaptureDevice) -> str:
    text = f"{device.name} {device.description}".lower()
    if "loopback" in text:
        return "loopback"
    if any(token in text for token in ("hyper-v", "vmware", "virtualbox", "virtual", "vpn", "tap", "tunnel")):
        return "virtual"
    if any(token in text for token in ("wi-fi", "wifi", "wireless", "wlan", "802.11")):
        return "wifi"
    if any(token in text for token in ("ethernet", "gigabit", "realtek", "intel(r) ethernet", "lan")):
        return "ethernet"
    return "unknown"


def _windows_note(kind: str) -> str:
    if kind == "wifi":
        return "无线网卡"
    if kind == "ethernet":
        return "有线网卡"
    if kind == "loopback":
        return "回环接口"
    if kind == "virtual":
        return "虚拟/VPN 接口"
    return "可用抓包接口"
