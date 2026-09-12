from netguard.capture.interface_mapping import (
    _native_alias,
    build_device_displays,
    device_recommendation_reason,
    recommend_device_display,
)
from netguard.capture.pcap import CaptureDevice


def test_native_alias_recognizes_en() -> None:
    assert _native_alias("en0") == "en0"
    assert _native_alias("en5") == "en5"


def test_native_alias_recognizes_lo() -> None:
    assert _native_alias("lo0") == "lo0"


def test_native_alias_rejects_unknown() -> None:
    assert _native_alias("eth0") == ""


def test_should_map_windows_wifi_to_mac_en0() -> None:
    devices = [
        CaptureDevice(r"\Device\NPF_{ETH}", "Intel(R) Ethernet Connection"),
        CaptureDevice(r"\Device\NPF_{WIFI}", "Wi-Fi 6 Adapter"),
        CaptureDevice(r"\Device\NPF_Loopback", "Npcap Loopback Adapter"),
    ]

    displays = build_device_displays(devices, system="Windows")
    aliases = {item.device.name: item.mac_alias for item in displays}

    assert aliases[r"\Device\NPF_{WIFI}"] == "en0"
    assert aliases[r"\Device\NPF_{ETH}"] == "en1"
    assert aliases[r"\Device\NPF_Loopback"] == "lo0"


def test_should_allow_manual_mac_alias_override() -> None:
    device = CaptureDevice(r"\Device\NPF_{WIFI}", "Wi-Fi")

    displays = build_device_displays(
        [device],
        manual_aliases={device.name: "en3"},
        system="Windows",
    )

    assert displays[0].mac_alias == "en3"
    assert displays[0].is_manual is True
    assert "手动" in displays[0].note


def test_should_recommend_windows_wifi_over_loopback_and_virtual() -> None:
    devices = [
        CaptureDevice(r"\Device\NPF_Loopback", "Npcap Loopback Adapter"),
        CaptureDevice(r"\Device\NPF_{VM}", "VMware Virtual Ethernet Adapter"),
        CaptureDevice(r"\Device\NPF_{WIFI}", "Wi-Fi 6 Adapter"),
    ]

    recommended = recommend_device_display(build_device_displays(devices, system="Windows"))

    assert recommended is not None
    assert recommended.device.name == r"\Device\NPF_{WIFI}"
    assert "无线" in device_recommendation_reason(recommended)


def test_should_recommend_native_physical_interface_over_tunnel_and_loopback() -> None:
    devices = [
        CaptureDevice("lo0", "Loopback"),
        CaptureDevice("utun4", "Tunnel"),
        CaptureDevice("en0", "Wi-Fi"),
    ]

    recommended = recommend_device_display(build_device_displays(devices, system="Darwin"))

    assert recommended is not None
    assert recommended.device.name == "en0"
