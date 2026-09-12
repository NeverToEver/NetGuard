from netguard.capture.interface_mapping import (
    build_device_displays,
    device_recommendation_reason,
    recommend_device_display,
)
from netguard.capture.pcap import CaptureDevice


def test_windows_displays_use_friendly_name_and_kind_note() -> None:
    devices = [
        CaptureDevice(r"\Device\NPF_{WIFI}", "Wi-Fi"),
        CaptureDevice(r"\Device\NPF_{ETH}", "Intel(R) Ethernet Connection I219-V"),
        CaptureDevice(r"\Device\NPF_{VM}", "VMware Virtual Ethernet Adapter"),
        CaptureDevice(r"\Device\NPF_Loopback", "Npcap Loopback Adapter"),
    ]

    displays = build_device_displays(devices, system="Windows")
    notes = {item.device.name: item.note for item in displays}

    assert notes[r"\Device\NPF_{WIFI}"] == "无线网卡"
    assert notes[r"\Device\NPF_{ETH}"] == "有线网卡"
    assert notes[r"\Device\NPF_{VM}"] == "虚拟/VPN 接口"
    assert notes[r"\Device\NPF_Loopback"] == "回环接口"


def test_windows_friendly_name_extracts_quoted_adapter_name() -> None:
    device = CaptureDevice(
        r"\Device\NPF_{GUID}",
        "Microsoft Wi-Fi Direct Virtual Adapter #2 'Wi-Fi 2'",
    )

    displays = build_device_displays([device], system="Windows")

    assert displays[0].friendly_name == "Wi-Fi 2"


def test_windows_loopback_without_description_gets_fallback_name() -> None:
    device = CaptureDevice(r"\Device\NPF_Loopback", "")

    displays = build_device_displays([device], system="Windows")

    assert displays[0].friendly_name == "Npcap Loopback Adapter"
    assert displays[0].note == "回环接口"


def test_native_displays_use_description_as_name() -> None:
    device = CaptureDevice("en0", "Wi-Fi")

    displays = build_device_displays([device], system="Darwin")

    assert displays[0].display_name == "Wi-Fi"
    assert displays[0].note == "本机接口"


def test_duplicate_display_names_are_disambiguated() -> None:
    devices = [
        CaptureDevice("eth0", "Ethernet"),
        CaptureDevice("eth1", "Ethernet"),
    ]

    displays = build_device_displays(devices, system="Linux")
    names = {item.device.name: item.display_name for item in displays}

    assert names["eth0"] == "Ethernet - eth0"
    assert names["eth1"] == "Ethernet - eth1"


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


def test_decode_output_handles_gbk_windows_ipconfig() -> None:
    from netguard.discovery.subnet import _decode_output

    # 中文 Windows 的 ipconfig 以 GBK(cp936) 输出，之前按 UTF-8 解码会崩溃
    gbk_bytes = "Windows IP 配置\r\n子网掩码".encode("gbk")
    text = _decode_output(gbk_bytes)
    assert "Windows IP 配置" in text
    assert "子网掩码" in text


def test_decode_output_handles_empty_and_invalid() -> None:
    from netguard.discovery.subnet import _decode_output

    assert _decode_output(None) == ""
    assert _decode_output(b"") == ""
    # 纯 UTF-8 文本应正常解码
    assert _decode_output("正常".encode("utf-8")) == "正常"
