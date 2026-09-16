"""PcapBackend 单元测试：mock ctypes.CDLL，无需真实 libpcap/Npcap。

覆盖：库符号校验、设备枚举（含地址链表解析与释放）、打开/关闭、
BPF 过滤（长度上限、编译失败路径）、抓包循环（正常回调/超时/EOF/错误）。
"""

from __future__ import annotations

import ctypes
import itertools
from unittest.mock import MagicMock

import pytest

from netguard.capture import pcap as pcap_mod
from netguard.capture.pcap import (
    PcapBackend,
    PcapError,
    RawPacket,
    pcap_pkthdr,
)


def _make_lib() -> MagicMock:
    return MagicMock(spec=pcap_mod.PcapBackend._REQUIRED_SYMBOLS)


def _backend() -> PcapBackend:
    return PcapBackend(library=_make_lib())


class TestValidateLibrary:
    def test_missing_symbols_raise(self):
        # _validate_library 直接调用，绕过 __init__ 的 _configure（需要完整符号集）
        lib = MagicMock(spec=["pcap_findalldevs"])  # 只给一个符号
        with pytest.raises(PcapError, match="缺少必要 pcap API"):
            PcapBackend._validate_library(lib, "fakepcap")

    def test_full_symbols_accepted(self):
        backend = _backend()
        assert backend.lib is not None


class TestListDevices:
    def _build_devs(self, entries: list[tuple[bytes, bytes]]) -> None:
        """把 (name, description) 链表挂到 pcap_findalldevs 的 out 参数上。"""
        structs = []
        for name, desc in entries:
            item = pcap_mod.pcap_if_t()
            item.name = name
            item.description = desc
            item.addresses = None
            structs.append(item)
        for i in range(len(structs) - 1):
            structs[i].next = ctypes.pointer(structs[i + 1])
        structs[-1].next = None

        def findalldevs(out_ptr, _errbuf):
            if structs:
                ctypes.cast(out_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.cast(
                    ctypes.pointer(structs[0]), ctypes.c_void_p
                )
            return 0

        return findalldevs

    def test_enumerates_devices_and_frees(self):
        lib = _make_lib()
        lib.pcap_findalldevs.side_effect = self._build_devs([(b"eth0", b"uplink"), (b"lo", b"loopback")])
        backend = PcapBackend(library=lib)
        devices = backend.list_devices()
        assert [d.name for d in devices] == ["eth0", "lo"]
        assert devices[0].description == "uplink"
        lib.pcap_freealldevs.assert_called_once()

    def test_findalldevs_failure_raises(self):
        lib = _make_lib()
        lib.pcap_findalldevs.return_value = -1
        backend = PcapBackend(library=lib)
        with pytest.raises(PcapError):
            backend.list_devices()

    def test_empty_list(self):
        lib = _make_lib()
        lib.pcap_findalldevs.return_value = 0  # alldevs 保持 NULL
        backend = PcapBackend(library=lib)
        assert backend.list_devices() == []
        lib.pcap_freealldevs.assert_not_called()


class TestOpen:
    def test_open_success(self):
        lib = _make_lib()
        lib.pcap_open_live.return_value = 1234
        backend = PcapBackend(library=lib)
        backend.open("eth0")
        assert backend._handle == 1234

    def test_open_failure_raises(self):
        lib = _make_lib()
        lib.pcap_open_live.return_value = None
        backend = PcapBackend(library=lib)
        with pytest.raises(PcapError):
            backend.open("missing0")

    def test_open_with_filter_compile_failure_closes_handle(self):
        lib = _make_lib()
        lib.pcap_open_live.return_value = 1234
        lib.pcap_compile.return_value = -1
        lib.pcap_geterr.return_value = b"syntax error"
        backend = PcapBackend(library=lib)
        with pytest.raises(PcapError, match="syntax error"):
            backend.open("eth0", bpf_filter="bad filter (((")
        # 打开失败后句柄必须关闭，避免泄漏
        assert backend._handle is None
        lib.pcap_close.assert_called_once()


class TestSetFilter:
    def test_requires_open_device(self):
        backend = _backend()
        with pytest.raises(PcapError, match="尚未打开"):
            backend.set_filter("tcp")

    def test_bpf_length_limit(self):
        lib = _make_lib()
        lib.pcap_open_live.return_value = 1234
        backend = PcapBackend(library=lib)
        backend.open("eth0")
        with pytest.raises(PcapError, match="最大长度"):
            backend.set_filter("x" * (PcapBackend._MAX_BPF_LENGTH + 1))
        lib.pcap_compile.assert_not_called()

    def test_freecode_always_called(self):
        lib = _make_lib()
        lib.pcap_open_live.return_value = 1234
        lib.pcap_compile.return_value = 0
        lib.pcap_setfilter.return_value = -1
        lib.pcap_geterr.return_value = b"setfilter failed"
        backend = PcapBackend(library=lib)
        backend.open("eth0")
        with pytest.raises(PcapError, match="setfilter failed"):
            backend.set_filter("tcp")
        lib.pcap_freecode.assert_called_once()


class TestCaptureLoop:
    def _open(self, lib: MagicMock) -> PcapBackend:
        lib.pcap_open_live.return_value = 1234
        backend = PcapBackend(library=lib)
        backend.open("eth0")
        return backend

    def test_requires_open_device(self):
        backend = _backend()
        with pytest.raises(PcapError, match="尚未打开"):
            backend.capture_loop(lambda _raw: None)

    def test_delivers_packet_then_eof(self):
        lib = _make_lib()
        payload = b"\xde\xad\xbe\xef"

        def next_ex(_handle, header_ptr, packet_ptr):
            header = pcap_pkthdr()
            header.ts.tv_sec = 1_700_000_000
            header.ts.tv_usec = 250_000
            header.caplen = len(payload)
            header.len = len(payload)
            buf = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
            ctypes.cast(header_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.cast(
                ctypes.pointer(header), ctypes.c_void_p
            )
            ctypes.cast(packet_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.cast(buf, ctypes.c_void_p)
            next_ex.done = getattr(next_ex, "done", False)
            if next_ex.done:
                return -2  # EOF / savefile 结束
            next_ex.done = True
            return 1

        lib.pcap_next_ex.side_effect = next_ex
        backend = self._open(lib)
        received: list[RawPacket] = []
        backend.capture_loop(received.append)
        assert len(received) == 1
        raw = received[0]
        assert raw.data == payload
        assert raw.timestamp == pytest.approx(1_700_000_000.25)
        assert raw.captured_length == len(payload)
        assert raw.original_length == len(payload)

    def test_error_code_raises(self):
        lib = _make_lib()
        lib.pcap_next_ex.return_value = -1
        lib.pcap_geterr.return_value = b"interface down"
        backend = self._open(lib)
        with pytest.raises(PcapError, match="interface down"):
            backend.capture_loop(lambda _raw: None)

    def test_stop_breaks_loop(self):
        lib = _make_lib()

        def next_ex(*_args):
            backend.stop()
            return 0  # 超时包；stop 已置位，下一轮应退出

        lib.pcap_next_ex.side_effect = next_ex
        backend = self._open(lib)
        backend.capture_loop(lambda _raw: None)  # 应正常返回而不是死循环
        assert backend._stop.is_set()


class TestClose:
    def test_close_releases_handle(self):
        lib = _make_lib()
        lib.pcap_open_live.return_value = 1234
        backend = PcapBackend(library=lib)
        backend.open("eth0")
        backend.close()
        lib.pcap_breakloop.assert_called()
        lib.pcap_close.assert_called_once()
        assert backend._handle is None

    def test_close_idempotent(self):
        backend = _backend()
        backend.close()
        backend.close()  # 未打开时重复关闭不应抛异常


class TestKernelDropStats:
    def test_kernel_drops_reported_via_hook(self):
        """pcap_stats 采样的内核丢弃经 on_kernel_drop 上报。"""
        lib = MagicMock(spec=[*PcapBackend._REQUIRED_SYMBOLS, "pcap_stats"])
        lib.pcap_open_live.return_value = 1234
        lib.pcap_geterr.return_value = b""

        payload = bytes([0xDE, 0xAD, 0xBE, 0xEF])
        header = pcap_pkthdr()
        header.ts.tv_sec = 1
        header.ts.tv_usec = 0
        header.caplen = len(payload)
        header.len = len(payload)
        buf = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
        state = {"calls": 0}

        def next_ex(_handle, header_ptr, packet_ptr):
            state["calls"] += 1
            ctypes.cast(header_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.cast(
                ctypes.pointer(header), ctypes.c_void_p
            )
            ctypes.cast(packet_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.cast(buf, ctypes.c_void_p)
            return -2 if state["calls"] > 200 else 1

        lib.pcap_next_ex.side_effect = next_ex

        def fake_stats(handle, stats_ptr):
            stats_ptr._obj.ps_drop = 7
            return 0

        lib.pcap_stats.side_effect = fake_stats

        backend = PcapBackend(library=lib)
        seen: list[int] = []
        backend.on_kernel_drop = seen.append
        backend.open("eth0")
        backend.capture_loop(lambda raw: None)
        assert seen == [7]

    def test_kernel_stats_skipped_without_symbol(self):
        """mock 库缺 pcap_stats 时不采样也不报错。"""
        lib = _make_lib()
        lib.pcap_open_live.return_value = 1234
        lib.pcap_next_ex.side_effect = [1] * 5 + [-2]
        backend = PcapBackend(library=lib)
        assert backend._has_pcap_stats is False
        backend.open("eth0")
        backend.capture_loop(lambda raw: None)  # 不抛异常即可


class TestAddressPairing:
    @staticmethod
    def _make_addr_chain(entries):
        """entries: [(ip_bytes, mask_bytes_or_None), ...] → (pcap_if_t, keepalive)"""
        addrs = []
        for ip, mask in entries:
            item = pcap_mod.pcap_addr_t()
            sa = pcap_mod.sockaddr_in()
            sa.sin_family = 2
            sa.sin_addr = (ctypes.c_ubyte * 4)(*ip)
            item.addr = ctypes.cast(ctypes.pointer(sa), ctypes.POINTER(pcap_mod.sockaddr))
            if mask is not None:
                sm = pcap_mod.sockaddr_in()
                sm.sin_family = 2
                sm.sin_addr = (ctypes.c_ubyte * 4)(*mask)
                item.netmask = ctypes.cast(ctypes.pointer(sm), ctypes.POINTER(pcap_mod.sockaddr))
            addrs.append((item, sa, sm if mask is not None else None))

        for (item, _, _), (next_item, _, _) in itertools.pairwise(addrs):
            item.next = ctypes.pointer(next_item)

        dev = pcap_mod.pcap_if_t()
        dev.name = b"eth0"
        dev.addresses = ctypes.cast(ctypes.pointer(addrs[0][0]), ctypes.c_void_p) if addrs else None
        # 返回值第二项用于持有 ctypes 对象引用，防止被 GC 回收
        _keepalive = [obj for triplet in addrs for obj in triplet if obj is not None]
        return dev, _keepalive

    def test_missing_netmask_keeps_pairing_aligned(self):
        dev, _keepalive = self._make_addr_chain(
            [
                (b"\x0a\x00\x00\x01", b"\xff\xff\xff\x00"),
                (b"\xc0\xa8\x01\x01", None),
            ]
        )
        ips, masks = pcap_mod._extract_device_addresses(dev)
        assert ips == ["10.0.0.1", "192.168.1.1"]
        # 第二个地址缺掩码时以默认值占位，不再错位配对
        assert masks == ["255.255.255.0", "255.255.255.0"]

    def test_single_address_without_mask(self):
        dev, _keepalive = self._make_addr_chain([(b"\x0a\x00\x00\x02", None)])
        ips, masks = pcap_mod._extract_device_addresses(dev)
        assert ips == ["10.0.0.2"]
        assert masks == ["255.255.255.0"]
