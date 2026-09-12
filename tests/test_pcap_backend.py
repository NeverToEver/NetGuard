"""PcapBackend 单元测试：mock ctypes.CDLL，无需真实 libpcap/Npcap。

覆盖：库符号校验、设备枚举（含地址链表解析与释放）、打开/关闭、
BPF 过滤（长度上限、编译失败路径）、抓包循环（正常回调/超时/EOF/错误）。
"""

from __future__ import annotations

import ctypes
from unittest.mock import MagicMock

import pytest

from netguard.capture import pcap as pcap_mod
from netguard.capture.pcap import (
    PcapBackend,
    PcapError,
    RawPacket,
    bpf_program,
    pcap_pkthdr,
)


def _make_lib() -> MagicMock:
    lib = MagicMock(spec=pcap_mod.PcapBackend._REQUIRED_SYMBOLS)
    return lib


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
