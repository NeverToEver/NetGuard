from __future__ import annotations

import ctypes
import ctypes.util
import logging
import platform
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol

logger = logging.getLogger(__name__)


class PcapBackendProtocol(Protocol):
    """可替换的抓包后端接口，便于 mock 测试。"""

    def list_devices(self) -> list[CaptureDevice]: ...
    def open(self, device: str, bpf_filter: str = "", promiscuous: bool = True, timeout_ms: int = 100) -> None: ...
    def set_filter(self, bpf_filter: str) -> None: ...
    def capture_loop(self, callback: Callable[[RawPacket], None]) -> None: ...
    def stop(self) -> None: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class CaptureDevice:
    name: str
    description: str = ""
    ip_addresses: tuple[str, ...] = ()
    netmasks: tuple[str, ...] = ()


@dataclass(frozen=True)
class RawPacket:
    timestamp: float
    data: bytes
    captured_length: int
    original_length: int


class PcapError(RuntimeError):
    pass


class timeval(ctypes.Structure):
    # macOS 的 timeval.tv_usec 是 __darwin_suseconds_t（int32），
    # Linux/Windows 遵循 POSIX 标准为 suseconds_t（long）
    if sys.platform == "darwin":
        _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_int32)]
    else:
        _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts", timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


class pcap_if_t(ctypes.Structure):
    pass


pcap_if_t._fields_ = [
    ("next", ctypes.POINTER(pcap_if_t)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint32),
]


class bpf_program(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


class sockaddr(ctypes.Structure):
    _fields_ = [
        ("sa_family", ctypes.c_ushort),
        ("sa_data", ctypes.c_char * 14),
    ]


class sockaddr_in(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_char * 8),
    ]


class pcap_addr_t(ctypes.Structure):
    pass


pcap_addr_t._fields_ = [
    ("next", ctypes.POINTER(pcap_addr_t)),
    ("addr", ctypes.POINTER(sockaddr)),
    ("netmask", ctypes.POINTER(sockaddr)),
    ("broadaddr", ctypes.POINTER(sockaddr)),
    ("dstaddr", ctypes.POINTER(sockaddr)),
]

_AF_INET = 2


def _extract_device_addresses(item: pcap_if_t) -> tuple[list[str], list[str]]:
    ips: list[str] = []
    netmasks: list[str] = []
    addr_cursor = item.addresses
    while addr_cursor:
        pcap_addr = ctypes.cast(addr_cursor, ctypes.POINTER(pcap_addr_t)).contents
        if pcap_addr.addr:
            sa = pcap_addr.addr.contents
            if sa.sa_family == _AF_INET:
                sin = ctypes.cast(pcap_addr.addr, ctypes.POINTER(sockaddr_in)).contents
                ips.append(".".join(str(b) for b in sin.sin_addr))
        if pcap_addr.netmask:
            sa = pcap_addr.netmask.contents
            if sa.sa_family == _AF_INET:
                sin = ctypes.cast(pcap_addr.netmask, ctypes.POINTER(sockaddr_in)).contents
                netmasks.append(".".join(str(b) for b in sin.sin_addr))
        addr_cursor = pcap_addr.next if pcap_addr.next else None
    return ips, netmasks


class PcapBackend:
    _REQUIRED_SYMBOLS = (
        "pcap_findalldevs",
        "pcap_freealldevs",
        "pcap_open_live",
        "pcap_close",
        "pcap_next_ex",
        "pcap_compile",
        "pcap_setfilter",
        "pcap_freecode",
        "pcap_geterr",
        "pcap_breakloop",
    )

    def __init__(self, library: ctypes.CDLL | None = None) -> None:
        self.lib = library or self._load_library()
        self._configure()
        self._handle: ctypes.c_void_p | None = None
        self._handle_lock = threading.Lock()
        self._capture_lock = threading.Lock()
        self._stop = threading.Event()

    @staticmethod
    def _load_library() -> ctypes.CDLL:
        candidates: list[str] = []
        system = platform.system().lower()
        if system == "windows":
            candidates.append("wpcap.dll")
        elif system == "darwin":
            candidates.extend([ctypes.util.find_library("pcap") or "", "libpcap.dylib"])
        else:
            candidates.extend([ctypes.util.find_library("pcap") or "", "libpcap.so.1", "libpcap.so"])
        for name in [c for c in candidates if c]:
            try:
                lib = ctypes.CDLL(name)
                PcapBackend._validate_library(lib, name)
                return lib
            except PcapError:
                raise
            except OSError:
                logger.debug("无法加载候选库 %s", name)
                continue
        if system == "windows":
            raise PcapError("无法加载 wpcap.dll。请先安装 Npcap，并勾选 WinPcap API-compatible Mode。")
        raise PcapError("无法加载 libpcap。请先安装 libpcap。")

    @staticmethod
    def _validate_library(lib: ctypes.CDLL, name: str) -> None:
        missing = [symbol for symbol in PcapBackend._REQUIRED_SYMBOLS if not hasattr(lib, symbol)]
        if missing:
            missing_text = ", ".join(missing)
            raise PcapError(f"{name} 缺少必要 pcap API：{missing_text}")

    def _configure(self) -> None:
        self.lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if_t)), ctypes.c_char_p]
        self.lib.pcap_findalldevs.restype = ctypes.c_int
        self.lib.pcap_freealldevs.argtypes = [ctypes.POINTER(pcap_if_t)]
        self.lib.pcap_open_live.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_char_p,
        ]
        self.lib.pcap_open_live.restype = ctypes.c_void_p
        self.lib.pcap_close.argtypes = [ctypes.c_void_p]
        self.lib.pcap_next_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
        ]
        self.lib.pcap_next_ex.restype = ctypes.c_int
        self.lib.pcap_compile.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(bpf_program),
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_uint32,
        ]
        self.lib.pcap_compile.restype = ctypes.c_int
        self.lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(bpf_program)]
        self.lib.pcap_setfilter.restype = ctypes.c_int
        self.lib.pcap_freecode.argtypes = [ctypes.POINTER(bpf_program)]
        self.lib.pcap_geterr.argtypes = [ctypes.c_void_p]
        self.lib.pcap_geterr.restype = ctypes.c_char_p
        self.lib.pcap_breakloop.argtypes = [ctypes.c_void_p]
        self.lib.pcap_breakloop.restype = None

    def list_devices(self) -> list[CaptureDevice]:
        errbuf = ctypes.create_string_buffer(256)
        alldevs = ctypes.POINTER(pcap_if_t)()
        if self.lib.pcap_findalldevs(ctypes.byref(alldevs), errbuf) != 0:
            raise PcapError(errbuf.value.decode(errors="replace"))
        devices: list[CaptureDevice] = []
        try:
            cursor = alldevs
            while cursor:
                item = cursor.contents
                name = item.name.decode(errors="replace") if item.name else ""
                desc = item.description.decode(errors="replace") if item.description else ""
                if name:
                    ips, masks = _extract_device_addresses(item)
                    devices.append(CaptureDevice(name, desc, tuple(ips), tuple(masks)))
                cursor = item.next
        finally:
            if alldevs:
                self.lib.pcap_freealldevs(alldevs)
        return devices

    def open(self, device: str, bpf_filter: str = "", promiscuous: bool = True, timeout_ms: int = 100) -> None:
        self.close()
        errbuf = ctypes.create_string_buffer(256)
        handle = self.lib.pcap_open_live(
            device.encode(),
            65535,
            1 if promiscuous else 0,
            timeout_ms,
            errbuf,
        )
        if not handle:
            raise PcapError(errbuf.value.decode(errors="replace"))
        self._handle = handle
        self._stop.clear()
        if bpf_filter:
            try:
                self.set_filter(bpf_filter)
            except Exception:
                self.close()
                raise

    _MAX_BPF_LENGTH = 4096

    def set_filter(self, bpf_filter: str) -> None:
        if not self._handle:
            raise PcapError("抓包设备尚未打开")
        if len(bpf_filter) > self._MAX_BPF_LENGTH:
            raise PcapError(f"BPF 过滤器超过最大长度 {self._MAX_BPF_LENGTH}")
        program = bpf_program()
        encoded = bpf_filter.encode()
        try:
            if self.lib.pcap_compile(self._handle, ctypes.byref(program), encoded, 1, 0xFFFFFFFF) != 0:
                raise PcapError(self._last_error())
            if self.lib.pcap_setfilter(self._handle, ctypes.byref(program)) != 0:
                raise PcapError(self._last_error())
        finally:
            self.lib.pcap_freecode(ctypes.byref(program))

    def capture_loop(self, callback: Callable[[RawPacket], None]) -> None:
        with self._handle_lock:
            handle = self._handle
        if handle is None:
            raise PcapError("抓包设备尚未打开")
        with self._capture_lock:
            header = ctypes.POINTER(pcap_pkthdr)()
            packet = ctypes.POINTER(ctypes.c_ubyte)()
            while not self._stop.is_set():
                with self._handle_lock:
                    handle = self._handle
                    if handle is None:
                        break
                rc = self.lib.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(packet))
                if rc == 1:
                    if not packet:
                        continue  # 防御：rc==1 但指针为 NULL（不对外抛异常打断抓包）
                    h = header.contents
                    data = ctypes.string_at(packet, h.caplen)
                    ts = float(h.ts.tv_sec) + float(h.ts.tv_usec) / 1_000_000.0
                    callback(RawPacket(ts, data, h.caplen, h.len))
                elif rc == 0:
                    time.sleep(0.001)
                elif rc == -2:
                    break
                else:
                    raise PcapError(self._last_error())

    def stop(self) -> None:
        self._stop.set()
        with self._handle_lock:
            if self._handle:
                self.lib.pcap_breakloop(self._handle)

    def close(self) -> None:
        self._stop.set()
        with self._handle_lock:
            if self._handle:
                self.lib.pcap_breakloop(self._handle)
        self._wait_for_capture_loop()
        with self._handle_lock:
            if self._handle:
                self.lib.pcap_close(self._handle)
                self._handle = None

    def _wait_for_capture_loop(self) -> None:
        with self._capture_lock:
            pass

    def _last_error(self) -> str:
        if not self._handle:
            return "pcap 句柄已关闭"
        err = self.lib.pcap_geterr(self._handle)
        return err.decode(errors="replace") if err else "未知 pcap 错误"


def create_backend() -> PcapBackend:
    return PcapBackend()
