"""纯标准库的 pcap 文件读写（不依赖 libpcap）。

支持经典的 pcap 格式（非 pcapng）：两种字节序、微秒/纳秒时间戳 magic，
用于离线回放、结果保存和与 Wireshark/tcpdump 交叉验证。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator

from netguard.capture.pcap import RawPacket

# magic -> (字节序, 时间戳分辨率除数)
_MAGICS: dict[bytes, tuple[str, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),   # 小端，微秒
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),   # 大端，微秒
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # 小端，纳秒
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # 大端，纳秒
}
_MAGIC_LE_US = b"\xd4\xc3\xb2\xa1"
_SNAPLEN = 262_144
_LINKTYPE_ETHERNET = 1


class PcapFileError(RuntimeError):
    pass


@dataclass(frozen=True)
class PcapFileHeader:
    byte_order: str
    nanosecond: bool
    version_major: int
    version_minor: int
    snaplen: int
    linktype: int


def _parse_header(handle: BinaryIO) -> PcapFileHeader:
    magic = handle.read(4)
    if len(magic) < 4:
        raise PcapFileError("文件过短，不是有效的 pcap 文件")
    if magic not in _MAGICS:
        raise PcapFileError("不支持的 pcap magic（可能为 pcapng 或已损坏）")
    byte_order, divisor = _MAGICS[magic]
    rest = handle.read(20)
    if len(rest) < 20:
        raise PcapFileError("pcap 全局头被截断")
    version_major, version_minor, _tz, _sigfigs, snaplen, linktype = struct.unpack(
        f"{byte_order}HHiIII", rest
    )
    return PcapFileHeader(
        byte_order=byte_order,
        nanosecond=divisor == 1_000_000_000,
        version_major=version_major,
        version_minor=version_minor,
        snaplen=snaplen,
        linktype=linktype,
    )


def read_header(path: str | Path) -> PcapFileHeader:
    with open(path, "rb") as handle:
        return _parse_header(handle)


def read_pcap(path: str | Path) -> Iterator[RawPacket]:
    """逐包读取 pcap 文件，产出 :class:`RawPacket`。

    仅支持 Ethernet（DLT_EN10MB）链路类型：其他链路（如 ``tcpdump -i any``
    的 Linux SLL）帧头长度不同，按 Ethernet 解析只会产出乱码，必须显式报错。
    容错策略：单个包记录头/载荷截断时抛出 :class:`PcapFileError`；调用方可
    用 :func:`iter_pcap_safe` 在记录级损坏时停在损坏处而非抛异常。
    """
    with open(path, "rb") as handle:
        header = _parse_header(handle)
        if header.linktype != _LINKTYPE_ETHERNET:
            raise PcapFileError(
                f"不支持的链路类型 {header.linktype}（仅支持 Ethernet/DLT_EN10MB=1），"
                "无法按以太网帧解析"
            )
        divisor = 1_000_000_000 if header.nanosecond else 1_000_000
        order = header.byte_order
        while True:
            record_header = handle.read(16)
            if not record_header:
                return
            if len(record_header) < 16:
                raise PcapFileError("pcap 包记录头被截断")
            ts_sec, ts_frac, caplen, origlen = struct.unpack(f"{order}IIII", record_header)
            data = handle.read(caplen)
            if len(data) < caplen:
                raise PcapFileError("pcap 包数据被截断")
            yield RawPacket(
                timestamp=ts_sec + ts_frac / divisor,
                data=data,
                captured_length=caplen,
                original_length=origlen,
            )


def iter_pcap_safe(path: str | Path) -> Iterator[RawPacket]:
    """逐包读取 pcap 文件，遇到损坏（文件头或包记录）时停止迭代而非抛异常。

    返回损坏点之前已成功读取的全部包；不牺牲任何包数据，也不让坏文件
    中断调用方。
    """
    iterator = read_pcap(path)
    while True:
        try:
            yield next(iterator)
        except StopIteration:
            return
        except PcapFileError:
            return


def write_pcap(path: str | Path, packets: Iterable[RawPacket], *, nanosecond: bool = False) -> int:
    """将数据包写入 pcap 文件（小端），返回写入包数。"""
    magic = b"\x4d\x3c\xb2\xa1" if nanosecond else _MAGIC_LE_US
    divisor = 1_000_000_000 if nanosecond else 1_000_000
    count = 0
    with open(path, "wb") as handle:
        handle.write(magic)
        handle.write(struct.pack("<HHiIII", 2, 4, 0, 0, _SNAPLEN, _LINKTYPE_ETHERNET))
        for packet in packets:
            # 负时间戳无法写入无符号字段；记录头声明的长度不能超过实际载荷，
            # 否则写出的文件自己读不回来（"pcap 包数据被截断"）
            ts_sec = max(0, int(packet.timestamp))
            ts_frac = int(round((packet.timestamp - int(packet.timestamp)) * divisor))
            if ts_frac >= divisor:
                ts_sec += ts_frac // divisor
                ts_frac %= divisor
            elif ts_frac < 0:
                ts_frac = 0
            caplen = min(packet.captured_length, len(packet.data))
            original = max(packet.original_length, caplen)
            handle.write(struct.pack("<IIII", ts_sec, ts_frac, caplen, original))
            # 记录头声明的 caplen 必须与实际写入字节数一致，否则后续所有
            # 记录边界错位，整个文件损坏
            handle.write(packet.data[:caplen])
            count += 1
    return count
