from __future__ import annotations

import concurrent.futures
import ipaddress
import locale
import logging
import platform
import re
import socket
import subprocess
import threading
from dataclasses import dataclass
from typing import Callable

logger = logging.getLogger(__name__)
MAX_SWEEP_HOSTS = 4096


@dataclass(frozen=True)
class HostInfo:
    ip: str
    hostname: str | None = None
    source: str = ""


@dataclass(frozen=True)
class SubnetInfo:
    cidr: str
    device_ip: str
    netmask: str
    network: ipaddress.IPv4Network
    total_hosts: int
    broadcast: str
    gateway_hint: str
    is_lab_network: bool


def subnet_from_device(ip: str, netmask: str) -> SubnetInfo | None:
    try:
        iface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return None
    net = iface.network
    total_hosts = max(0, net.num_addresses - (2 if net.version == 4 and net.num_addresses > 2 else 0))
    broadcast = str(net.broadcast_address)
    # /32 前缀时 hosts() 返回 list 而非迭代器，需 iter() 兼容，否则 next() 抛 TypeError
    gateway_hint = str(next(iter(net.hosts()), net.network_address))
    is_lab = 2 < total_hosts <= 254
    return SubnetInfo(
        cidr=f"{net.network_address}/{net.prefixlen}",
        device_ip=ip,
        netmask=netmask,
        network=net,
        total_hosts=total_hosts,
        broadcast=broadcast,
        gateway_hint=gateway_hint,
        is_lab_network=is_lab,
    )


def extract_subnets(ip_addresses: tuple[str, ...], netmasks: tuple[str, ...]) -> list[SubnetInfo]:
    seen: set[str] = set()
    result: list[SubnetInfo] = []
    for i, ip in enumerate(ip_addresses):
        mask = netmasks[i] if i < len(netmasks) else "255.255.255.0"
        info = subnet_from_device(ip, mask)
        if info is None or info.cidr in seen:
            continue
        seen.add(info.cidr)
        result.append(info)
    result.sort(key=lambda s: s.cidr)
    return result


def subnet_to_bpf(subnet: SubnetInfo) -> str:
    return f"net {subnet.network.network_address}/{subnet.network.prefixlen}"


def ping_host(ip: str, timeout: float = 1.0) -> bool:
    system = platform.system().lower()
    timeout_ms = str(int(timeout * 1000))
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", timeout_ms, ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 2.0,
        )
        if result.returncode != 0:
            return False
        # 退出码 0 不代表目标可达：Windows 收到网关的 "Destination host
        # unreachable" 应答时返回码也是 0。真实回显应答带 TTL/time 特征，
        # unreachable 应答没有，用特征区分而不只看退出码。
        output = _decode_output(result.stdout).lower()
        return "ttl=" in output or "time=" in output or "时间=" in output
    except (subprocess.TimeoutExpired, OSError):
        return False


def ping_sweep(
    subnet: SubnetInfo,
    *,
    max_workers: int = 100,
    timeout: float = 1.0,
    on_progress: Callable[[int, int, str], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> list[str]:
    total = subnet.total_hosts
    if total <= 0:
        return []
    if total > MAX_SWEEP_HOSTS:
        logger.warning("跳过过大网段扫描：%s (%d hosts)", subnet.cidr, total)
        return []
    hosts = [str(h) for h in subnet.network.hosts()]
    alive: list[str] = []
    completed = 0
    _cancel = cancel_event or threading.Event()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        pending_hosts = iter(hosts)
        future_map: dict[concurrent.futures.Future[bool], str] = {}

        def submit_until_full() -> None:
            while not _cancel.is_set() and len(future_map) < max_workers:
                try:
                    host = next(pending_hosts)
                except StopIteration:
                    return
                future_map[executor.submit(ping_host, host, timeout)] = host

        submit_until_full()
        while future_map:
            done, _pending = concurrent.futures.wait(
                future_map,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                host = future_map.pop(future)
                try:
                    if future.result():
                        alive.append(host)
                except Exception:
                    logger.debug("ping %s 异常", host, exc_info=True)
                completed += 1
                if on_progress is not None:
                    try:
                        on_progress(completed, total, host)
                    except Exception:
                        pass
            if _cancel.is_set():
                for future in future_map:
                    future.cancel()
                break
            submit_until_full()
    alive.sort(key=lambda ip_str: ipaddress.IPv4Address(ip_str))
    return alive


def _looks_multibyte(encoding: str) -> bool:
    """探测编码是否为多字节：多字节 CJK 编码会把 0x81 0x40 解成单个字符。

    单字节编码（cp1252/latin-1 等）做不到——要么解出两个字符，要么直接报错。
    """
    try:
        return len(b"\x81\x40".decode(encoding)) == 1
    except (UnicodeDecodeError, LookupError, TypeError):
        return False


def _decoding_order() -> list[str]:
    """给出“先严格多字节、后宽松单字节”的候选编码顺序。

    Windows 子进程输出多为本地代码页：中文是 cp936(GBK)、日文 cp932 等多字节
    编码，而西文 cp1252/latin-1 是单字节编码。单字节编码几乎能“成功”解码任意
    字节，若排在 GBK 之前就会把 GBK 字节静默解成乱码，令 GBK 永远轮不到，因此
    这里让多字节的本地编码优先、GBK 其次，单字节本地编码与 latin-1 仅作兜底。
    """
    preferred = locale.getpreferredencoding(False)
    order = ["utf-8"]
    if preferred and _looks_multibyte(preferred):
        order.append(preferred)
    order.append("gbk")
    if preferred:
        order.append(preferred)
    order.append("latin-1")
    return order


def _decode_output(data: bytes | None) -> str:
    """把子进程原始输出解码为文本。

    Windows 上 ipconfig 等命令常按本地代码页（如中文 GBK/cp936）输出，若强制
    UTF-8 解码会抛 UnicodeDecodeError 并让 stdout 变成 None。这里按 UTF-8 →
    （多字节的）本地首选编码 → GBK → 单字节本地编码 → latin-1 的顺序尝试，最后
    以 replace 兜底，保证不崩。
    """
    if not data:
        return ""
    seen: set[str] = set()
    for encoding in _decoding_order():
        if not encoding or encoding.lower() in seen:
            continue
        seen.add(encoding.lower())
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def _run_command(args: list[str], *, timeout: float = 10.0) -> subprocess.CompletedProcess[bytes]:
    """执行命令并返回字节输出，由调用方按平台编码解码。"""
    return subprocess.run(args, capture_output=True, timeout=timeout)


def _normalize_device_token(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


def _windows_section_name(section: str) -> str:
    first_line = next((line.strip() for line in section.splitlines() if line.strip()), "")
    match = re.match(r".*(?: adapter |适配器\s+)(.+):$", first_line, flags=re.IGNORECASE)
    return match.group(1).strip() if match else first_line.rstrip(":").strip()


def _split_ipconfig_sections(output: str) -> list[str]:
    sections: list[list[str]] = []
    current: list[str] = []
    adapter_header = re.compile(r"^\S.*(?: adapter |适配器\s+).+:$", re.IGNORECASE)
    for line in output.splitlines():
        stripped = line.strip()
        if adapter_header.match(stripped):
            if current:
                sections.append(current)
            current = [stripped]
            continue
        if current:
            current.append(line)
    if current:
        sections.append(current)
    if sections:
        return ["\n".join(section) for section in sections]
    return [section for section in re.split(r'\r?\n\r?\n', output) if section.strip()]


def _windows_device_matches(section: str, device_name: str) -> bool:
    needle = _normalize_device_token(device_name)
    if not needle or len(needle) < 3:
        return False
    section_name = _normalize_device_token(_windows_section_name(section))
    section_text = _normalize_device_token(section)
    guid_match = re.search(r"\{([^}]+)\}", device_name)
    if guid_match and _normalize_device_token(guid_match.group(1)) in section_text:
        return True
    # 只做正向包含：反向包含（section_name in needle）会让 Windows 默认命名的
    # "以太网 2" 匹配到 "以太网" 网卡，取错网段
    return bool((section_name and needle in section_name) or needle in section_text)


def _subnets_from_ipconfig_sections(sections: list[str]) -> list[SubnetInfo]:
    result: list[SubnetInfo] = []
    seen: set[str] = set()
    for section in sections:
        ip_match = re.search(r'IPv4[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', section)
        mask_match = re.search(r'(?:Subnet Mask|子网掩码)[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', section)
        if not (ip_match and mask_match):
            continue
        info = subnet_from_device(ip_match.group(1), mask_match.group(1))
        if info and info.cidr not in seen:
            seen.add(info.cidr)
            result.append(info)
    return result


_DNS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=32, thread_name_prefix="netguard-dns")


def _gethostbyaddr(ip: str) -> str:
    name, _aliases, _addresses = socket.gethostbyaddr(ip)
    return name


def resolve_hostname(ip: str, timeout: float = 2.0) -> str | None:
    """反向 DNS 解析，带真实超时。

    socket.setdefaulttimeout 只影响新建 socket，对 gethostbyaddr（直接走
    OS 解析器）无效——不可达主机在 Windows 上可能阻塞 10 秒量级。改为提交
    到共享线程池并带超时回收：超时后放弃该次结果立即返回，解析线程由
    OS 解析器决定何时退出（最终会退出，不阻塞调用方）。
    """
    future = _DNS_EXECUTOR.submit(_gethostbyaddr, ip)
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        future.cancel()
        return None
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def _resolve_netbios(ip: str, timeout: float = 2.0) -> str | None:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["nbtstat", "-A", ip]
    else:
        cmd = ["nmblookup", "-A", ip]
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout + 2.0
        )
        if result.returncode != 0:
            return None
        stderr_text = _decode_output(result.stderr).strip()
        if stderr_text:
            logger.debug("nbtstat/nmblookup stderr for %s: %s", ip, stderr_text[:200])
        stdout_text = _decode_output(result.stdout).strip()
        if not stdout_text:
            return None
        logger.debug("nbtstat/nmblookup raw output for %s:\n%s", ip, stdout_text[:500])
        for line in stdout_text.splitlines():
            stripped = line.strip()
            if "<00>" in stripped or "<20>" in stripped:
                parts = stripped.split()
                for p in parts:
                    if p not in ("<00>", "<20>", "UNIQUE", "GROUP", "<ACTIVE>"):
                        candidate = p.strip()
                        if candidate and len(candidate) >= 2 and not candidate[0].isdigit():
                            return candidate
        return None
    except (subprocess.TimeoutExpired, OSError):
        return None


def resolve_host(ip: str, timeout: float = 2.0) -> HostInfo:
    hostname = resolve_hostname(ip, timeout)
    if hostname:
        return HostInfo(ip=ip, hostname=hostname, source="DNS")
    nb_name = _resolve_netbios(ip, timeout)
    if nb_name:
        return HostInfo(ip=ip, hostname=nb_name, source="NetBIOS")
    return HostInfo(ip=ip)


def resolve_hosts(
    ips: list[str],
    *,
    max_workers: int = 40,
    timeout: float = 2.0,
    on_progress: Callable[[int, int, str], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> dict[str, HostInfo]:
    result: dict[str, HostInfo] = {}
    total = len(ips)
    completed = 0
    _cancel = cancel_event or threading.Event()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 增量提交 + 取消时撤销排队任务：一次性提交全部后只 break 的话，
        # with 退出要等所有排队任务跑完（死主机最坏十几分钟）
        pending_ips = iter(ips)
        future_map: dict[concurrent.futures.Future[HostInfo], str] = {}

        def submit_until_full() -> None:
            while not _cancel.is_set() and len(future_map) < max_workers:
                try:
                    ip = next(pending_ips)
                except StopIteration:
                    return
                future_map[executor.submit(resolve_host, ip, timeout)] = ip

        submit_until_full()
        while future_map:
            done, _pending = concurrent.futures.wait(
                future_map,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for future in done:
                ip = future_map.pop(future)
                try:
                    info = future.result()
                    result[ip] = info
                except Exception:
                    logger.info("resolve %s 失败", ip)
                    result[ip] = HostInfo(ip=ip)
                completed += 1
                if on_progress is not None:
                    try:
                        on_progress(completed, total, ip)
                    except Exception:
                        pass
            if _cancel.is_set():
                for future in future_map:
                    future.cancel()
                break
            submit_until_full()
    return result


def detect_subnet_os_fallback(device_name: str, aliases: tuple[str, ...] = ()) -> list[SubnetInfo]:
    system = platform.system().lower()
    if system == "windows":
        return _detect_windows_subnets(device_name, aliases)
    return _detect_unix_subnets(device_name)


def _detect_unix_subnets(ifname: str) -> list[SubnetInfo]:
    result: list[SubnetInfo] = []
    if ifname.startswith("-"):
        # 防参数注入：接口名以 "-" 开头会被解析为命令选项
        return result
    proc: subprocess.CompletedProcess[bytes] | None = None
    try:
        proc = subprocess.run(["ifconfig", ifname], capture_output=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        proc = None
    # ifconfig 存在但对指定接口返回非 0（接口名不匹配/BusyBox 差异）时
    # 也要回退 ip addr，不能拿空输出直接返回
    if proc is None or proc.returncode != 0:
        try:
            proc = subprocess.run(
                ["ip", "addr", "show", ifname], capture_output=True, timeout=5
            )
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return result
    if proc.returncode != 0:
        return result
    output = _decode_output(proc.stdout)
    for m in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+).*?netmask (0x[0-9a-fA-F]+)', output):
        ip = m.group(1)
        mask_hex = int(m.group(2), 16)
        netmask = ".".join(str((mask_hex >> (24 - 8 * i)) & 0xFF) for i in range(4))
        info = subnet_from_device(ip, netmask)
        if info:
            result.append(info)
    for m in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', output):
        ip = m.group(1)
        prefix = int(m.group(2))
        mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        netmask = ".".join(str((mask_int >> (24 - 8 * i)) & 0xFF) for i in range(4))
        info = subnet_from_device(ip, netmask)
        if info and info.cidr not in {s.cidr for s in result}:
            result.append(info)
    return result


def _detect_windows_subnets(device_name: str, aliases: tuple[str, ...] = ()) -> list[SubnetInfo]:
    try:
        proc = _run_command(["ipconfig"], timeout=10)
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return []
    sections = _split_ipconfig_sections(_decode_output(proc.stdout))
    candidates = tuple(dict.fromkeys(name for name in (device_name, *aliases) if name))
    matching_sections = [
        section for section in sections
        if any(_windows_device_matches(section, candidate) for candidate in candidates)
    ]
    matched = _subnets_from_ipconfig_sections(matching_sections)
    return matched or _subnets_from_ipconfig_sections(sections)
