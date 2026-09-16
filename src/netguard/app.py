from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from contextlib import suppress
from typing import TYPE_CHECKING

from netguard.capture.interface_mapping import build_device_displays
from netguard.capture.pcap import PcapError, create_backend

if TYPE_CHECKING:
    from netguard.parser.packet import PacketInfo
    from netguard.processing import PacketEvent

os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")


def build_message() -> str:
    return "NetGuard 跨平台网络数据包监控工具"


def _list_devices() -> int:
    backend = create_backend()
    try:
        devices = backend.list_devices()
        if not devices:
            print("未找到可用的抓包设备。")
            return 1
        for idx, item in enumerate(build_device_displays(devices), start=1):
            desc = f" - {item.device.description}" if item.device.description else ""
            print(f"{idx}. {item.device.name}{desc} [{item.note}]")
        return 0
    finally:
        backend.close()


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    # Windows 下 stdout 重定向到文件/管道时使用 ANSI 代码页（如 cp936，strict），
    # 报文 summary 里的高位字节会让 print 抛 UnicodeEncodeError 丢行，放宽为替换
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description=build_message(), add_help=False)
    parser._optionals.title = "选项"
    parser.add_argument("-h", "--help", action="help", help="显示帮助信息并退出")
    parser.add_argument("--list-devices", action="store_true", help="列出 pcap 抓包设备")
    parser.add_argument("--interface", help="要监听的网络接口名称")
    parser.add_argument("--bpf", default="", help='BPF 过滤表达式，例如 "tcp or udp"')
    parser.add_argument("--no-gui", action="store_true", help="运行简易控制台抓包预览")
    parser.add_argument("--read", metavar="FILE", help="离线读取 pcap 文件（无需 libpcap）")
    parser.add_argument("--write", metavar="FILE", help="将捕获的数据包保存为 pcap 文件")
    parser.add_argument("--alerts-json", metavar="FILE", help="将 IDS 告警以 JSON 行格式写入文件")
    parser.add_argument("--rules", metavar="FILE", help="从文件加载 IDS 规则（默认使用内置示例规则）")
    args = parser.parse_args(argv)

    if args.read and args.interface:
        print("--read 与 --interface 不能同时使用", file=sys.stderr)
        raise SystemExit(2)
    if not (args.no_gui or args.read):
        ignored = [
            flag
            for flag in ("--bpf", "--write", "--alerts-json", "--rules")
            if getattr(args, flag.strip("-").replace("-", "_"), None)
        ]
        if ignored:
            print(f"提示：{' '.join(ignored)} 仅在 --no-gui / --read 控制台模式下生效", file=sys.stderr)

    try:
        if args.list_devices:
            raise SystemExit(_list_devices())
        if args.no_gui or args.read:
            from netguard.pipeline import PacketPipeline
            from netguard.rules.engine import DEFAULT_RULES

            if args.read is None and not args.interface:
                print("使用 --no-gui 时必须指定 --interface")
                raise SystemExit(2)
            pipeline = PacketPipeline()

            if args.rules:
                try:
                    with open(args.rules, encoding="utf-8") as handle:
                        rule_text = handle.read()
                except OSError as exc:
                    print(f"无法读取规则文件：{exc}", file=sys.stderr)
                    raise SystemExit(2) from exc
            else:
                rule_text = DEFAULT_RULES
            failed = pipeline.load_rules(rule_text)
            print(f"已加载 {pipeline.rule_count} 条 IDS 规则" + (f"（跳过 {failed} 条无效）" if failed else ""))

            collected: list[PacketInfo] = []
            alert_records: list[dict[str, object]] = []

            def on_packet(event: PacketEvent) -> None:
                pkt = event.packet
                if args.alerts_json:
                    for alert in event.alerts:
                        alert_records.append(alert.to_dict())
                if args.write is not None:
                    collected.append(pkt)
                print(f"{pkt.timestamp:.3f} {pkt.src} -> {pkt.dst} {pkt.protocol} len={pkt.length} {pkt.summary}")
                for alert in event.alerts:
                    print(
                        f"[ALERT] {alert.timestamp:.3f} {alert.msg} "
                        f"({alert.src}:{alert.src_port} -> {alert.dst}:{alert.dst_port})"
                    )

            pipeline.on_packet = on_packet
            exit_code = 0
            if args.read:
                pipeline.start_file(args.read)
                print(f"正在回放 {args.read}。按 Ctrl+C 停止。")
                interrupted = False
                try:
                    pipeline.drain_and_wait()
                except KeyboardInterrupt:
                    interrupted = True
                finally:
                    pipeline.stop()
                # 回放线程的错误只写入 capture_error，控制台必须显式检查，
                # 否则坏文件/回放失败会以退出码 0 静默结束
                error = pipeline.capture_error
                if error:
                    print(f"回放失败：{error}", file=sys.stderr)
                    exit_code = 1
                elif not interrupted:
                    print(f"回放完成，共处理 {pipeline.status().total_packets} 个数据包")
            else:
                pipeline.start(args.interface, args.bpf)
                print("正在抓包。按 Ctrl+C 停止。")
                try:
                    while True:
                        if len(pipeline.pump()) == 0:
                            # 抓包线程死亡（如网卡拔出）只记录在 capture_error，
                            # 不检查会让控制台无限空转，用户误以为只是没流量
                            error = pipeline.capture_error
                            if error:
                                print(f"抓包错误：{error}", file=sys.stderr)
                                exit_code = 1
                                break
                            time.sleep(0.05)
                except KeyboardInterrupt:
                    pass
                finally:
                    pipeline.stop()
            if args.write is not None and collected:
                from netguard.capture.pcap import RawPacket
                from netguard.capture.pcap_file import write_pcap

                raws = [RawPacket(p.timestamp, p.raw, len(p.raw), p.length) for p in collected]
                try:
                    count = write_pcap(args.write, raws)
                except OSError as exc:
                    print(f"无法写入 pcap 文件 {args.write}：{exc}", file=sys.stderr)
                    exit_code = 1
                else:
                    print(f"已保存 {count} 个数据包到 {args.write}")
            if args.alerts_json is not None:
                try:
                    _write_alerts_json(args.alerts_json, alert_records)
                except OSError as exc:
                    print(f"无法写入告警文件 {args.alerts_json}：{exc}", file=sys.stderr)
                    exit_code = 1
            if exit_code:
                raise SystemExit(exit_code)
            return
        from netguard.gui.main_ui import run_gui

        with suppress(KeyboardInterrupt):
            run_gui()
    except PcapError as exc:
        print(f"pcap 错误：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def _write_alerts_json(path: str, records: list[dict[str, object]]) -> None:
    import json

    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"已写入 {len(records)} 条告警到 {path}")


if __name__ == "__main__":
    main()
