from __future__ import annotations

import argparse
import logging
import os
import sys
import time

from netguard.capture.pcap import PcapError, create_backend
from netguard.capture.interface_mapping import build_device_displays

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
                    raise SystemExit(2)
            else:
                rule_text = DEFAULT_RULES
            failed = pipeline.load_rules(rule_text)
            print(f"已加载 {pipeline.rule_count} 条 IDS 规则" + (f"（跳过 {failed} 条无效）" if failed else ""))

            collected: list = []
            alert_records: list = []

            def on_packet(event):
                pkt = event.packet
                if args.alerts_json:
                    for alert in event.alerts:
                        alert_records.append(alert.to_dict())
                if args.write is not None:
                    collected.append(pkt)
                print(
                    f"{pkt.timestamp:.3f} {pkt.src} -> {pkt.dst} "
                    f"{pkt.protocol} len={pkt.length} {pkt.summary}"
                )
                for alert in event.alerts:
                    print(f"[ALERT] {alert.timestamp:.3f} {alert.msg} "
                          f"({alert.src}:{alert.src_port} -> {alert.dst}:{alert.dst_port})")

            pipeline.on_packet = on_packet
            if args.read:
                pipeline.start_file(args.read)
                print(f"正在回放 {args.read}。按 Ctrl+C 停止。")
                try:
                    pipeline.drain_and_wait()
                except KeyboardInterrupt:
                    pass
                finally:
                    pipeline.stop()
            else:
                pipeline.start(args.interface, args.bpf)
                print("正在抓包。按 Ctrl+C 停止。")
                try:
                    while True:
                        if len(pipeline.pump()) == 0:
                            time.sleep(0.05)
                except KeyboardInterrupt:
                    pass
                finally:
                    pipeline.stop()
            if args.write is not None and collected:
                from netguard.capture.pcap import RawPacket
                from netguard.capture.pcap_file import write_pcap

                raws = [
                    RawPacket(p.timestamp, p.raw, len(p.raw), p.length) for p in collected
                ]
                count = write_pcap(args.write, raws)
                print(f"已保存 {count} 个数据包到 {args.write}")
            if args.alerts_json is not None:
                _write_alerts_json(args.alerts_json, alert_records)
            return
        from netguard.gui.main_ui import run_gui

        try:
            run_gui()
        except KeyboardInterrupt:
            pass
    except PcapError as exc:
        print(f"pcap 错误：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def _write_alerts_json(path: str, records: list) -> None:
    import json

    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(f"已写入 {len(records)} 条告警到 {path}")


if __name__ == "__main__":
    main()
