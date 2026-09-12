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
    args = parser.parse_args(argv)

    try:
        if args.list_devices:
            raise SystemExit(_list_devices())
        if args.no_gui:
            from netguard.pipeline import PacketPipeline

            if not args.interface:
                print("使用 --no-gui 时必须指定 --interface")
                raise SystemExit(2)
            pipeline = PacketPipeline()

            def on_packet(event):
                pkt = event.packet
                print(
                    f"{pkt.timestamp:.3f} {pkt.src} -> {pkt.dst} "
                    f"{pkt.protocol} len={pkt.length} {pkt.summary}"
                )

            pipeline.on_packet = on_packet
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
            return
        from netguard.gui.main_ui import run_gui

        try:
            run_gui()
        except KeyboardInterrupt:
            pass
    except PcapError as exc:
        print(f"pcap 错误：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
