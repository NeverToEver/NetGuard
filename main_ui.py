from __future__ import annotations

import logging
import os
import threading
import tkinter as tk
from contextlib import ExitStack
from importlib import resources
from tkinter import filedialog, messagebox, ttk

from netguard.capture.interface_mapping import DeviceDisplay, build_device_displays
from netguard.gui.theme import ThemeManager
from netguard.gui.view_models import DEFAULT_RULES, _format_packet, _search_text
from netguard.parser.packet import PacketInfo, hex_dump
from netguard.pipeline import PacketEvent, PacketPipeline

logger = logging.getLogger(__name__)
os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

MAX_TABLE_ROWS = 5000
MAX_ALERT_ROWS = 1000
MAX_EVENTS = 50_000
PUMP_BATCH = 500
TICK_MS = 250


def _sort_key(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return 0.0


class NetGuardApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("NetGuard")
        self.geometry("1280x820")
        self.minsize(1040, 720)
        self.pipeline = PacketPipeline()
        self.events: list[PacketEvent] = []
        self.filtered: list[int] = []
        self.device_displays: list[DeviceDisplay] = []
        self.display_to_device: dict[str, str] = {}
        self.manual_device_aliases: dict[str, str] = {}
        self.paused = False
        self.dark_mode = tk.BooleanVar(value=False)
        self._classic_widgets: list[tk.Widget] = []
        self._icon_stack = ExitStack()
        self._icon_image: tk.PhotoImage | None = None
        self.packet_total_var = tk.StringVar(value="数据包 0")
        self.rate_var = tk.StringVar(value="0.0 包/秒")
        self.bytes_rate_var = tk.StringVar(value="0.0 字节/秒")
        self.session_var = tk.StringVar(value="会话 0")
        self.alert_count_var = tk.StringVar(value="告警 0")
        self._last_stats_text = ""
        self._filter_after_id: str | None = None
        self.alert_packet_indices: list[int] = []
        self._theme = ThemeManager(self)
        try:
            self._theme._style.theme_use("clam")
        except tk.TclError:
            pass
        self._set_window_icon()
        self._build()
        self._apply_theme()
        self.after(100, self._load_devices)
        self.after(200, self._tick)
        self.bind_all("<Control-Return>", lambda _: self._start())
        self.bind_all("<Escape>", lambda _: self._stop())
        self.bind_all("<Control-p>", lambda _: self._toggle_pause())
        self.bind_all("<Control-l>", lambda _: self._clear())

    def _set_window_icon(self) -> None:
        try:
            icon_ref = resources.files("netguard.assets").joinpath("netguard-icon.png")
            icon_path = self._icon_stack.enter_context(resources.as_file(icon_ref))
            self._icon_image = tk.PhotoImage(file=str(icon_path))
            self.iconphoto(True, self._icon_image)
        except Exception:
            logger.debug("无法加载应用图标", exc_info=True)
            self._icon_image = None

    def _apply_theme(self) -> None:
        self._theme.apply(self.dark_mode.get(), self.table, self._classic_widgets)

    def _build(self) -> None:
        top = ttk.Frame(self, padding=(8, 6), style="Toolbar.TFrame")
        top.pack(fill=tk.X)

        actions = ttk.Frame(top, style="Toolbar.TFrame")
        actions.pack(side=tk.RIGHT, anchor=tk.NE, padx=(10, 0))
        capture_controls = ttk.Frame(top, style="Toolbar.TFrame")
        capture_controls.pack(side=tk.LEFT, fill=tk.X, expand=True)
        capture_controls.columnconfigure(2, weight=1)

        ttk.Label(capture_controls, text="NetGuard 抓包", style="AppTitle.TLabel").grid(
            row=0, column=0, sticky=tk.W, padx=(0, 16)
        )
        ttk.Label(capture_controls, text="网卡", style="Muted.TLabel").grid(row=0, column=1, sticky=tk.W, padx=(0, 6))
        self.device_var = tk.StringVar()
        self.device_box = ttk.Combobox(capture_controls, textvariable=self.device_var, width=34)
        self.device_box.grid(row=0, column=2, sticky=tk.EW, padx=(0, 12))
        self.device_box.bind("<<ComboboxSelected>>", lambda _: self._sync_mapping_fields())
        ttk.Label(capture_controls, text="Mac映射", style="Muted.TLabel").grid(row=0, column=3, sticky=tk.W, padx=(0, 6))
        self.mac_alias_var = tk.StringVar()
        ttk.Entry(capture_controls, textvariable=self.mac_alias_var, width=10).grid(row=0, column=4, sticky=tk.EW, padx=(0, 10))
        ttk.Label(capture_controls, text="抓包过滤器 (BPF)", style="Muted.TLabel").grid(
            row=1, column=0, sticky=tk.W, padx=(0, 12), pady=(6, 0)
        )
        self.bpf_var = tk.StringVar(value="tcp or udp")
        ttk.Entry(capture_controls, textvariable=self.bpf_var, style="Filter.TEntry").grid(
            row=1, column=1, columnspan=4, sticky=tk.EW, padx=(0, 10), pady=(6, 0)
        )
        ttk.Button(capture_controls, text="应用映射", width=8, style="Secondary.TButton", command=self._apply_manual_mapping).grid(
            row=1, column=5, sticky=tk.EW, padx=(0, 6), pady=(6, 0)
        )
        ttk.Button(capture_controls, text="自动推断", width=8, style="Secondary.TButton", command=self._reset_auto_mapping).grid(
            row=1, column=6, sticky=tk.EW, padx=(0, 0), pady=(6, 0)
        )

        ttk.Button(actions, text="开始", width=8, style="Accent.TButton", command=self._start).grid(row=0, column=0, sticky=tk.EW, padx=(0, 6))
        ttk.Button(actions, text="停止", width=8, style="Danger.TButton", command=self._stop).grid(row=0, column=1, sticky=tk.EW, padx=(0, 6))
        self.pause_btn = ttk.Button(actions, text="暂停", width=8, style="Secondary.TButton", command=self._toggle_pause)
        self.pause_btn.grid(row=0, column=2, sticky=tk.EW)
        ttk.Button(actions, text="清空", width=8, style="Secondary.TButton", command=self._clear).grid(row=1, column=0, sticky=tk.EW, padx=(0, 6), pady=(6, 0))
        ttk.Button(actions, text="导出告警", width=10, style="Secondary.TButton", command=self._export_alerts).grid(
            row=1, column=1, sticky=tk.EW, padx=(0, 6), pady=(6, 0)
        )
        ttk.Checkbutton(actions, text="夜间模式", variable=self.dark_mode, style="Switch.TCheckbutton", command=self._apply_theme).grid(
            row=1, column=2, sticky=tk.W, pady=(6, 0)
        )
        self.status_var = tk.StringVar(value="正在加载网卡...")
        ttk.Label(actions, textvariable=self.status_var, anchor=tk.E, style="Status.TLabel").grid(
            row=2, column=0, columnspan=3, sticky=tk.EW, pady=(6, 0)
        )

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X)

        filters = ttk.Frame(self, padding=(8, 7, 8, 7), style="FilterBar.TFrame")
        filters.pack(fill=tk.X)
        filters.columnconfigure(1, weight=1)
        ttk.Label(filters, text="显示过滤器", style="FilterLabel.TLabel").grid(row=0, column=0, sticky=tk.W, padx=(0, 8))
        self.display_filter = tk.StringVar()
        entry = ttk.Entry(filters, textvariable=self.display_filter, style="Filter.TEntry")
        entry.grid(row=0, column=1, sticky=tk.EW, padx=(0, 8))
        entry.bind("<KeyRelease>", lambda _: self._debounced_refilter())
        ttk.Button(filters, text="应用", width=10, style="Secondary.TButton", command=self._refilter).grid(row=0, column=2, sticky=tk.EW)

        summary = ttk.Frame(self, padding=(8, 4), style="Summary.TFrame")
        summary.pack(fill=tk.X)
        for column, variable in enumerate(
            (self.packet_total_var, self.rate_var, self.bytes_rate_var, self.session_var, self.alert_count_var)
        ):
            ttk.Label(summary, textvariable=variable, style="Metric.TLabel").grid(row=0, column=column, sticky=tk.W, padx=(0, 18))

        body = ttk.PanedWindow(self, orient=tk.HORIZONTAL, style="Content.TPanedwindow")
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))
        left = ttk.Frame(body, style="Panel.TFrame")
        right = ttk.PanedWindow(body, orient=tk.VERTICAL)
        body.add(left, weight=3)
        body.add(right, weight=2)

        columns = ("time", "src", "dst", "proto", "len", "summary")
        headings = {
            "time": "时间",
            "src": "源地址",
            "dst": "目的地址",
            "proto": "协议",
            "len": "长度",
            "summary": "摘要",
        }
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.table = ttk.Treeview(left, columns=columns, show="headings", height=16)
        for col, width in zip(columns, [96, 164, 164, 72, 68, 420]):
            self.table.heading(col, text=headings[col], command=lambda c=col: self._sort(c))
            self.table.column(col, width=width, anchor=tk.W)
        self.table.column("len", anchor=tk.E, stretch=False)
        self.table.column("proto", anchor=tk.CENTER, stretch=False)
        table_scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.table.yview)
        table_hscroll = ttk.Scrollbar(left, orient=tk.HORIZONTAL, command=self.table.xview)
        self.table.configure(yscrollcommand=table_scroll.set, xscrollcommand=table_hscroll.set)
        self.table.grid(row=0, column=0, sticky=tk.NSEW)
        table_scroll.grid(row=0, column=1, sticky=tk.NS)
        table_hscroll.grid(row=1, column=0, sticky=tk.EW)
        self.table.bind("<<TreeviewSelect>>", lambda _: self._show_selected())

        detail_frame = ttk.LabelFrame(right, text="数据包详情", padding=5)
        self.detail = tk.Text(detail_frame, height=8, wrap=tk.NONE)
        self._classic_widgets.append(self.detail)
        self.detail.pack(fill=tk.BOTH, expand=True)
        right.add(detail_frame, weight=2)

        hex_frame = ttk.LabelFrame(right, text="数据包原始字节", padding=5)
        self.hex_view = tk.Text(hex_frame, height=7, wrap=tk.NONE)
        self._classic_widgets.append(self.hex_view)
        self.hex_view.pack(fill=tk.BOTH, expand=True)
        right.add(hex_frame, weight=2)

        bottom = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        bottom.pack(fill=tk.BOTH, expand=False, padx=8, pady=(0, 6))
        alert_frame = ttk.LabelFrame(bottom, text="告警日志", padding=5)
        self.alerts = tk.Listbox(alert_frame, height=6)
        self._classic_widgets.append(self.alerts)
        self.alerts.bind("<Double-Button-1>", lambda _: self._jump_to_alert_packet())
        self.alerts.pack(fill=tk.BOTH, expand=True)
        bottom.add(alert_frame, weight=2)
        stats_frame = ttk.LabelFrame(bottom, text="统计信息", padding=5)
        self.stats_text = tk.Text(stats_frame, height=6)
        self._classic_widgets.append(self.stats_text)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        bottom.add(stats_frame, weight=1)

        rules_frame = ttk.LabelFrame(self, text="IDS 规则", padding=5)
        rules_frame.pack(fill=tk.X, padx=8, pady=(0, 8))
        self.rules_text = tk.Text(rules_frame, height=6)
        self._classic_widgets.append(self.rules_text)
        self.rules_text.insert("1.0", DEFAULT_RULES)
        self.rules_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(rules_frame, text="加载规则", style="Secondary.TButton", command=self._load_rules).pack(side=tk.LEFT, padx=(8, 0))

    def _load_devices(self) -> None:
        self.status_var.set("正在加载网卡...")
        thread = threading.Thread(target=self._load_devices_worker, name="netguard-device-loader", daemon=True)
        thread.start()

    def _load_devices_worker(self) -> None:
        try:
            devices = self.pipeline.list_devices()
        except Exception as exc:
            self.after(0, self._show_device_error, str(exc))
            return
        self.after(0, self._set_devices, devices)

    def _set_devices(self, devices) -> None:
        self.device_displays = build_device_displays(devices, self.manual_device_aliases)
        values = [item.display_name for item in self.device_displays]
        self.display_to_device = {item.display_name: item.device.name for item in self.device_displays}
        self.device_box["values"] = values
        if values:
            self.device_var.set(values[0])
            self._sync_mapping_fields()
            self.status_var.set(f"已加载 {len(values)} 个网卡")
        else:
            self.status_var.set("未找到可用网卡")

    def _selected_device_name(self) -> str:
        selected = self.device_var.get()
        return self.display_to_device.get(selected, selected)

    def _selected_device_display(self) -> DeviceDisplay | None:
        device_name = self._selected_device_name()
        for item in self.device_displays:
            if item.device.name == device_name:
                return item
        return None

    def _sync_mapping_fields(self) -> None:
        selected = self._selected_device_display()
        self.mac_alias_var.set(selected.mac_alias if selected else "")

    def _refresh_device_display_values(self, selected_device: str) -> None:
        devices = [item.device for item in self.device_displays]
        self.device_displays = build_device_displays(devices, self.manual_device_aliases)
        values = [item.display_name for item in self.device_displays]
        self.display_to_device = {item.display_name: item.device.name for item in self.device_displays}
        self.device_box["values"] = values
        for item in self.device_displays:
            if item.device.name == selected_device:
                self.device_var.set(item.display_name)
                self.mac_alias_var.set(item.mac_alias)
                break

    def _apply_manual_mapping(self) -> None:
        device_name = self._selected_device_name()
        alias = self.mac_alias_var.get().strip()
        if not device_name or not alias:
            messagebox.showwarning("Mac映射", "请先选择网卡并填写 Mac 接口名，例如 en0。")
            return
        self.manual_device_aliases[device_name] = alias
        self._refresh_device_display_values(device_name)
        self.status_var.set(f"已将当前网卡手动映射为 Mac {alias}")

    def _reset_auto_mapping(self) -> None:
        device_name = self._selected_device_name()
        if not device_name:
            return
        self.manual_device_aliases.pop(device_name, None)
        self._refresh_device_display_values(device_name)
        self.status_var.set("当前网卡已恢复自动推断映射")

    def _show_device_error(self, error: str) -> None:
        logger.error("网卡加载失败：%s", error)
        self.status_var.set("网卡加载失败")
        messagebox.showwarning("Npcap/libpcap", error)

    def _load_rules(self) -> None:
        try:
            failed = self.pipeline.load_rules(self.rules_text.get("1.0", tk.END))
            if failed:
                messagebox.showwarning("规则", f"规则已加载，{failed} 条规则解析失败已跳过。")
            else:
                messagebox.showinfo("规则", "规则已加载。")
        except Exception as exc:
            messagebox.showerror("规则错误", str(exc))

    def _start(self) -> None:
        device = self._selected_device_name()
        if not device:
            messagebox.showwarning("网卡", "请先选择一个网络接口。")
            return
        try:
            self._load_rules()
            self.pipeline.start(device, self.bpf_var.get())
            self.status_var.set(f"正在监听 {self.device_var.get()}")
        except Exception as exc:
            self.status_var.set("抓包启动失败")
            messagebox.showerror("抓包错误", str(exc))

    def _stop(self) -> None:
        if not messagebox.askokcancel("停止抓包", "确定要停止抓包吗？"):
            return
        self.pipeline.stop()
        self.status_var.set("已停止抓包")

    def _toggle_pause(self) -> None:
        self.paused = not self.paused
        self.pause_btn.configure(text="恢复" if self.paused else "暂停")
        self.status_var.set("已暂停刷新" if self.paused else "已恢复刷新")

    def _clear(self) -> None:
        self.events.clear()
        self.filtered.clear()
        self.alert_packet_indices.clear()
        self._last_stats_text = ""
        self.table.delete(*self.table.get_children())
        self.alerts.delete(0, tk.END)
        self.detail.delete("1.0", tk.END)
        self.hex_view.delete("1.0", tk.END)

    def _tick(self) -> None:
        events = self.pipeline.pump(PUMP_BATCH)
        if events:
            self.events.extend(events)
            if len(self.events) > MAX_EVENTS:
                trim_count = len(self.events) - MAX_EVENTS
                del self.events[:trim_count]
                self.filtered = [idx - trim_count for idx in self.filtered if idx >= trim_count]
            if not self.paused:
                self._append_events(events)
        self._refresh_stats()
        self.after(TICK_MS, self._tick)

    def _append_events(self, events: list[PacketEvent]) -> None:
        needle = self.display_filter.get().strip().lower()
        start_idx = len(self.events) - len(events)
        for offset, event in enumerate(events):
            idx = start_idx + offset
            if needle and needle not in _search_text(event.packet):
                continue
            self.filtered.append(idx)
            self._insert_packet(idx, event.packet)
            for alert in event.alerts:
                self.alerts.insert(
                    tk.END,
                    f"{alert.timestamp:.3f} {alert.msg} {alert.src}:{alert.src_port} -> {alert.dst}:{alert.dst_port}",
                )
                self.alert_packet_indices.append(idx)
        self._trim_alerts()
        self._trim_table()

    def _insert_packet(self, idx: int, packet: PacketInfo) -> None:
        tags = ["even" if idx % 2 == 0 else "odd", packet.protocol.lower()]
        if packet.issues:
            tags.append("issue")
        self.table.insert(
            "",
            tk.END,
            iid=str(idx),
            tags=tuple(tags),
            values=(
                f"{packet.timestamp:.3f}",
                f"{packet.src}:{packet.src_port or ''}",
                f"{packet.dst}:{packet.dst_port or ''}",
                packet.protocol,
                packet.length,
                packet.summary,
            ),
        )

    def _trim_table(self) -> None:
        rows = self.table.get_children()
        if len(rows) > MAX_TABLE_ROWS:
            self.table.delete(*rows[: len(rows) - MAX_TABLE_ROWS])

    def _trim_alerts(self) -> None:
        extra = self.alerts.size() - MAX_ALERT_ROWS
        if extra > 0:
            self.alerts.delete(0, extra)
            del self.alert_packet_indices[:extra]

    def _show_selected(self) -> None:
        selected = self.table.selection()
        if not selected:
            return
        packet = self.events[int(selected[0])].packet
        self.detail.delete("1.0", tk.END)
        self.detail.insert(tk.END, _format_packet(packet))
        self.hex_view.delete("1.0", tk.END)
        self.hex_view.insert(tk.END, hex_dump(packet.raw))

    def _jump_to_alert_packet(self) -> None:
        selection = self.alerts.curselection()
        if not selection:
            return
        alert_idx = selection[0]
        if alert_idx >= len(self.alert_packet_indices):
            return
        packet_idx = self.alert_packet_indices[alert_idx]
        iid = str(packet_idx)
        children = self.table.get_children()
        if iid not in children:
            return
        self.table.selection_set(iid)
        self.table.see(iid)
        self.table.focus(iid)
        self._show_selected()

    def _debounced_refilter(self) -> None:
        if self._filter_after_id is not None:
            self.after_cancel(self._filter_after_id)
        self._filter_after_id = self.after(300, self._refilter)

    def _refilter(self) -> None:
        self._filter_after_id = None
        self.table.delete(*self.table.get_children())
        self.filtered.clear()
        needle = self.display_filter.get().strip().lower()
        for idx, event in enumerate(self.events[-MAX_TABLE_ROWS:]):
            real_idx = len(self.events) - min(len(self.events), MAX_TABLE_ROWS) + idx
            if not needle or needle in _search_text(event.packet):
                self.filtered.append(real_idx)
                self._insert_packet(real_idx, event.packet)

    def _sort(self, col: str) -> None:
        rows = [(self.table.set(row, col), row) for row in self.table.get_children("")]
        if col in {"time", "len"}:
            rows.sort(key=lambda item: _sort_key(item[0]))
        else:
            rows.sort(key=lambda item: item[0])
        for index, (_, row) in enumerate(rows):
            self.table.move(row, "", index)

    def _refresh_stats(self) -> None:
        snap = self.pipeline.stats.snapshot()
        self.packet_total_var.set(f"数据包 {snap.total_packets}")
        self.rate_var.set(f"{snap.packets_per_second:.1f} 包/秒")
        self.bytes_rate_var.set(f"{snap.bytes_per_second:.1f} 字节/秒")
        self.session_var.set(f"会话 {snap.active_sessions}")
        self.alert_count_var.set(f"告警 {self.alerts.size()}")
        lines = [
            f"数据包数：{snap.total_packets}",
            f"字节数：{snap.total_bytes}",
            f"活跃会话：{snap.active_sessions}",
            f"每秒数据包：{snap.packets_per_second:.1f}",
            f"每秒字节：{snap.bytes_per_second:.1f}",
            f"丢弃数据包：{self.pipeline.dropped_packets}",
            f"协议分布：{snap.protocol_counts}",
        ]
        stats_text = "\n".join(lines)
        if stats_text != self._last_stats_text:
            self.stats_text.delete("1.0", tk.END)
            self.stats_text.insert(tk.END, stats_text)
            self._last_stats_text = stats_text

    def _export_alerts(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("日志", "*.log"), ("文本", "*.txt")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                for item in self.alerts.get(0, tk.END):
                    handle.write(item + "\n")
        except (OSError, IsADirectoryError) as exc:
            messagebox.showerror("导出错误", f"无法写入文件：{exc}")

    def destroy(self) -> None:
        self.pipeline.stop()
        self._icon_stack.close()
        super().destroy()

def run_gui() -> None:
    app = NetGuardApp()
    app.mainloop()
