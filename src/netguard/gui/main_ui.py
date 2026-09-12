from __future__ import annotations

import ipaddress
import json
import logging
import pathlib
import threading
import time
import tkinter as tk
from contextlib import ExitStack
from dataclasses import dataclass
from importlib import resources
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from netguard.capture.interface_mapping import (
    DeviceDisplay,
    build_device_displays,
    device_recommendation_reason,
    recommend_device_display,
)
from netguard.gui.theme import ThemeManager, build_colors
from netguard.gui.view_models import _format_packet, _search_text
from netguard.parser.packet import PacketInfo, hex_dump
from netguard.pipeline import PacketEvent, PacketPipeline
from netguard.rules.suggestions import RuleSuggestion, generate_rule_suggestions
from netguard.trafficgen import TEMPLATES, PacketTemplate, TrafficGenerator
from netguard.discovery import HostInfo, SubnetInfo, detect_subnet_os_fallback, extract_subnets, ping_host, ping_sweep, resolve_hosts, subnet_to_bpf

logger = logging.getLogger(__name__)
MAX_TABLE_ROWS = 5000
MAX_ALERT_ROWS = 1000
MAX_EVENTS = 50_000
PUMP_BATCH = 500
TICK_MS = 250
TABLE_TRIM_CHUNK = 3000


def _sort_key(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        return 0.0


@dataclass(frozen=True)
class InputTemplate:
    title: str
    description: str
    value: str


BPF_TEMPLATES = [
    InputTemplate("TCP 或 UDP", "常用抓包范围，适合观察 Web、DNS 和大多数应用流量。", "tcp or udp"),
    InputTemplate("HTTP 明文", "抓取 80 端口 HTTP 流量。", "tcp port 80"),
    InputTemplate("HTTPS/TLS", "抓取 443 端口加密 Web 流量，不能直接匹配明文内容。", "tcp port 443"),
    InputTemplate("DNS 查询", "抓取 53 端口 DNS 流量。", "port 53"),
    InputTemplate("ICMP / Ping", "抓取 ping 相关 ICMP 流量。", "icmp"),
    InputTemplate("指定主机", "将示例 IP 替换为目标主机地址。", "host 192.168.1.10"),
    InputTemplate("指定网段", "将示例网段替换为授权实验网段。", "net 192.168.1.0/24"),
    InputTemplate("排除 SSH", "远程调试时减少 SSH 连接自身产生的干扰包。", "(tcp or udp) and not port 22"),
]

DISPLAY_FILTER_TEMPLATES = [
    InputTemplate("HTTP 数据包", "在已捕获数据中筛选协议、摘要或详情里包含 HTTP 的记录。", "HTTP"),
    InputTemplate("DNS 数据包", "筛选 DNS 查询和响应。", "DNS"),
    InputTemplate("TCP 数据包", "筛选 TCP 流量。", "TCP"),
    InputTemplate("UDP 数据包", "筛选 UDP 流量。", "UDP"),
    InputTemplate("GET 请求", "筛选摘要或 HTTP 详情中包含 GET 的记录。", "GET"),
    InputTemplate("POST 请求", "筛选摘要或 HTTP 详情中包含 POST 的记录。", "POST"),
    InputTemplate("80 端口", "筛选源端口或目的端口包含 80 的记录。", "80"),
    InputTemplate("域名关键字", "将 example.com 替换为需要查找的域名。", "example.com"),
]

IDS_RULE_TEMPLATES = [
    InputTemplate("HTTP GET 告警", "匹配发往 80 端口且载荷包含 GET 的明文 HTTP 请求。", 'alert tcp any any -> any 80 (content "GET"; msg "检测到 HTTP GET 请求";)'),
    InputTemplate("HTTP POST 告警", "匹配发往 80 端口且载荷包含 POST 的明文 HTTP 请求。", 'alert tcp any any -> any 80 (content "POST"; msg "检测到 HTTP POST 请求";)'),
    InputTemplate("HTTP Host 告警", "将 example.com 替换为目标 Host 域名。", 'alert tcp any any -> any 80 (content "Host: example.com"; msg "检测到指定 HTTP Host";)'),
    InputTemplate("DNS 流量告警", "匹配普通 DNS 查询和响应流量。", 'alert udp any any -> any 53 (msg "检测到 DNS 流量";)'),
    InputTemplate("DNS 关键字告警", "将 example 替换为目标域名中的关键字。", 'alert udp any any -> any 53 (content "example"; msg "检测到 DNS 查询关键字";)'),
    InputTemplate("任意协议关键字", "将 secret 替换为需要在载荷中查找的关键字。", 'alert any any any -> any any (content "secret"; msg "检测到关键字 secret";)'),
]


def _fit_combobox_width(combo: ttk.Combobox, values: list[str], *, min_width: int = 20, max_width: int = 70) -> None:
    if not values:
        return
    max_chars = max((len(v) for v in values))
    combo["width"] = max(min_width, min(max_chars, max_width))


def _set_initial_window_size(window: tk.Toplevel | tk.Tk, width: int, height: int,
                             min_width: int, min_height: int) -> None:
    screen_width = max(1, window.winfo_screenwidth())
    screen_height = max(1, window.winfo_screenheight())
    target_width = min(max(width, min_width), max(min_width, int(screen_width * 0.92)))
    target_height = min(max(height, min_height), max(min_height, int(screen_height * 0.88)))
    x = max(0, (screen_width - target_width) // 2)
    y = max(0, (screen_height - target_height) // 2)
    window.geometry(f"{target_width}x{target_height}+{x}+{y}")
    window.minsize(min_width, min_height)


def _device_match_aliases(display: DeviceDisplay) -> tuple[str, ...]:
    values = (
        display.display_name,
        display.friendly_name,
        display.device.description,
        display.note,
    )
    return tuple(dict.fromkeys(value for value in values if value and value != display.device.name))


class NetGuardApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("NetGuard")
        _set_initial_window_size(self, 1600, 940, 1180, 720)
        self._config_path = pathlib.Path.home() / ".netguard_config.json"
        self._config = self._load_config()
        self.pipeline = PacketPipeline()
        self.events: list[PacketEvent] = []
        self.event_offset = 0
        self.filtered: list[int] = []
        self.device_displays: list[DeviceDisplay] = []
        self.display_to_device: dict[str, str] = {}
        self.paused = False
        self.capturing = False
        self._active_bpf_filter = ""
        self.dark_mode = tk.BooleanVar(value=self._config.get("dark_mode", False))
        self._classic_widgets: list[tk.Widget] = []
        self._capture_indicator: tk.Label | None = None
        self._log_text: tk.Text | None = None
        self._log_expanded = False
        self._icon_stack = ExitStack()
        self._icon_image: tk.PhotoImage | None = None
        self.packet_total_var = tk.StringVar(value="数据包 0")
        self.rate_var = tk.StringVar(value="0.0 包/秒")
        self.bytes_rate_var = tk.StringVar(value="0.0 字节/秒")
        self.session_var = tk.StringVar(value="会话 0")
        self.alert_count_var = tk.StringVar(value="告警 0")
        self._last_stats_text = ""
        self._last_error_state: tuple[int, int, int, str] | None = None
        self._filter_after_id: str | None = None
        self.packet_count_var = tk.StringVar(value="已显示 0 条")
        self.alert_packet_indices: list[int] = []
        self._error_packet_indices: list[int] = []
        self._last_error_refresh = 0.0
        self.alerts_placeholder = False
        self._theme = ThemeManager(self)
        try:
            self._theme.theme_use("clam")
        except tk.TclError:
            pass
        self._set_window_icon()
        self._build()
        self._apply_theme()
        self._update_control_states()
        self.after(100, self._load_devices)
        self.after(200, self._tick)
        self.bind_all("<Control-Return>", lambda _: self._start())
        self.bind_all("<Escape>", lambda _: self._stop())
        self.bind_all("<Control-p>", lambda _: self._toggle_pause())
        self.bind_all("<Control-l>", lambda _: self._clear())
        self.protocol("WM_DELETE_WINDOW", self._exit)

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
        colors = build_colors(self.dark_mode.get())
        if self._capture_indicator:
            self._capture_indicator.configure(bg=colors["toolbar"])
        self._save_config()

    def _load_config(self) -> dict:
        try:
            return json.loads(self._config_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_config(self) -> None:
        self._config["dark_mode"] = self.dark_mode.get()
        try:
            self._config_path.write_text(json.dumps(self._config, indent=2), encoding="utf-8")
        except OSError:
            logger.debug("无法保存配置文件 %s", self._config_path, exc_info=True)

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        toolbar = ttk.Frame(self, padding=(10, 6), style="Toolbar.TFrame")
        toolbar.grid(row=0, column=0, sticky=tk.EW)
        toolbar.columnconfigure(1, weight=1)
        toolbar.rowconfigure(2, weight=1)

        ttk.Label(toolbar, text="NetGuard 抓包", style="AppTitle.TLabel").grid(
            row=0, column=0, sticky=tk.W, padx=(0, 14)
        )
        capture_controls = ttk.Frame(toolbar, style="Toolbar.TFrame")
        capture_controls.grid(row=0, column=1, sticky=tk.EW)
        capture_controls.columnconfigure(1, weight=2)
        capture_controls.columnconfigure(3, weight=3)

        ttk.Label(capture_controls, text="网卡", style="Muted.TLabel").grid(row=0, column=0, sticky=tk.W, padx=(0, 6))
        self.device_var = tk.StringVar()
        self.device_box = ttk.Combobox(capture_controls, textvariable=self.device_var, width=28, state="readonly")
        self.device_box.grid(row=0, column=1, sticky=tk.EW, padx=(0, 10))
        self.device_box.bind("<<ComboboxSelected>>", lambda _: self._on_device_selected())
        ttk.Label(capture_controls, text="抓包过滤(BPF)", style="Muted.TLabel").grid(row=0, column=2, sticky=tk.W, padx=(0, 6))
        self.bpf_var = tk.StringVar(value="tcp or udp")
        bpf_entry = ttk.Entry(capture_controls, textvariable=self.bpf_var, style="Filter.TEntry")
        bpf_entry.grid(
            row=0, column=3, sticky=tk.EW, padx=(0, 6)
        )
        bpf_entry.bind("<Return>", lambda _: self._apply_bpf_entry())
        ttk.Button(capture_controls, text="应用BPF", width=7, style="Accent.TButton", command=self._apply_bpf_entry).grid(
            row=0, column=4, sticky=tk.EW, padx=(0, 6)
        )
        ttk.Button(capture_controls, text="BPF 模板", width=8, style="Secondary.TButton", command=self._show_bpf_templates).grid(
            row=0, column=5, sticky=tk.EW
        )

        self.status_var = tk.StringVar(value="正在加载网卡...")
        status_frame = ttk.Frame(toolbar, style="Toolbar.TFrame")
        status_frame.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=(6, 0))
        status_frame.columnconfigure(1, weight=1)
        self._capture_indicator = tk.Label(status_frame, text="●", font=("", 9),
            fg="#536475", bg="#0e1824", borderwidth=0, highlightthickness=0)
        self._capture_indicator.grid(row=0, column=0, sticky=tk.W, padx=(0, 4))
        self._log_text = tk.Text(status_frame, height=2, wrap=tk.WORD, state=tk.DISABLED)
        self._log_text.grid(row=0, column=1, sticky=tk.EW)
        self._classic_widgets.append(self._log_text)
        self._log_expand_btn = ttk.Button(status_frame, text="展开", width=4, style="Secondary.TButton",
                                          command=self._toggle_log)
        self._log_expand_btn.grid(row=0, column=2, sticky=tk.E, padx=(4, 10))

        actions = ttk.Frame(toolbar, style="Toolbar.TFrame")
        actions.grid(row=1, column=0, columnspan=2, sticky=tk.EW, pady=(6, 0))
        actions.columnconfigure(0, weight=1)
        for column in range(1, 6):
            actions.columnconfigure(column, minsize=88)
        self.start_btn = ttk.Button(actions, text="开始", width=8, style="Accent.TButton", command=self._start)
        self.start_btn.grid(row=0, column=1, sticky=tk.EW, padx=(0, 6))
        self.stop_btn = ttk.Button(actions, text="停止", width=8, style="Danger.TButton", command=self._stop)
        self.stop_btn.grid(row=0, column=2, sticky=tk.EW, padx=(0, 6))
        self.pause_btn = ttk.Button(actions, text="暂停", width=8, style="Secondary.TButton", command=self._toggle_pause)
        self.pause_btn.grid(row=0, column=3, sticky=tk.EW, padx=(0, 6))
        ttk.Button(actions, text="清空", width=8, style="Secondary.TButton", command=self._clear).grid(
            row=0, column=4, sticky=tk.EW)
        ttk.Button(actions, text="测试发包", width=10, style="Secondary.TButton", command=self._open_traffic_gen).grid(
            row=1, column=1, sticky=tk.EW, padx=(0, 6), pady=(6, 0))
        ttk.Button(actions, text="网段扫描", width=10, style="Secondary.TButton", command=self._open_subnet_scan).grid(
            row=1, column=2, sticky=tk.EW, padx=(0, 6), pady=(6, 0))
        self.export_alerts_btn = ttk.Button(actions, text="导出告警", width=10, style="Secondary.TButton", command=self._export_alerts)
        self.export_alerts_btn.grid(row=1, column=3, sticky=tk.EW, padx=(0, 6), pady=(6, 0))
        ttk.Checkbutton(actions, text="夜间模式", variable=self.dark_mode, style="Switch.TCheckbutton", command=self._apply_theme).grid(
            row=1, column=4, sticky=tk.W, padx=(0, 6), pady=(6, 0))
        ttk.Button(actions, text="退出", width=8, style="Danger.TButton", command=self._exit).grid(
            row=1, column=5, sticky=tk.EW, pady=(6, 0))

        filters = ttk.Frame(self, padding=(10, 5), style="FilterBar.TFrame")
        filters.grid(row=1, column=0, sticky=tk.EW)
        filters.columnconfigure(1, weight=1)
        ttk.Label(filters, text="显示过滤", style="FilterLabel.TLabel").grid(row=0, column=0, sticky=tk.W, padx=(0, 8))
        self.display_filter = tk.StringVar()
        entry = ttk.Entry(filters, textvariable=self.display_filter, style="Filter.TEntry")
        entry.grid(row=0, column=1, sticky=tk.EW, padx=(0, 8))
        entry.bind("<KeyRelease>", lambda _: self._debounced_refilter())
        ttk.Button(filters, text="过滤模板", width=8, style="Secondary.TButton", command=self._show_display_filter_templates).grid(
            row=0, column=2, sticky=tk.EW, padx=(0, 6)
        )
        ttk.Button(filters, text="应用", width=8, style="Secondary.TButton", command=self._refilter).grid(row=0, column=3, sticky=tk.EW)
        metrics = ttk.Frame(filters, style="FilterBar.TFrame")
        metrics.grid(row=1, column=0, columnspan=4, sticky=tk.W, pady=(5, 0))
        for column, variable in enumerate(
            (self.packet_count_var, self.packet_total_var, self.rate_var, self.bytes_rate_var, self.session_var, self.alert_count_var)
        ):
            ttk.Label(metrics, textvariable=variable, style="FilterLabel.TLabel").grid(row=0, column=column, sticky=tk.W, padx=(0, 12))

        workspace = ttk.PanedWindow(self, orient=tk.VERTICAL, style="Content.TPanedwindow")
        workspace.grid(row=2, column=0, sticky=tk.NSEW, padx=8, pady=(0, 8))
        main_area = ttk.PanedWindow(workspace, orient=tk.HORIZONTAL, style="Content.TPanedwindow")
        bottom_area = ttk.PanedWindow(workspace, orient=tk.HORIZONTAL, style="Content.TPanedwindow")
        workspace.add(main_area, weight=5)
        workspace.add(bottom_area, weight=3)

        packet_frame = ttk.LabelFrame(main_area, text="数据包列表", padding=5)
        details = ttk.PanedWindow(main_area, orient=tk.VERTICAL, style="Content.TPanedwindow")
        main_area.add(packet_frame, weight=3)
        main_area.add(details, weight=2)

        columns = ("time", "src", "dst", "proto", "len", "summary")
        headings = {
            "time": "时间",
            "src": "源地址",
            "dst": "目的地址",
            "proto": "协议",
            "len": "长度",
            "summary": "摘要",
        }
        packet_frame.rowconfigure(0, weight=1)
        packet_frame.columnconfigure(0, weight=1)
        self.table = ttk.Treeview(packet_frame, columns=columns, show="headings", height=14)
        for col, width in zip(columns, [100, 170, 170, 72, 68, 440]):
            self.table.heading(col, text=headings[col], command=lambda c=col: self._sort(c))
            self.table.column(col, width=width, anchor=tk.W)
        self.table.column("len", anchor=tk.E, stretch=False)
        self.table.column("proto", anchor=tk.CENTER, stretch=False)
        table_scroll = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.table.yview)
        table_hscroll = ttk.Scrollbar(packet_frame, orient=tk.HORIZONTAL, command=self.table.xview)
        self.table.configure(yscrollcommand=table_scroll.set, xscrollcommand=table_hscroll.set)
        self.table.grid(row=0, column=0, sticky=tk.NSEW)
        table_scroll.grid(row=0, column=1, sticky=tk.NS)
        table_hscroll.grid(row=1, column=0, sticky=tk.EW)
        self.table.bind("<<TreeviewSelect>>", lambda _: self._show_selected())

        detail_frame = ttk.LabelFrame(details, text="数据包详情", padding=5)
        self.detail = tk.Text(detail_frame, height=7, wrap=tk.NONE)
        self._classic_widgets.append(self.detail)
        self.detail.pack(fill=tk.BOTH, expand=True)
        details.add(detail_frame, weight=3)

        hex_frame = ttk.LabelFrame(details, text="数据包原始字节", padding=5)
        self.hex_view = tk.Text(hex_frame, height=5, wrap=tk.NONE)
        self._classic_widgets.append(self.hex_view)
        self.hex_view.pack(fill=tk.BOTH, expand=True)
        details.add(hex_frame, weight=2)

        alert_error_column = ttk.Frame(bottom_area)
        alert_error_column.columnconfigure(0, weight=1)
        alert_error_column.rowconfigure(0, weight=1)
        alert_error_column.rowconfigure(1, weight=1)

        alert_frame = ttk.LabelFrame(alert_error_column, text="告警日志（双击定位数据包）", padding=5)
        alert_frame.grid(row=0, column=0, sticky=tk.NSEW, pady=(0, 4))
        alert_inner = ttk.Frame(alert_frame)
        alert_inner.pack(fill=tk.BOTH, expand=True)
        self.alerts = tk.Listbox(alert_inner, height=4)
        self._classic_widgets.append(self.alerts)
        self.alerts.bind("<Double-Button-1>", lambda _: self._jump_to_alert_packet())
        alert_scroll = ttk.Scrollbar(alert_inner, orient=tk.VERTICAL, command=self.alerts.yview)
        self.alerts.configure(yscrollcommand=alert_scroll.set)
        self.alerts.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alert_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        error_frame = ttk.LabelFrame(alert_error_column, text="解析问题（截断 / 无效字段 / 协议异常）", padding=5)
        error_frame.grid(row=1, column=0, sticky=tk.NSEW)
        error_header = ttk.Frame(error_frame)
        error_header.pack(fill=tk.X, pady=(0, 4))
        self.error_summary_var = tk.StringVar(value="解析问题 0 | 致命异常 0")
        ttk.Label(error_header, textvariable=self.error_summary_var, style="FilterLabel.TLabel").pack(side=tk.LEFT)
        ttk.Label(error_header, text="异常包不会被丢弃，而是标记问题后继续流转", style="Muted.TLabel").pack(side=tk.RIGHT)
        error_inner = ttk.Frame(error_frame)
        error_inner.pack(fill=tk.BOTH, expand=True)
        self.error_list = tk.Listbox(error_inner, height=4)
        self._classic_widgets.append(self.error_list)
        self.error_list.bind("<Double-Button-1>", lambda _: self._jump_to_error_packet())
        error_scroll = ttk.Scrollbar(error_inner, orient=tk.VERTICAL, command=self.error_list.yview)
        self.error_list.configure(yscrollcommand=error_scroll.set)
        self.error_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        error_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        bottom_area.add(alert_error_column, weight=2)

        stats_frame = ttk.LabelFrame(bottom_area, text="统计信息", padding=5)
        self.stats_text = tk.Text(stats_frame, height=5)
        self._classic_widgets.append(self.stats_text)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        bottom_area.add(stats_frame, weight=1)

        rules_frame = ttk.LabelFrame(bottom_area, text="IDS 规则", padding=5)
        rules_actions = ttk.Frame(rules_frame)
        rules_actions.pack(side=tk.RIGHT, fill=tk.Y, padx=(6, 0))
        self.rules_text = tk.Text(rules_frame, height=5)
        self._classic_widgets.append(self.rules_text)
        self.rules_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Button(rules_actions, text="加载规则", style="Secondary.TButton", command=self._load_rules).pack(fill=tk.X)
        ttk.Button(rules_actions, text="规则模板", style="Secondary.TButton", command=self._show_ids_rule_templates).pack(fill=tk.X, pady=(4, 0))
        ttk.Button(rules_actions, text="自动生成", style="Secondary.TButton",
                   command=self._show_rule_suggestions).pack(fill=tk.X, pady=(4, 0))
        ttk.Button(rules_actions, text="清空规则", style="Secondary.TButton", command=self._clear_rules).pack(fill=tk.X, pady=(4, 0))
        bottom_area.add(rules_frame, weight=1)
        self._bottom_panes = bottom_area
        self._workspace = workspace
        self._main_panes = main_area
        self._set_initial_empty_state()
        self.after(50, self._apply_sash_positions)

    def _load_devices(self) -> None:
        self._log("正在加载网卡...")
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
        self.device_displays = build_device_displays(devices)
        values = [item.display_name for item in self.device_displays]
        self.display_to_device = {item.display_name: item.device.name for item in self.device_displays}
        self.device_box["values"] = values
        _fit_combobox_width(self.device_box, values, max_width=42)
        if values:
            self._apply_recommended_device(f"已加载 {len(values)} 个网卡，已自动选择推荐网卡")
        else:
            self._log("未找到可用网卡")
        self._update_control_states()

    def _set_initial_empty_state(self) -> None:
        self.detail.insert("1.0", "选择左侧数据包后，这里显示协议字段解析详情。")
        self.hex_view.insert("1.0", "选择左侧数据包后，这里显示原始字节（十六进制视图）。")
        self.alerts.insert(tk.END, "命中 IDS 规则后将在这里显示告警；双击告警可定位对应数据包。")
        self.alerts_placeholder = True
        self.error_list.insert(tk.END, "开始抓包后，这里显示解析异常数据包；双击可定位到对应数据包。")
        self.stats_text.insert("1.0", "开始抓包后，这里显示总字节、丢弃数量、协议分布和速率。")

    def _update_control_states(self) -> None:
        has_device = bool(self._selected_device_name())
        self.start_btn.configure(state=tk.NORMAL if has_device and not self.capturing else tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL if self.capturing else tk.DISABLED)
        self.pause_btn.configure(state=tk.NORMAL if self.capturing else tk.DISABLED)
        self.export_alerts_btn.configure(state=tk.NORMAL if self._real_alert_count() > 0 else tk.DISABLED)
        self._update_indicator()

    def _log(self, msg: str) -> None:
        self.status_var.set(msg)
        if self._log_text is None:
            return
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.insert(tk.END, f"{msg}\n")
        lines = int(self._log_text.index("end-1c").split(".")[0])
        if lines > 200:
            self._log_text.delete("1.0", f"{lines - 150}.0")
        self._log_text.see(tk.END)
        self._log_text.configure(state=tk.DISABLED)

    def _toggle_log(self) -> None:
        self._log_expanded = not self._log_expanded
        if self._log_expanded:
            self._log_text.configure(height=12)
            self._log_expand_btn.configure(text="收起")
        else:
            self._log_text.configure(height=2)
            self._log_expand_btn.configure(text="展开")

    def _update_indicator(self) -> None:
        if self._capture_indicator is None:
            return
        if self.capturing and not self.paused:
            self._capture_indicator.configure(fg="#3ddc84")
        elif self.capturing and self.paused:
            self._capture_indicator.configure(fg="#ffcc66")
        else:
            self._capture_indicator.configure(fg="#536475")

    def _real_alert_count(self) -> int:
        return 0 if self.alerts_placeholder else self.alerts.size()

    def _selected_device_name(self) -> str:
        selected = self.device_var.get()
        return self.display_to_device.get(selected, selected)

    def _selected_device_display(self) -> DeviceDisplay | None:
        device_name = self._selected_device_name()
        for item in self.device_displays:
            if item.device.name == device_name:
                return item
        return None

    def _recommended_device_display(self) -> DeviceDisplay | None:
        return recommend_device_display(self.device_displays)

    def _apply_recommended_device(self, prefix: str = "已自动应用推荐网卡") -> None:
        selected = self._recommended_device_display()
        if not selected:
            self._log("暂无可推荐网卡")
            self._update_control_states()
            return
        self.device_var.set(selected.display_name)
        reason = device_recommendation_reason(selected)
        self._log(f"{prefix}：{selected.friendly_name}（{reason}）")
        self._update_control_states()

    def _on_device_selected(self) -> None:
        selected = self._selected_device_display()
        recommended = self._recommended_device_display()
        if selected and recommended:
            if selected.device.name == recommended.device.name:
                reason = device_recommendation_reason(selected)
                self._log(f"已选择推荐网卡：{selected.friendly_name}（{reason}）")
            else:
                reason = device_recommendation_reason(recommended)
                self._log(f"非推荐网卡，建议选择 {recommended.friendly_name}（{reason}）")
        self._update_control_states()

    def _show_device_error(self, error: str) -> None:
        logger.error("网卡加载失败：%s", error)
        self._log("网卡加载失败")
        messagebox.showwarning("Npcap/libpcap", error)

    def _load_rules(self) -> None:
        try:
            failed = self.pipeline.load_rules(self.rules_text.get("1.0", tk.END))
            loaded = len(self.pipeline.rules.rules)
            if failed:
                self._log(f"已加载 {loaded} 条规则，跳过 {failed} 条无效规则")
            else:
                self._log(f"已加载 {loaded} 条 IDS 规则")
        except Exception as exc:
            messagebox.showerror("规则错误", str(exc))

    def _clear_rules(self) -> None:
        self.rules_text.delete("1.0", tk.END)
        self._log("已清空 IDS 规则")

    def _open_traffic_gen(self) -> None:
        TrafficGenDialog(self)

    def _open_subnet_scan(self) -> None:
        display = self._selected_device_display()
        if display is None:
            messagebox.showwarning("网段扫描", "请先在主窗口选择一个网卡。")
            return
        SubnetScanDialog(self, display, self.device_displays, self.bpf_var,
                        on_switch_device=self._switch_to_device,
                        on_add_bpf_template=self._add_bpf_template)

    def _switch_to_device(self, device_name: str) -> None:
        for item in self.device_displays:
            if item.device.name == device_name:
                self.device_var.set(item.display_name)
                self._on_device_selected()
                self._log(f"网段扫描：已切换网卡到 {item.display_name}")
                return

    def _add_bpf_template(self, title: str, description: str, value: str) -> None:
        template = InputTemplate(title, description, value)
        if not any(t.value == value for t in BPF_TEMPLATES):
            BPF_TEMPLATES.insert(0, template)
            self._log(f"网段扫描：已添加 BPF 模板「{title}」")

    def _show_bpf_templates(self) -> None:
        TemplateDialog(self, "抓包过滤模板（BPF）", BPF_TEMPLATES, lambda values: self._apply_bpf_template(values[0]))

    def _apply_bpf_template(self, value: str) -> None:
        self._apply_bpf_filter(value, title="更换 BPF 模板")

    def _apply_bpf_entry(self) -> None:
        self._apply_bpf_filter(self.bpf_var.get(), title="应用 BPF 过滤")

    def _format_bpf_for_log(self, value: str) -> str:
        return value or "无过滤"

    def _apply_bpf_filter(self, value: str, *, title: str) -> None:
        value = value.strip()
        if self.capturing:
            device = self._selected_device_name()
            if not device:
                messagebox.showwarning("网卡", "请先选择一个网络接口。")
                return
            alert_count = self._real_alert_count()
            packet_count = len(self.events)
            detail = f"当前已捕获 {packet_count} 个数据包"
            if alert_count:
                detail += f"，触发 {alert_count} 条 IDS 告警"
            if not messagebox.askokcancel(
                title,
                f"应用 BPF 将清空当前抓包数据并使用新过滤条件重新开始。\n\n"
                f"{detail}。\n\n"
                f"建议先导出告警数据（导出告警按钮），是否继续更换？",
            ):
                current = self._format_bpf_for_log(getattr(self, "_active_bpf_filter", ""))
                self._log(f"已取消应用 BPF，当前抓包仍使用：{current}")
                return
            self.bpf_var.set(value)
            self.paused = False
            self.pause_btn.configure(text="暂停")
            self.pipeline.stop()
            self.pipeline.reset_state()
            self._clear_capture_data()
            try:
                self._load_rules()
                self.pipeline.start(device, value)
                self.capturing = True
                self._active_bpf_filter = value
                self._log(f"已应用 BPF 并重新开始抓包：{self._format_bpf_for_log(value)}")
                self._update_control_states()
            except Exception as exc:
                self.capturing = False
                self._active_bpf_filter = ""
                self._update_control_states()
                self._log("应用 BPF 后抓包启动失败")
                messagebox.showerror("抓包错误", str(exc))
        else:
            self.bpf_var.set(value)
            self._log(f"BPF 过滤条件已更新，开始抓包时生效：{self._format_bpf_for_log(value)}")

    def _clear_capture_data(self) -> None:
        self.events.clear()
        self.event_offset = 0
        self.filtered.clear()
        self.alert_packet_indices.clear()
        self._error_packet_indices.clear()
        self._last_error_refresh = 0.0
        self._last_stats_text = ""
        self._last_error_state = None
        self.table.delete(*self.table.get_children())
        self.alerts.delete(0, tk.END)
        self.alerts_placeholder = False
        self.error_list.delete(0, tk.END)
        self.detail.delete("1.0", tk.END)
        self.hex_view.delete("1.0", tk.END)
        self.stats_text.delete("1.0", tk.END)
        self._update_packet_count()
        self._set_initial_empty_state()

    def _show_display_filter_templates(self) -> None:
        TemplateDialog(
            self,
            "显示过滤模板",
            DISPLAY_FILTER_TEMPLATES,
            lambda values: self._apply_display_filter_template(values[0]),
        )

    def _show_ids_rule_templates(self) -> None:
        TemplateDialog(self, "IDS 常用规则模板", IDS_RULE_TEMPLATES, self._append_generated_rules, multi_select=True)

    def _apply_sash_positions(self) -> None:
        w = self.winfo_width()
        h = self.winfo_height()
        if w > 100 and h > 100:
            self._main_panes.sashpos(0, int(w * 0.60))
            self._workspace.sashpos(0, int(h * 0.58))
            self._bottom_panes.sashpos(0, int(w * 0.48))
            self._bottom_panes.sashpos(1, int(w * 0.72))

    def _apply_display_filter_template(self, value: str) -> None:
        self.display_filter.set(value)
        self._refilter()

    def _show_rule_suggestions(self) -> None:
        if not self.events:
            messagebox.showinfo("自动生成规则", "当前还没有可用于生成 IDS 规则的 TCP、UDP、HTTP 或 DNS 数据包。")
            return
        self._log("正在分析数据包生成 IDS 规则建议...")
        thread = threading.Thread(target=self._compute_rule_suggestions, name="netguard-suggestions", daemon=True)
        thread.start()

    def _compute_rule_suggestions(self) -> None:
        try:
            suggestions = generate_rule_suggestions((event.packet for event in self.events), limit=8)
        except Exception:
            logger.exception("规则建议生成失败")
            self.after(0, lambda: messagebox.showerror("自动生成规则", "生成失败，请重试。"))
            return
        self.after(0, lambda: self._show_suggestions_result(suggestions))

    def _show_suggestions_result(self, suggestions: list) -> None:
        if not suggestions:
            self._log("自动生成规则：无可用建议")
            messagebox.showinfo("自动生成规则", "当前还没有可用于生成 IDS 规则的 TCP、UDP、HTTP 或 DNS 数据包。")
            return
        self._log(f"自动生成规则：已生成 {len(suggestions)} 条建议")
        RuleSuggestionDialog(self, suggestions, self._append_generated_rules)

    def _append_generated_rules(self, rules: list[str]) -> None:
        if not rules:
            return
        current = self.rules_text.get("1.0", tk.END).strip()
        new_text = "\n".join(rules)
        text = f"{current}\n{new_text}" if current else new_text
        self.rules_text.delete("1.0", tk.END)
        self.rules_text.insert("1.0", text)
        self._log(f"已添加 {len(rules)} 条自动生成的 IDS 规则")

    def _start(self) -> None:
        device = self._selected_device_name()
        if not device:
            messagebox.showwarning("网卡", "请先选择一个网络接口。")
            return
        bpf_filter = self.bpf_var.get().strip()
        self.bpf_var.set(bpf_filter)
        try:
            self._load_rules()
            self.pipeline.start(device, bpf_filter)
            self.capturing = True
            self._active_bpf_filter = bpf_filter
            self.paused = False
            self.pause_btn.configure(text="暂停")
            self._log(f"正在监听 {self.device_var.get()}，BPF：{self._format_bpf_for_log(bpf_filter)}")
            self._update_control_states()
        except Exception as exc:
            self.capturing = False
            self._active_bpf_filter = ""
            self._update_control_states()
            self._log("抓包启动失败")
            messagebox.showerror("抓包错误", str(exc))

    def _stop(self) -> None:
        if not self.capturing:
            return
        if not messagebox.askokcancel("停止抓包", "确定要停止抓包吗？"):
            return
        self.pipeline.stop()
        self.capturing = False
        self._active_bpf_filter = ""
        self.paused = False
        self.pause_btn.configure(text="暂停")
        self._log("已停止抓包")
        self._update_control_states()

    def _exit(self) -> None:
        was_capturing = self.capturing
        if was_capturing:
            msg = "抓包正在进行中，确定要退出程序吗？"
        elif self.events:
            msg = f"已捕获 {len(self.events)} 个数据包，确定要退出程序吗？"
        else:
            msg = "确定要退出程序吗？"
        if not messagebox.askokcancel("退出程序", msg):
            return
        if was_capturing:
            self.pipeline.stop()
            self.capturing = False
            self.paused = False
        self.destroy()

    def _toggle_pause(self) -> None:
        if not self.capturing:
            return
        self.paused = not self.paused
        if self.paused:
            self._pause_event_total = self.event_offset + len(self.events)
            self.pause_btn.configure(text="恢复")
            self._log("已暂停刷新")
        else:
            self.pause_btn.configure(text="暂停")
            self._log("已恢复刷新")
            self._refilter()
            self._catch_up_paused_alerts()
        self._update_indicator()

    def _catch_up_paused_alerts(self) -> None:
        pause_total = getattr(self, '_pause_event_total', 0)
        for local_idx, event in enumerate(self.events):
            global_idx = self.event_offset + local_idx
            if global_idx < pause_total:
                continue
            for alert in event.alerts:
                if self.alerts_placeholder:
                    self.alerts.delete(0, tk.END)
                    self.alerts_placeholder = False
                self.alerts.insert(
                    0,
                    f"{alert.timestamp:.3f} {alert.msg} {alert.src}:{alert.src_port} -> {alert.dst}:{alert.dst_port}",
                )
                self.alerts.itemconfigure(0, fg=self._alert_color(alert.msg))
                self.alert_packet_indices.insert(0, global_idx)
        self._trim_alerts()
        self._update_control_states()

    def _update_packet_count(self) -> None:
        total = len(self.filtered)
        self.packet_count_var.set(f"已显示 {total} 条")

    def _clear(self) -> None:
        self._clear_capture_data()
        self._update_control_states()

    def _tick(self) -> None:
        if self.__dict__.get('_destroyed', False):
            return
        try:
            t0 = time.monotonic()
            capture_error = self.pipeline.capture_error
            if capture_error and self.capturing:
                self._log(f"抓包错误：{capture_error}")
                self.pipeline.stop()
                self.capturing = False
                self.paused = False
                self.pause_btn.configure(text="暂停")
                self._log("抓包已因错误停止，请检查网卡权限或重新选择网卡后重试")
                self._update_control_states()
            events = self.pipeline.pump(PUMP_BATCH)
            if events:
                start_idx = self.event_offset + len(self.events)
                self.events.extend(events)
                if len(self.events) > MAX_EVENTS:
                    trim_count = len(self.events) - MAX_EVENTS
                    del self.events[:trim_count]
                    self.event_offset += trim_count
                    self.filtered = [idx for idx in self.filtered if idx >= self.event_offset]
                    self.alert_packet_indices = [idx for idx in self.alert_packet_indices if idx >= self.event_offset]
                if not self.paused:
                    self._append_alerts(events, start_idx)
                    self._append_events(events, start_idx)
            if not self.paused:
                self._refresh_stats()
            elapsed_ms = (time.monotonic() - t0) * 1000
            if elapsed_ms > TICK_MS * 2:
                logger.debug("tick 耗时 %.0fms（处理 %d 事件）", elapsed_ms, len(events))
        except Exception:
            logger.exception("_tick 崩溃，重新调度")
        self.after(TICK_MS, self._tick)

    def _append_alerts(self, events: list[PacketEvent], start_idx: int) -> None:
        for offset, event in enumerate(events):
            idx = start_idx + offset
            for alert in event.alerts:
                if self.alerts_placeholder:
                    self.alerts.delete(0, tk.END)
                    self.alerts_placeholder = False
                self.alerts.insert(
                    0,
                    f"{alert.timestamp:.3f} {alert.msg} {alert.src}:{alert.src_port} -> {alert.dst}:{alert.dst_port}",
                )
                self.alerts.itemconfigure(0, fg=self._alert_color(alert.msg))
                self.alert_packet_indices.insert(0, idx)
        self._trim_alerts()
        self._update_control_states()

    def _append_events(self, events: list[PacketEvent], start_idx: int | None = None) -> None:
        needle = self.display_filter.get().strip().lower()
        if start_idx is None:
            start_idx = self.event_offset + len(self.events) - len(events)
        for offset, event in enumerate(events):
            idx = start_idx + offset
            if needle and needle not in _search_text(event.packet):
                continue
            self.filtered.append(idx)
            self._insert_packet(idx, event.packet)
        self._trim_table()
        self._update_packet_count()
        self._update_control_states()

    @staticmethod
    def _alert_color(msg: str) -> str:
        lower = msg.lower()
        if any(k in lower for k in ("attack", "overflow", "injection", "exploit", "trojan", "malware")):
            return "#ff6b5f"
        if any(k in lower for k in ("scan", "suspicious", "policy", "anomaly", "attempt")):
            return "#ffcc66"
        return "#3ddc84"

    def _insert_packet(self, idx: int, packet: PacketInfo) -> None:
        tags = ["even" if idx % 2 == 0 else "odd", packet.protocol.lower()]
        if packet.issues:
            tags.append("issue")
        self.table.insert(
            "",
            0,
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
        excess = len(rows) - MAX_TABLE_ROWS
        if excess >= TABLE_TRIM_CHUNK:
            rows_set = set(rows)
            oldest = [str(idx) for idx in self.filtered if str(idx) in rows_set][:excess]
            for iid in oldest:
                self.table.delete(iid)
            removed = {int(iid) for iid in oldest}
            self.filtered = [idx for idx in self.filtered if idx not in removed]
            self._log(f"表格已裁剪 {len(removed)} 行")

    def _trim_alerts(self) -> None:
        if self.alerts_placeholder:
            return
        extra = self.alerts.size() - MAX_ALERT_ROWS
        if extra > 0:
            self.alerts.delete(self.alerts.size() - extra, tk.END)
            del self.alert_packet_indices[-extra:]
            self._log(f"告警已裁剪 {extra} 条")

    def _show_selected(self) -> None:
        selected = self.table.selection()
        if not selected:
            return
        idx = int(selected[0])
        event = self._event_at(idx)
        if event is None:
            return
        packet = event.packet
        self.detail.delete("1.0", tk.END)
        self.detail.insert(tk.END, _format_packet(packet))
        self.hex_view.delete("1.0", tk.END)
        self.hex_view.insert(tk.END, hex_dump(packet.raw))

    def _event_at(self, idx: int) -> PacketEvent | None:
        local_idx = idx - self.event_offset
        if local_idx < 0 or local_idx >= len(self.events):
            return None
        return self.events[local_idx]

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

    def _jump_to_error_packet(self) -> None:
        selection = self.error_list.curselection()
        if not selection:
            return
        error_idx = selection[0]
        if error_idx >= len(self._error_packet_indices):
            return
        packet_idx = self._error_packet_indices[error_idx]
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
        start = max(0, len(self.events) - MAX_TABLE_ROWS)
        for local_idx in range(start, len(self.events)):
            event = self.events[local_idx]
            real_idx = self.event_offset + local_idx
            if not needle or needle in _search_text(event.packet):
                self.filtered.append(real_idx)
                self._insert_packet(real_idx, event.packet)
        self._update_packet_count()

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
        self.alert_count_var.set(f"告警 {self._real_alert_count()}")
        dropped = self.pipeline.dropped_packets
        header = f"总字节：{snap.total_bytes:,}"
        if dropped:
            header += f"  丢弃：{dropped}"
        lines = [header, ""]
        total = sum(snap.protocol_counts.values()) or 1
        max_bar = 28
        for proto in ("TCP", "UDP", "HTTP", "DNS", "ICMP", "OTHER"):
            count = snap.protocol_counts.get(proto, 0)
            if count == 0:
                continue
            bar_len = max(1, int(count / total * max_bar))
            bar = "█" * bar_len
            lines.append(f"  {proto:<5} {bar} {count}")
        stats_text = "\n".join(lines)
        if stats_text != self._last_stats_text:
            self.stats_text.delete("1.0", tk.END)
            self.stats_text.insert(tk.END, stats_text)
            self._last_stats_text = stats_text
        self._refresh_errors()

    def _refresh_errors(self) -> None:
        dropped = self.pipeline.dropped_packets
        parse_errs = self.pipeline.parse_errors
        issue_count = 0
        recent_issues: list[str] = []
        issue_indices: list[int] = []
        # 从最新事件向旧事件遍历，收集最多 50 条异常及对应包索引
        start = max(0, len(self.events) - 300)
        for local_idx in range(len(self.events) - 1, start - 1, -1):
            event = self.events[local_idx]
            if event.packet.issues:
                issue_count += 1
                if len(recent_issues) < 50:
                    global_idx = self.event_offset + local_idx
                    for issue in reversed(event.packet.issues):
                        if len(recent_issues) >= 50:
                            break
                        recent_issues.append(
                            f"{event.packet.timestamp:.3f} [{issue.layer}] {issue.message} "
                            f"{event.packet.src}:{event.packet.src_port or ''} -> "
                            f"{event.packet.dst}:{event.packet.dst_port or ''}"
                        )
                        issue_indices.append(global_idx)
        # 变更检测 + 节流：最多每 2 秒刷新一次 Listbox
        new_state = (dropped, parse_errs, issue_count, "\n".join(recent_issues[:50]))
        now = time.monotonic()
        if new_state == self._last_error_state and now - self._last_error_refresh < 2.0:
            return
        self._last_error_state = new_state
        self._last_error_refresh = now
        parts = [f"解析问题 {issue_count}"]
        if dropped:
            parts.append(f"队列丢弃 {dropped}")
        parts.append(f"致命异常 {parse_errs}")
        self.error_summary_var.set(" | ".join(parts))
        self.error_list.delete(0, tk.END)
        self._error_packet_indices = issue_indices
        if not recent_issues:
            self.error_list.insert(tk.END, "暂无异常数据包")
        else:
            for line in recent_issues:
                self.error_list.insert(tk.END, line)

    def _export_alerts(self) -> None:
        if self._real_alert_count() == 0:
            messagebox.showinfo("导出告警", "当前没有可导出的 IDS 告警。")
            return
        path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("日志", "*.log"), ("文本", "*.txt")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                for item in self.alerts.get(0, tk.END):
                    handle.write(item + "\n")
        except OSError as exc:
            messagebox.showerror("导出错误", f"无法写入文件：{exc}")

    def destroy(self) -> None:
        self._destroyed = True
        try:
            self.pipeline.stop()
        except Exception:
            pass
        self.capturing = False
        try:
            self._icon_stack.close()
        except Exception:
            pass
        super().destroy()


class RuleSuggestionDialog(tk.Toplevel):
    def __init__(
        self,
        parent: NetGuardApp,
        suggestions: list[RuleSuggestion],
        on_apply: Callable[[list[str]], None],
    ) -> None:
        super().__init__(parent)
        self.title("自动生成 IDS 规则")
        self.transient(parent)
        self.grab_set()
        _set_initial_window_size(self, 840, 520, 700, 440)
        self._suggestions = suggestions
        self._on_apply = on_apply
        colors = build_colors(parent.dark_mode.get())
        self.configure(background=colors["bg"])

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        body = ttk.Frame(self, padding=8)
        body.grid(row=0, column=0, sticky=tk.NSEW)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)

        self.listbox = tk.Listbox(body, selectmode=tk.EXTENDED, height=8)
        self.listbox.configure(
            background=colors["field"],
            foreground=colors["text"],
            selectbackground=colors["select"],
            selectforeground="#ffffff" if parent.dark_mode.get() else colors["text"],
            highlightbackground=colors["border"],
            highlightcolor=colors["accent"],
        )
        self.listbox.grid(row=0, column=0, sticky=tk.NSEW)
        scroll = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky=tk.NS)

        self.detail = tk.Text(body, height=8, wrap=tk.WORD)
        self.detail.configure(
            background=colors["field"],
            foreground=colors["text"],
            insertbackground=colors["text"],
            selectbackground=colors["select"],
            selectforeground="#ffffff" if parent.dark_mode.get() else colors["text"],
            highlightbackground=colors["border"],
            highlightcolor=colors["accent"],
            relief=tk.FLAT,
        )
        self.detail.grid(row=1, column=0, columnspan=2, sticky=tk.NSEW, pady=(8, 0))

        actions = ttk.Frame(self, padding=(8, 0, 8, 8))
        actions.grid(row=1, column=0, sticky=tk.EW)
        actions.columnconfigure(0, weight=1)
        ttk.Button(actions, text="采用选中规则", style="Accent.TButton", command=self._apply).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(actions, text="取消", style="Secondary.TButton", command=self.destroy).grid(row=0, column=2)

        for suggestion in suggestions:
            self.listbox.insert(tk.END, f"{suggestion.title}  命中 {suggestion.match_count} 个已捕获包")
        self.listbox.selection_set(0)
        self.listbox.bind("<<ListboxSelect>>", lambda _: self._refresh_detail())
        self._refresh_detail()

    def _refresh_detail(self) -> None:
        selected = self.listbox.curselection()
        self.detail.delete("1.0", tk.END)
        if not selected:
            return
        lines: list[str] = []
        for index in selected:
            suggestion = self._suggestions[index]
            lines.extend([suggestion.description, suggestion.rule, ""])
        self.detail.insert("1.0", "\n".join(lines).strip())

    def _apply(self) -> None:
        selected = self.listbox.curselection()
        if not selected:
            messagebox.showwarning("自动生成规则", "请先选择至少一条规则。", parent=self)
            return
        self._on_apply([self._suggestions[index].rule for index in selected])
        self.destroy()


class TemplateDialog(tk.Toplevel):
    def __init__(
        self,
        parent: NetGuardApp,
        title: str,
        templates: list[InputTemplate],
        on_apply: Callable[[list[str]], None],
        multi_select: bool = False,
    ) -> None:
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.grab_set()
        _set_initial_window_size(self, 820, 480, 680, 400)
        self._templates = templates
        self._on_apply = on_apply
        self._multi_select = multi_select
        self._value_var = tk.StringVar()
        colors = build_colors(parent.dark_mode.get())
        self.configure(background=colors["bg"])

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        body = ttk.Frame(self, padding=8)
        body.grid(row=0, column=0, sticky=tk.NSEW)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)

        mode = tk.EXTENDED if multi_select else tk.BROWSE
        self.listbox = tk.Listbox(body, selectmode=mode, height=8)
        self.listbox.configure(
            background=colors["field"],
            foreground=colors["text"],
            selectbackground=colors["select"],
            selectforeground="#ffffff" if parent.dark_mode.get() else colors["text"],
            highlightbackground=colors["border"],
            highlightcolor=colors["accent"],
        )
        self.listbox.grid(row=0, column=0, sticky=tk.NSEW)
        scroll = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky=tk.NS)

        self.detail = tk.Text(body, height=7, wrap=tk.WORD)
        self.detail.configure(
            background=colors["field"],
            foreground=colors["text"],
            insertbackground=colors["text"],
            selectbackground=colors["select"],
            selectforeground="#ffffff" if parent.dark_mode.get() else colors["text"],
            highlightbackground=colors["border"],
            highlightcolor=colors["accent"],
            relief=tk.FLAT,
        )
        self.detail.grid(row=1, column=0, columnspan=2, sticky=tk.NSEW, pady=(8, 0))
        self.detail.configure(state=tk.DISABLED)

        if not multi_select:
            value_row = ttk.Frame(body)
            value_row.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=(8, 0))
            value_row.columnconfigure(1, weight=1)
            ttk.Label(value_row, text="应用内容", style="Muted.TLabel").grid(row=0, column=0, sticky=tk.W, padx=(0, 6))
            ttk.Entry(value_row, textvariable=self._value_var, style="Filter.TEntry").grid(row=0, column=1, sticky=tk.EW)

        actions = ttk.Frame(self, padding=(8, 0, 8, 8))
        actions.grid(row=1, column=0, sticky=tk.EW)
        actions.columnconfigure(0, weight=1)
        ttk.Button(actions, text="采用选中项", style="Accent.TButton", command=self._apply).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(actions, text="取消", style="Secondary.TButton", command=self.destroy).grid(row=0, column=2)

        for template in templates:
            self.listbox.insert(tk.END, template.title)
        self.listbox.selection_set(0)
        self.listbox.bind("<<ListboxSelect>>", lambda _: self._refresh_detail())
        self.listbox.bind("<Double-Button-1>", lambda _: self._apply())
        self._refresh_detail()

    def _refresh_detail(self) -> None:
        selected = self.listbox.curselection()
        self.detail.configure(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)
        if not selected:
            self.detail.configure(state=tk.DISABLED)
            return
        lines: list[str] = []
        for index in selected:
            template = self._templates[index]
            lines.extend([template.description, template.value, ""])
        if not self._multi_select:
            self._value_var.set(self._templates[selected[0]].value)
        self.detail.insert("1.0", "\n".join(lines).strip())
        self.detail.configure(state=tk.DISABLED)

    def _apply(self) -> None:
        selected = self.listbox.curselection()
        if not selected:
            messagebox.showwarning("模板", "请先选择至少一项。", parent=self)
            return
        if not self._multi_select:
            selected = selected[:1]
            value = self._value_var.get().strip()
            if not value:
                messagebox.showwarning("模板", "应用内容不能为空。", parent=self)
                return
            values = [value]
        else:
            values = [self._templates[index].value for index in selected]
        callback = self._on_apply
        self.destroy()
        self.master.after_idle(lambda: callback(values))


class TrafficGenDialog(tk.Toplevel):
    def __init__(self, parent: NetGuardApp) -> None:
        super().__init__(parent)
        self.title("测试发包器")
        self.transient(parent)
        self.grab_set()
        _set_initial_window_size(self, 860, 680, 700, 560)
        self._parent = parent
        self._inject = parent.pipeline.inject_test_packet
        self._generator = TrafficGenerator()
        self._sent_count = 0
        self._checked_template_ids: set[str] = set()
        self._visible_templates: list[PacketTemplate] = []
        self._after_ids: list[str] = []
        colors = build_colors(parent.dark_mode.get())
        self.configure(background=colors["bg"])
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        # 顶部提示行
        self._capture_warning = tk.Label(self, text='⚠ 请先在主窗口点击「开始」启动抓包，再使用自动发包',
            font=parent._theme.font_small, fg="#ffcc66", bg=colors["bg"], anchor=tk.W, pady=4, padx=8)
        self._capture_warning.grid(row=0, column=0, sticky=tk.EW)
        if parent.capturing:
            self._capture_warning.grid_remove()

        # 筛选栏
        header = ttk.Frame(self, padding=(8, 4, 8, 0))
        header.grid(row=1, column=0, sticky=tk.EW)
        self._select_label = tk.StringVar(value="已勾选 0 种")
        ttk.Label(header, textvariable=self._select_label, style="FilterLabel.TLabel").pack(side=tk.LEFT)
        mode_frame = ttk.Frame(header)
        mode_frame.pack(side=tk.RIGHT)
        self._mode_var = tk.StringVar(value="all")
        ttk.Radiobutton(mode_frame, text="全部", variable=self._mode_var, value="all",
                        command=self._filter_list).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Radiobutton(mode_frame, text="正常包", variable=self._mode_var, value="normal",
                        command=self._filter_list).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Radiobutton(mode_frame, text="异常包", variable=self._mode_var, value="abnormal",
                        command=self._filter_list).pack(side=tk.LEFT)

        # 模板列表
        list_frame = ttk.Frame(self, padding=(8, 4))
        list_frame.grid(row=2, column=0, sticky=tk.NSEW)
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        self._listbox = tk.Listbox(list_frame, selectmode=tk.BROWSE, height=14)
        self._listbox.configure(
            background=colors["field"], foreground=colors["text"],
            selectbackground=colors["select"],
            selectforeground="#ffffff" if parent.dark_mode.get() else colors["text"],
            highlightbackground=colors["border"], highlightcolor=colors["accent"],
        )
        self._listbox.grid(row=0, column=0, sticky=tk.NSEW)
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self._listbox.yview)
        self._listbox.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky=tk.NS)

        # 快捷操作行
        quick_bar = ttk.Frame(self, padding=(8, 4, 8, 0))
        quick_bar.grid(row=3, column=0, sticky=tk.EW)
        ttk.Button(quick_bar, text="全选", style="Secondary.TButton", command=self._select_all).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(quick_bar, text="取消全选", style="Secondary.TButton", command=self._deselect_all).pack(side=tk.LEFT)
        self._desc_var = tk.StringVar()
        ttk.Label(quick_bar, textvariable=self._desc_var, style="Muted.TLabel",
                  anchor=tk.E, wraplength=400).pack(side=tk.RIGHT)

        # 操作按钮行
        action_bar = ttk.Frame(self, padding=(8, 8, 8, 8))
        action_bar.grid(row=4, column=0, sticky=tk.EW)
        self._gen_status_var = tk.StringVar(value="就绪 — 勾选模板后点击开始，每 0.5 秒轮询发送")
        ttk.Label(action_bar, textvariable=self._gen_status_var, style="Status.TLabel").pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._toggle_btn = ttk.Button(action_bar, text="开始发包", style="Accent.TButton", command=self._toggle)
        self._toggle_btn.pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(action_bar, text="手动发一次", style="Secondary.TButton", command=self._send_once).pack(side=tk.RIGHT)

        self._populate_list()
        self._update_select_label()
        self._listbox.bind("<<ListboxSelect>>", lambda _: self._on_selection_change())
        self._listbox.bind("<ButtonRelease-1>", self._toggle_clicked_template)
        self._listbox.bind("<space>", self._toggle_focused_template)
        self._listbox.bind("<Return>", self._toggle_focused_template)
        self.after(200, self._check_capture_state)

    def _schedule(self, delay_ms: int, callback) -> None:
        aid = self.after(delay_ms, callback)
        self._after_ids.append(aid)

    def _on_close(self) -> None:
        if self._generator.running:
            self._parent._log("测试发包：窗口关闭，已自动停止发包")
        self._generator.stop()
        for aid in self._after_ids:
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        self._after_ids.clear()
        self.destroy()

    def _check_capture_state(self) -> None:
        if self._parent.capturing:
            self._capture_warning.grid_remove()
        else:
            self._capture_warning.grid()
        if not self._generator.running:
            self._schedule(300, self._check_capture_state)

    def _populate_list(self, selected_index: int | None = None) -> None:
        self._listbox.delete(0, tk.END)
        mode = self._mode_var.get()
        self._visible_templates = []
        for template in TEMPLATES:
            if mode != "all" and template.category != mode:
                continue
            self._visible_templates.append(template)
            mark = "☑" if template.id in self._checked_template_ids else "☐"
            prefix = "[正常]" if template.category == "normal" else "[异常]"
            self._listbox.insert(tk.END, f"{mark} {prefix} {template.name}  ({template.protocol})")
        if selected_index is not None and self._visible_templates:
            index = min(selected_index, len(self._visible_templates) - 1)
            self._listbox.selection_set(index)
            self._listbox.activate(index)
            self._listbox.see(index)

    def _filter_list(self) -> None:
        self._populate_list()
        self._update_select_label()
        self._desc_var.set("")

    def _get_selected_templates(self) -> list[PacketTemplate]:
        return [template for template in TEMPLATES if template.id in self._checked_template_ids]

    def _update_select_label(self) -> None:
        count = len(self._checked_template_ids)
        self._select_label.set(f"已勾选 {count} 种" if count else "已勾选 0 种")

    def _on_selection_change(self) -> None:
        selection = self._listbox.curselection()
        if selection and selection[0] < len(self._visible_templates):
            self._desc_var.set(self._visible_templates[selection[0]].description)
        else:
            self._desc_var.set("")

    def _select_all(self) -> None:
        self._checked_template_ids.update(template.id for template in self._visible_templates)
        self._populate_list()
        self._update_select_label()

    def _deselect_all(self) -> None:
        for template in self._visible_templates:
            self._checked_template_ids.discard(template.id)
        self._populate_list()
        self._update_select_label()

    def _toggle_clicked_template(self, event) -> None:
        if not self._visible_templates:
            return
        index = self._listbox.nearest(event.y)
        bbox = self._listbox.bbox(index)
        if not bbox:
            return
        _x, y, _width, height = bbox
        if event.y < y or event.y > y + height:
            return
        self._toggle_template_at(index)

    def _toggle_focused_template(self, _event=None) -> str:
        selection = self._listbox.curselection()
        if not selection:
            return "break"
        self._toggle_template_at(selection[0])
        return "break"

    def _toggle_template_at(self, index: int) -> None:
        if index < 0 or index >= len(self._visible_templates):
            return
        template = self._visible_templates[index]
        if template.id in self._checked_template_ids:
            self._checked_template_ids.remove(template.id)
        else:
            self._checked_template_ids.add(template.id)
        self._populate_list(selected_index=index)
        self._update_select_label()
        self._desc_var.set(template.description)

    def _send_once(self) -> None:
        if not self._parent.capturing:
            self._gen_status_var.set("⚠ 请先启动抓包")
            return
        templates = self._get_selected_templates()
        if not templates:
            self._gen_status_var.set("⚠ 请先勾选至少一种测试包类型")
            return
        for template in templates:
            try:
                self._inject(template.build())
            except Exception as exc:
                message = str(exc) or exc.__class__.__name__
                self._gen_status_var.set(f"⚠ 发包失败：{message}")
                self._parent._log(f"测试发包失败：{template.name} - {message}")
                return
        self._sent_count += len(templates)
        names = ", ".join(t.name for t in templates)
        self._parent._log(f"测试发包：手动发送 {len(templates)} 种包（{names}）")
        self._gen_status_var.set(f"已手动发送 {len(templates)} 种（累计 {self._sent_count}）")

    def _toggle(self) -> None:
        if self._generator.running:
            self._generator.stop()
            self._toggle_btn.configure(text="开始发包", style="Accent.TButton")
            self._parent._log(f"测试发包：已停止（累计 {self._sent_count} 包）")
            self._gen_status_var.set(f"已停止（累计 {self._sent_count} 包）")
            self._check_capture_state()
            return
        if not self._parent.capturing:
            self._gen_status_var.set("⚠ 请先启动抓包")
            return
        templates = self._get_selected_templates()
        if not templates:
            self._gen_status_var.set("⚠ 请先勾选至少一种测试包类型")
            return
        self._sent_count = 0
        self._toggle_btn.configure(text="停止发包", style="Danger.TButton")
        self._capture_warning.grid_remove()
        self._generator.start(self._inject, templates, interval=0.5)
        count = len(templates)
        self._parent._log(f"测试发包：已启动（{count} 种模板，每 0.5 秒轮发）")
        self._gen_status_var.set("● 发包中（每 0.5 秒一轮）…")
        self._poll_status()

    def _poll_status(self) -> None:
        if not self._generator.running:
            self._toggle_btn.configure(text="开始发包", style="Accent.TButton")
            if self._generator.last_error:
                self._gen_status_var.set(f"⚠ 发包失败：{self._generator.last_error}")
                self._parent._log(f"测试发包失败：{self._generator.last_error}")
            else:
                self._gen_status_var.set(f"已停止 — 期间每 0.5 秒轮发一组模板")
            self._check_capture_state()
            return
        self._schedule(1000, self._poll_status)

    def destroy(self) -> None:
        self._generator.stop()
        for aid in self._after_ids:
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        self._after_ids.clear()
        super().destroy()


class SubnetScanDialog(tk.Toplevel):
    def __init__(self, parent: NetGuardApp, device_display: DeviceDisplay,
                 all_displays: list[DeviceDisplay], bpf_var: tk.StringVar,
                 on_switch_device: Callable[[str], None] | None = None,
                 on_add_bpf_template: Callable[[str, str, str], None] | None = None) -> None:
        super().__init__(parent)
        self.title("网段扫描与管理")
        self.transient(parent)
        self.grab_set()
        _set_initial_window_size(self, 820, 700, 680, 560)
        self._parent = parent
        self._bpf_var = bpf_var
        self._on_switch_device = on_switch_device
        self._on_add_bpf_template = on_add_bpf_template
        self._current_display = device_display
        self._all_displays = all_displays
        self._displays_with_ip = [d for d in all_displays if d.ip_addresses]
        self._subnets = extract_subnets(
            device_display.ip_addresses, device_display.device.netmasks
        )
        if not self._subnets:
            self._subnets = detect_subnet_os_fallback(
                device_display.device.name,
                _device_match_aliases(device_display),
            )
        self._alive_hosts: list[str] = []
        self._host_infos: dict[str, HostInfo] = {}
        self._scanning = False
        self._resolving = False
        self._cancel_event = threading.Event()
        self._after_ids: list[str] = []
        colors = build_colors(parent.dark_mode.get())
        self.configure(background=colors["bg"])
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        sw_frame = ttk.Frame(self, padding=(8, 8, 8, 0))
        sw_frame.grid(row=0, column=0, sticky=tk.EW)
        ttk.Label(sw_frame, text="网卡", style="Muted.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        self._device_var = tk.StringVar(value=device_display.display_name)
        device_names = [d.display_name for d in self._displays_with_ip] if self._displays_with_ip else [device_display.display_name]
        self._device_box = ttk.Combobox(sw_frame, textvariable=self._device_var,
                                        values=device_names, width=40, state="readonly")
        self._device_box.pack(side=tk.LEFT, fill=tk.X, expand=True)
        _fit_combobox_width(self._device_box, device_names)
        self._device_box.bind("<<ComboboxSelected>>", lambda _: self._on_device_switched())
        if not self._subnets and self._displays_with_ip:
            hint = f"当前网卡无 IPv4，以下 {len(self._displays_with_ip)} 张网卡已检测到地址"
        elif not self._subnets:
            hint = "所有网卡均未检测到 IPv4 地址"
        else:
            hint = "可切换网卡以查看其他网段"
        ttk.Label(sw_frame, text=hint, style="Status.TLabel", anchor=tk.E).pack(side=tk.RIGHT, padx=(8, 0))

        info_frame = ttk.Frame(self, padding=(8, 6, 8, 0))
        info_frame.grid(row=1, column=0, sticky=tk.EW)
        self._info_var = tk.StringVar(value=self._build_info_text())
        ttk.Label(info_frame, textvariable=self._info_var, style="Muted.TLabel",
                  wraplength=650, anchor=tk.W, justify=tk.LEFT).pack(fill=tk.X)

        manual_row = ttk.Frame(info_frame)
        manual_row.pack(fill=tk.X, pady=(6, 0))
        ttk.Label(manual_row, text="手动网段:", style="Muted.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        self._manual_cidr = tk.StringVar()
        ttk.Entry(manual_row, textvariable=self._manual_cidr, width=22, style="Filter.TEntry").pack(
            side=tk.LEFT, padx=(0, 6))
        presets = ["192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24", "10.0.1.0/24"]
        self._preset_var = tk.StringVar(value="常用网段")
        preset_box = ttk.Combobox(manual_row, textvariable=self._preset_var, values=presets, width=16, state="readonly")
        preset_box.pack(side=tk.LEFT, padx=(0, 6))
        preset_box.bind("<<ComboboxSelected>>", lambda _: self._manual_cidr.set(self._preset_var.get()))
        ttk.Button(manual_row, text="应用", width=6, style="Accent.TButton",
                   command=self._apply_manual_subnet).pack(side=tk.LEFT)

        ctrl_frame = ttk.Frame(self, padding=(8, 4))
        ctrl_frame.grid(row=2, column=0, sticky=tk.EW)
        self._scan_btn = ttk.Button(ctrl_frame, text="开始扫描", style="Accent.TButton",
                                    command=self._toggle_scan)
        self._scan_btn.pack(side=tk.LEFT)
        if not self._subnets:
            self._scan_btn.configure(state=tk.DISABLED)
        self._status_var = tk.StringVar(value="就绪" if self._subnets else self._no_ipv4_status())
        ttk.Label(ctrl_frame, textvariable=self._status_var, style="Status.TLabel",
                  anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))

        list_frame = ttk.Frame(self, padding=(8, 4))
        list_frame.grid(row=3, column=0, sticky=tk.EW)
        ttk.Label(list_frame, text="活跃主机", style="FilterLabel.TLabel").pack(anchor=tk.W)
        detail_list = ttk.Frame(self, padding=(8, 4))
        detail_list.grid(row=4, column=0, sticky=tk.NSEW)
        detail_list.rowconfigure(0, weight=1)
        detail_list.columnconfigure(0, weight=1)
        self._host_list = tk.Listbox(detail_list, selectmode=tk.EXTENDED, height=10)
        self._host_list.configure(
            background=colors["field"], foreground=colors["text"],
            selectbackground=colors["select"],
            selectforeground="#ffffff" if parent.dark_mode.get() else colors["text"],
            highlightbackground=colors["border"], highlightcolor=colors["accent"],
        )
        self._host_list.grid(row=0, column=0, sticky=tk.NSEW)
        host_scroll = ttk.Scrollbar(detail_list, orient=tk.VERTICAL, command=self._host_list.yview)
        self._host_list.configure(yscrollcommand=host_scroll.set)
        host_scroll.grid(row=0, column=1, sticky=tk.NS)
        self._host_list.bind("<<ListboxSelect>>", lambda _: self._on_host_select())

        self._detail_text = tk.Text(detail_list, height=6, wrap=tk.WORD)
        self._detail_text.configure(
            background=colors["field"], foreground=colors["text"],
            insertbackground=colors["text"], relief=tk.FLAT,
            highlightbackground=colors["border"], highlightcolor=colors["accent"],
        )
        self._detail_text.grid(row=1, column=0, columnspan=2, sticky=tk.NSEW, pady=(8, 0))
        self._detail_text.insert("1.0", "选择主机后可查看详情；点击下方按钮发送 Ping 验证连通性。")

        action_bar = ttk.Frame(self, padding=(8, 8))
        action_bar.grid(row=5, column=0, sticky=tk.EW)
        self._resolve_btn = ttk.Button(action_bar, text="解析主机名", style="Secondary.TButton",
                                       command=self._toggle_resolve)
        self._resolve_btn.pack(side=tk.LEFT)
        self._resolve_btn.configure(state=tk.DISABLED)
        self._ping_btn = ttk.Button(action_bar, text="Ping 选中", style="Secondary.TButton",
                                    command=self._ping_selected)
        self._ping_btn.pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(action_bar, text="保存为 BPF 模板", style="Secondary.TButton",
                   command=self._save_as_template).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(action_bar, text="应用过滤", style="Accent.TButton",
                   command=self._apply_subnet_filter).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(action_bar, text="取消", style="Secondary.TButton",
                   command=self.destroy).pack(side=tk.RIGHT)

    def _safe_after(self, delay_ms: int, callback) -> None:
        if not self.winfo_exists():
            return
        try:
            aid = self.after(delay_ms, callback)
        except tk.TclError:
            return
        self._after_ids.append(aid)

    def _no_ipv4_status(self) -> str:
        if self._displays_with_ip:
            names = ", ".join(d.display_name for d in self._displays_with_ip[:3])
            extra = f" 等 {len(self._displays_with_ip)} 张" if len(self._displays_with_ip) > 3 else ""
            return f"未检测到 IPv4 地址 — 建议切换到：{names}{extra}"
        return "所有网卡均未检测到 IPv4 地址，请检查网络配置"

    def _build_info_text(self) -> str:
        if not self._subnets:
            name = self._current_display.display_name
            lines = [f"当前网卡「{name}」未检测到 IPv4 地址，无法进行网段扫描。", ""]
            if self._displays_with_ip:
                lines.append("以下网卡已检测到 IPv4 地址，可在上方下拉框切换：")
                for d in self._displays_with_ip[:8]:
                    lines.append(f"  • {d.display_name}")
            else:
                lines.append("所有网卡均未检测到 IPv4 地址。请检查：")
                lines.append("  1. 网卡是否已连接网络并获取到 IP 地址")
                lines.append("  2. Npcap/libpcap 驱动是否正常工作")
                lines.append("  3. 是否需要管理员权限运行程序")
            return "\n".join(lines)
        lines = ["检测到的网段："]
        for s in self._subnets:
            lab = " 实验室网段" if s.is_lab_network else "（非实验室网段，主机数较多）"
            lines.append(f"  {s.cidr} — {s.total_hosts} 台可用主机 — 网关 {s.gateway_hint}{lab}")
        return "\n".join(lines)

    def _on_device_switched(self) -> None:
        selected = self._device_var.get()
        for d in self._displays_with_ip:
            if d.display_name == selected:
                self._rebuild_for_device(d)
                if self._on_switch_device:
                    self._on_switch_device(d.device.name)
                return

    def _rebuild_for_device(self, display: DeviceDisplay) -> None:
        self._current_display = display
        self._subnets = extract_subnets(
            display.ip_addresses, display.device.netmasks
        )
        if not self._subnets:
            self._subnets = detect_subnet_os_fallback(
                display.device.name,
                _device_match_aliases(display),
            )
        self._alive_hosts.clear()
        self._host_infos.clear()
        self._info_var.set(self._build_info_text())
        self._host_list.delete(0, tk.END)
        self._detail_text.delete("1.0", tk.END)
        self._detail_text.insert("1.0", "选择主机后可查看详情；点击下方按钮发送 Ping 验证连通性。")
        if self._subnets:
            self._scan_btn.configure(state=tk.NORMAL)
            self._status_var.set("就绪")
        else:
            self._scan_btn.configure(state=tk.DISABLED)
            self._status_var.set(self._no_ipv4_status())
        self._resolve_btn.configure(state=tk.DISABLED)

    def _save_as_template(self) -> None:
        if not self._subnets:
            messagebox.showwarning("保存模板", "当前网卡未检测到网段，无法保存。", parent=self)
            return
        subnet = self._subnets[0]
        bpf = subnet_to_bpf(subnet)
        title = f"网段 {subnet.cidr}"
        desc = f"自动发现的网段 {subnet.cidr}，{subnet.total_hosts} 台主机，网关 {subnet.gateway_hint}"
        if self._on_add_bpf_template:
            self._on_add_bpf_template(title, desc, bpf)
        self._status_var.set(f"已保存 BPF 模板「{title}」")
        self._parent._log(f"网段扫描：已保存 BPF 模板 {bpf}")

    def _apply_manual_subnet(self) -> None:
        cidr = self._manual_cidr.get().strip()
        if not cidr:
            return
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            messagebox.showwarning("手动网段", f"无效的 CIDR 格式：{cidr}\n\n请输入如 192.168.1.0/24 的格式。", parent=self)
            return
        hosts = list(net.hosts())
        total = len(hosts)
        gw = str(hosts[0]) if hosts else str(net.network_address)
        is_lab = 2 < total <= 254
        subnet = SubnetInfo(
            cidr=f"{net.network_address}/{net.prefixlen}",
            device_ip="手动指定",
            netmask=str(net.netmask),
            network=net,
            total_hosts=total,
            broadcast=str(net.broadcast_address),
            gateway_hint=gw,
            is_lab_network=is_lab,
        )
        self._subnets = [subnet]
        self._info_var.set(self._build_info_text())
        self._scan_btn.configure(state=tk.NORMAL)
        self._status_var.set(f"就绪 — 手动网段 {cidr}")
        self._host_list.delete(0, tk.END)
        self._alive_hosts.clear()
        self._host_infos.clear()
        self._resolve_btn.configure(state=tk.DISABLED)
        self._parent._log(f"网段扫描：已手动设置网段 {cidr}")

    def _toggle_scan(self) -> None:
        if self._scanning:
            self._cancel_event.set()
            return
        self._scanning = True
        self._cancel_event.clear()
        self._scan_btn.configure(text="停止扫描", style="Danger.TButton")
        self._status_var.set("正在扫描...")
        self._host_list.delete(0, tk.END)
        self._alive_hosts.clear()

        subnet = self._subnets[0]
        thread = threading.Thread(target=self._run_sweep, args=(subnet,), name="netguard-sweep", daemon=True)
        thread.start()

    def _run_sweep(self, subnet: SubnetInfo) -> None:
        def on_progress(completed: int, total: int, last_ip: str) -> None:
            self._safe_after(0, lambda c=completed, t=total, ip=last_ip: self._sweep_progress(c, t, ip))

        hosts = ping_sweep(subnet, max_workers=100, timeout=0.8, on_progress=on_progress,
                           cancel_event=self._cancel_event)
        self._safe_after(0, lambda h=hosts: self._sweep_done(h))

    def _sweep_progress(self, completed: int, total: int, last_ip: str) -> None:
        self._status_var.set(f"扫描中 {completed}/{total} — {last_ip}")

    def _sweep_done(self, hosts: list[str]) -> None:
        self._scanning = False
        self._cancel_event.clear()
        self._scan_btn.configure(text="重新扫描", style="Accent.TButton")
        self._alive_hosts = hosts
        if not hosts:
            self._status_var.set("扫描完成 — 未发现活跃主机")
            return
        self._status_var.set(f"扫描完成 — 发现 {len(hosts)} 台活跃主机")
        self._resolve_btn.configure(state=tk.NORMAL)
        for ip in hosts:
            self._host_list.insert(tk.END, ip)

    def _on_host_select(self) -> None:
        selection = self._host_list.curselection()
        if not selection:
            return
        ips = [self._alive_hosts[i] for i in selection if i < len(self._alive_hosts)]
        lines = ["选中主机："]
        for ip in ips:
            info = self._host_infos.get(ip)
            if info and info.hostname:
                lines.append(f"  {ip} — {info.hostname}  ({info.source})")
            else:
                lines.append(f"  {ip}")
        lines.append("")
        lines.append("点击下方「Ping 选中」按钮验证连通性。")
        self._detail_text.delete("1.0", tk.END)
        self._detail_text.insert("1.0", "\n".join(lines))

    def _ping_selected(self) -> None:
        selection = self._host_list.curselection()
        if not selection:
            messagebox.showwarning("Ping", "请先选择要 Ping 的主机。", parent=self)
            return
        ips = [self._alive_hosts[i] for i in selection if i < len(self._alive_hosts)]
        if not ips:
            return
        self._ping_btn.configure(state=tk.DISABLED)
        self._status_var.set(f"正在 Ping {len(ips)} 台主机...")
        thread = threading.Thread(target=self._run_ping_batch, args=(ips,), name="netguard-ping", daemon=True)
        thread.start()

    def _run_ping_batch(self, ips: list[str]) -> None:
        results: list[tuple[str, bool]] = []
        for ip in ips:
            ok = ping_host(ip, timeout=2.0)
            results.append((ip, ok))
            self._safe_after(0, lambda r=results[:]: self._ping_progress(r))
        self._safe_after(0, lambda r=results: self._ping_done(r))

    def _ping_progress(self, results: list[tuple[str, bool]]) -> None:
        lines = [f"Ping 进度 ({len(results)} 台):"]
        for ip, ok in results:
            status = "通" if ok else "不通"
            lines.append(f"  {ip} — {status}")
        self._detail_text.delete("1.0", tk.END)
        self._detail_text.insert("1.0", "\n".join(lines))

    def _ping_done(self, results: list[tuple[str, bool]]) -> None:
        ok_count = sum(1 for _, ok in results if ok)
        self._status_var.set(f"Ping 完成 — {ok_count}/{len(results)} 通")
        self._ping_btn.configure(state=tk.NORMAL)

    def _toggle_resolve(self) -> None:
        if self._resolving:
            self._cancel_event.set()
            return
        if not self._alive_hosts:
            return
        self._resolving = True
        self._cancel_event.clear()
        self._host_infos.clear()
        self._resolve_btn.configure(text="停止解析", style="Danger.TButton")
        self._status_var.set("正在解析主机名...")
        thread = threading.Thread(target=self._run_resolve, name="netguard-resolve", daemon=True)
        thread.start()

    def _run_resolve(self) -> None:
        def on_progress(completed: int, total: int, last_ip: str) -> None:
            self._safe_after(0, lambda c=completed, t=total, ip=last_ip: self._resolve_progress(c, t, ip))

        infos = resolve_hosts(self._alive_hosts, max_workers=40, timeout=2.0, on_progress=on_progress,
                              cancel_event=self._cancel_event)
        self._safe_after(0, lambda i=infos: self._resolve_done(i))

    def _resolve_progress(self, completed: int, total: int, last_ip: str) -> None:
        self._status_var.set(f"解析中 {completed}/{total} — {last_ip}")

    def _resolve_done(self, infos: dict[str, HostInfo]) -> None:
        self._resolving = False
        self._cancel_event.clear()
        self._resolve_btn.configure(text="重新解析", style="Secondary.TButton")
        self._host_infos = infos
        resolved = sum(1 for info in infos.values() if info.hostname)
        self._status_var.set(f"解析完成 — {resolved}/{len(infos)} 台获取到主机名")
        self._host_list.delete(0, tk.END)
        for ip in self._alive_hosts:
            info = infos.get(ip)
            if info and info.hostname:
                self._host_list.insert(tk.END, f"{ip} — {info.hostname}  ({info.source})")
            else:
                self._host_list.insert(tk.END, ip)

    def _apply_subnet_filter(self) -> None:
        if not self._subnets:
            messagebox.showwarning("应用过滤", "当前网卡未检测到网段。", parent=self)
            return
        subnet = self._subnets[0]
        bpf = subnet_to_bpf(subnet)
        self._bpf_var.set(bpf)
        self._parent._log(f"网段扫描：已应用 BPF 过滤 {bpf}")
        self.destroy()

    def _on_close(self) -> None:
        if self._scanning:
            self._cancel_event.set()
        for aid in self._after_ids:
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        self._after_ids.clear()
        self.destroy()

    def destroy(self) -> None:
        if self._scanning:
            self._cancel_event.set()
        for aid in self._after_ids:
            try:
                self.after_cancel(aid)
            except Exception:
                pass
        self._after_ids.clear()
        super().destroy()


def run_gui() -> None:
    app = NetGuardApp()
    try:
        app.lift()
        app.attributes("-topmost", True)
        app.after_idle(app.attributes, "-topmost", False)
    except tk.TclError:
        pass
    app.mainloop()
