from __future__ import annotations

import ipaddress
import json
import logging
import queue
import re
import sys
import threading
import time
import tkinter as tk
from collections.abc import Callable
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from functools import partial
from importlib import resources
from tkinter import filedialog, messagebox, ttk
from typing import Any, TypeVar, cast

from netguard._version import __version__
from netguard.capture.interface_mapping import (
    DeviceDisplay,
    build_device_displays,
    device_recommendation_reason,
    recommend_device_display,
)
from netguard.capture.pcap import CaptureDevice, RawPacket
from netguard.capture.pcap_file import write_pcap
from netguard.discovery import (
    MAX_SWEEP_HOSTS,
    HostInfo,
    SubnetInfo,
    detect_subnet_os_fallback,
    extract_subnets,
    ping_host,
    ping_sweep,
    resolve_hosts,
    subnet_to_bpf,
)
from netguard.gui.config import AppConfig, resolve_theme_mode
from netguard.gui.theme import (
    PROTOCOL_COLOR_KEYS,
    ThemeManager,
    apply_menu,
    build_colors,
    detect_system_dark,
    protocol_color,
    severity_key,
)
from netguard.gui.view_models import (
    MAX_HEX_BYTES,
    DetailNode,
    _format_packet,
    _search_text,
    alert_detail_text,
    alert_row,
    build_detail_tree,
    format_endpoint,
    hex_rows,
    packet_row,
)
from netguard.gui.widgets import PanelHeader, StatCard, StatusPill, Tooltip, hline, vline
from netguard.parser.packet import PacketInfo
from netguard.pipeline import PacketEvent, PacketPipeline, PipelineStatus
from netguard.rules.engine import Alert
from netguard.rules.suggestions import RuleSuggestion, generate_rule_suggestions
from netguard.trafficgen import TEMPLATES, PacketTemplate, TrafficGenerator

logger = logging.getLogger(__name__)

_T = TypeVar("_T")
_W = TypeVar("_W", bound=tk.Widget)
MAX_TABLE_ROWS = 5000
MAX_ALERT_ROWS = 1000
MAX_EVENTS = 50_000
PUMP_BATCH = 500
TICK_MS = 250
TABLE_TRIM_CHUNK = 3000
REFILTER_BATCH = 400
SYSTEM_THEME_POLL_MS = 5000
CONFIG_SAVE_DEBOUNCE_MS = 800
#: 默认窗口尺寸与最小尺寸。最小尺寸必须容得下并排的两个面板的默认列宽之和
#: （见 _DEFAULT_PACKET_COLUMNS / _DEFAULT_DETAIL_COLUMNS，有测试守住这条预算）。
_DEFAULT_WINDOW_SIZE = (1600, 940)
MIN_WINDOW_SIZE = (1280, 760)
#: 数据包列表默认列宽：(宽度, 是否随窗口伸缩)
_DEFAULT_PACKET_COLUMNS = {
    "time": (110, False),
    "src": (140, True),
    "dst": (140, True),
    "proto": (56, False),
    "len": (52, False),
    "summary": (202, True),
}
#: 检视面板解析树的默认列宽（"字段" 列要放得下空状态提示里的 6 个汉字 + 层级缩进）
_DEFAULT_DETAIL_COLUMNS = {"#0": 132, "value": 200}
#: 恢复分隔条位置的最大重试次数（等窗口完成首次布局）
_SASH_RETRY_LIMIT = 12
#: 各分隔条两侧的最小窗格尺寸（前导, 尾部）：恢复布局与窗口缩放共用同一套钳制，
#: 尾部尺寸取该窗格"能正常显示内容"的请求尺寸（检视面板 340、底部标签页 150）。
_SASH_MIN_SIZES = {"workspace": (160, 150), "main": (380, 340)}
#: 流量统计页协议进度条的宽度与右侧留白列索引
_STATS_BAR_WIDTH = 260
_STATS_BAR_SPACER_COLUMN = 3

#: 主题模式 → 日志文案（_cycle_theme_mode 用）
_THEME_MODE_LABELS = {"system": "跟随系统", "light": "浅色", "dark": "深色"}

#: 快捷键定义：(菜单标签, 加速键, Tk 事件序列)
SHORTCUTS: list[tuple[str, str, str]] = [
    ("开始抓包", "F5", "<F5>"),
    ("停止抓包", "Shift+F5", "<Shift-F5>"),
    ("停止抓包（输入框聚焦时不触发）", "Esc", "<Escape>"),
    ("暂停/恢复", "Ctrl+P", "<Control-p>"),
    ("清空数据", "Ctrl+L", "<Control-l>"),
    ("打开 pcap", "Ctrl+O", "<Control-o>"),
    ("保存 pcap", "Ctrl+S", "<Control-s>"),
    ("导出告警", "Ctrl+E", "<Control-e>"),
    ("聚焦显示过滤", "Ctrl+F", "<Control-f>"),
    ("退出", "Ctrl+Q", "<Control-q>"),
    ("快捷键说明", "F1", "<F1>"),
]


def _compact_bytes(value: float) -> str:
    """把字节数压成 4 个字符左右，避免 KPI 卡里的数字撑破行宽。

    只返回数值与量级前缀，单位由调用方的指标卡单独显示。
    """
    for limit, suffix in ((1024**4, "TB"), (1024**3, "GB"), (1024**2, "MB"), (1024, "KB")):
        if abs(value) >= limit:
            return f"{value / limit:.1f} {suffix}"
    return f"{value:.0f}"


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
    InputTemplate(
        "HTTP GET 告警",
        "匹配发往 80 端口且载荷包含 GET 的明文 HTTP 请求。",
        'alert tcp any any -> any 80 (content "GET"; msg "检测到 HTTP GET 请求";)',
    ),
    InputTemplate(
        "HTTP POST 告警",
        "匹配发往 80 端口且载荷包含 POST 的明文 HTTP 请求。",
        'alert tcp any any -> any 80 (content "POST"; msg "检测到 HTTP POST 请求";)',
    ),
    InputTemplate(
        "HTTP Host 告警",
        "将 example.com 替换为目标 Host 域名。",
        'alert tcp any any -> any 80 (content "Host: example.com"; msg "检测到指定 HTTP Host";)',
    ),
    InputTemplate(
        "DNS 流量告警", "匹配普通 DNS 查询和响应流量。", 'alert udp any any -> any 53 (msg "检测到 DNS 流量";)'
    ),
    InputTemplate(
        "DNS 关键字告警",
        "将 example 替换为目标域名中的关键字。",
        'alert udp any any -> any 53 (content "example"; msg "检测到 DNS 查询关键字";)',
    ),
    InputTemplate(
        "任意协议关键字",
        "将 secret 替换为需要在载荷中查找的关键字。",
        'alert any any any -> any any (content "secret"; msg "检测到关键字 secret";)',
    ),
]


def _fit_combobox_width(combo: ttk.Combobox, values: list[str], *, min_width: int = 20, max_width: int = 70) -> None:
    if not values:
        return
    max_chars = max(len(v) for v in values)
    combo["width"] = max(min_width, min(max_chars, max_width))


def _set_initial_window_size(
    window: tk.Toplevel | tk.Tk, width: int, height: int, min_width: int, min_height: int
) -> None:
    screen_width = max(1, window.winfo_screenwidth())
    screen_height = max(1, window.winfo_screenheight())
    target_width = min(max(width, min_width), max(min_width, int(screen_width * 0.92)))
    target_height = min(max(height, min_height), max(min_height, int(screen_height * 0.88)))
    x = max(0, (screen_width - target_width) // 2)
    y = max(0, (screen_height - target_height) // 2)
    window.geometry(f"{target_width}x{target_height}+{x}+{y}")
    window.minsize(min_width, min_height)


def center_on_parent(
    window: tk.Toplevel, parent: tk.Misc, width: int, height: int, min_width: int, min_height: int
) -> None:
    """按父窗口居中并钳制到屏幕范围，符合对话框的常见惯例。"""
    try:
        parent.update_idletasks()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
    except tk.TclError:
        _set_initial_window_size(window, width, height, min_width, min_height)
        return
    if pw <= 1 or ph <= 1:
        _set_initial_window_size(window, width, height, min_width, min_height)
        return
    screen_width = max(1, window.winfo_screenwidth())
    screen_height = max(1, window.winfo_screenheight())
    target_width = min(max(width, min_width), max(min_width, int(screen_width * 0.92)))
    target_height = min(max(height, min_height), max(min_height, int(screen_height * 0.88)))
    x = min(max(0, px + (pw - target_width) // 2), max(0, screen_width - target_width))
    y = min(max(0, py + (ph - target_height) // 2), max(0, screen_height - target_height))
    window.geometry(f"{target_width}x{target_height}+{x}+{y}")
    window.minsize(min_width, min_height)


def bind_dialog_keys(
    window: tk.Toplevel, on_cancel: Callable[[], None], on_default: Callable[[], None] | None = None
) -> None:
    """为对话框绑定 Esc 取消与可选的回车默认动作。"""
    window.bind("<Escape>", lambda _e: on_cancel())
    if on_default is not None:
        window.bind("<Return>", lambda _e: on_default())


def wire_dialog_theme(dialog: tk.Toplevel, parent: NetGuardApp, classic_widgets: list[tk.Widget]) -> None:
    """让对话框跟随主窗口主题变化重刷，避免开着弹窗切主题时"花脸"。"""
    state: dict[str, str | None] = {"binding": None}

    def on_theme_changed(_event: tk.Event | None = None) -> None:
        try:
            if not dialog.winfo_exists():
                return
        except tk.TclError:
            return
        colors = build_colors(parent.dark_mode.get())
        try:
            dialog.configure(background=colors["bg"])
        except tk.TclError:
            return
        for widget in classic_widgets:
            try:
                if not widget.winfo_exists():
                    continue
                supported = set(widget.keys())
                options = {
                    "background": colors["field"],
                    "foreground": colors["text"],
                    "insertbackground": colors["text"],
                    "selectbackground": colors["select"],
                    "selectforeground": colors["select_text"],
                    "highlightbackground": colors["border"],
                    "highlightcolor": colors["accent"],
                }
                widget.configure(**{k: v for k, v in options.items() if k in supported})
            except tk.TclError:
                continue

    def on_destroy(event: tk.Event | None = None) -> None:
        if event is not None and event.widget is not dialog:
            return
        funcid = state["binding"]
        if funcid:
            with suppress(tk.TclError, AttributeError):
                parent.unbind("<<ThemeChanged>>", funcid)
            state["binding"] = None

    state["binding"] = parent.bind("<<ThemeChanged>>", on_theme_changed, add="+")
    dialog.bind("<Destroy>", on_destroy, add="+")
    # 保持引用，防止闭包被回收。Tk 控件是动态属性容器，用 cast 声明而非
    # 依赖 setattr，既让 mypy 满意又不掩盖类型
    cast("Any", dialog)._theme_hooks = (on_theme_changed, on_destroy)


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
        self._config = AppConfig.load()
        self._config_save_after_id: str | None = None
        self._config_ready = False
        self._restore_window_state()
        self.pipeline = PacketPipeline()
        self.events: list[PacketEvent] = []
        self.event_offset = 0
        self.filtered: list[int] = []
        self.device_displays: list[DeviceDisplay] = []
        self.display_to_device: dict[str, str] = {}
        self.paused = False
        self.capturing = False
        self._active_bpf_filter = ""
        self.theme_mode = tk.StringVar(value=resolve_theme_mode(self._config.theme_mode))
        self.dark_mode = tk.BooleanVar(value=self._resolve_dark())
        self._classic_widgets: list[tk.Widget] = []
        #: 需要跟随主题换色的原生控件：(控件, {选项: build_colors 的键})
        self._themed: list[tuple[tk.Widget, dict[str, str]]] = []
        self._menus: list[tk.Menu] = []
        self._status_bar: tk.Label | None = None
        self._busy_label: tk.Widget | None = None
        self._log_text: tk.Text | None = None
        self._log_expanded = False
        self._icon_stack = ExitStack()
        self._icon_image: tk.PhotoImage | None = None
        self._tooltips: list[Tooltip] = []
        # --- 新版外壳控件 ---
        self._pill: StatusPill | None = None
        self._rail_buttons: dict[str, ttk.Button] = {}
        self._rail_glyphs: dict[str, str] = {}
        self._rail_labels: dict[str, str] = {}
        self._panel_headers: list[PanelHeader] = []
        self._stat_cards: dict[str, StatCard] = {}
        self._stats_cells: dict[str, tk.Label] = {}
        self._proto_bars: dict[str, tuple[tk.Frame, tk.Frame, tk.Label]] = {}
        self._detail_nodes: dict[str, DetailNode] = {}
        #: 告警表行 iid → Alert，用于主题切换后重刷严重度配色
        self._alert_by_row: dict[str, Alert] = {}
        self._alert_seq = 0
        self._alert_sort_column = ""
        self._alert_sort_descending = False
        self._alert_tab_index = 0
        self._issue_tab_index = 1
        self._match_chip: tk.Label | None = None
        self._log_strip: tk.Frame | None = None
        self._table_hint: tk.Label | None = None
        self._status_detail: tk.Label | None = None
        self._drop_hint: tk.Label | None = None
        self._error_badge: tk.Label | None = None
        self._rule_count_label: tk.Label | None = None
        self._log_expand_btn: ttk.Button | None = None
        self.status_text_var = tk.StringVar(value="空闲")
        self.busy_text_var = tk.StringVar(value="")
        self._last_error_state: tuple[int, int, int, str] | None = None
        self._filter_after_id: str | None = None
        self._refilter_after_id: str | None = None
        self._refilter_queue: list[int] = []
        self._refilter_cursor = 0
        self._sort_column = ""
        self._sort_descending = False
        # 表头分隔线双击检测：(event.time, event.x)
        self._last_separator_click: tuple[int, int] | None = None
        self._busy_count = 0
        # 队列元素：("ok"|"error", 标题, 消息, 主线程待执行的零参回调)
        self._background_queue: queue.Queue[tuple[str, str | None, str | None, Callable[[], None] | None]] = (
            queue.Queue()
        )
        self._last_error_refresh = 0.0
        self._theme = ThemeManager(self)
        with suppress(tk.TclError):
            self._theme.theme_use("clam")
        self._set_window_icon()
        self._build()
        self._build_menu()
        self._apply_theme()
        self._bind_shortcuts()
        self._restore_layout_state()
        self._update_control_states()
        self._config_ready = True
        self.after(100, self._load_devices)
        self.after(200, self._tick)
        if self.theme_mode.get() == "system":
            self._start_system_theme_poll()
        self.protocol("WM_DELETE_WINDOW", self._exit)

    def _resolve_dark(self) -> bool:
        mode = self.theme_mode.get()
        if mode == "dark":
            return True
        if mode == "light":
            return False
        return detect_system_dark()

    def _restore_window_state(self) -> None:
        geometry = self._clamped_geometry(self._config.window.geometry)
        if geometry:
            try:
                self.geometry(geometry)
            except tk.TclError:
                _set_initial_window_size(self, *_DEFAULT_WINDOW_SIZE, *MIN_WINDOW_SIZE)
        else:
            _set_initial_window_size(self, *_DEFAULT_WINDOW_SIZE, *MIN_WINDOW_SIZE)
        self.minsize(*MIN_WINDOW_SIZE)
        if self._config.window.zoomed:
            try:
                self.state("zoomed")
            except tk.TclError:
                with suppress(tk.TclError):
                    self.attributes("-zoomed", True)

    def _clamped_geometry(self, geometry: str) -> str:
        """恢复窗口几何时按当前屏幕钳制。

        位置和尺寸都要钳：早期版本只夹位置，把 2560 宽的显示器上存下来的
        geometry 搬到 2048 宽的屏幕上时，窗口右半边（含操作按钮）会直接落到屏幕外。
        """
        geometry = geometry.strip()
        if not geometry:
            return ""
        match = re.match(r"^(?:(\d+)x(\d+))?([+-]\d+)([+-]\d+)$", geometry)
        if not match:
            return geometry
        width, height, x_text, y_text = match.groups()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x, y = int(x_text), int(y_text)
        if width and height:
            # 留出任务栏与窗口装饰的余量，避免贴边或超出可用工作区
            width = str(min(int(width), int(screen_w * 0.98)))
            height = str(min(int(height), int(screen_h * 0.94)))
        max_x = max(0, screen_w - (int(width) if width else 0))
        max_y = max(0, screen_h - (int(height) if height else 0) - 40)
        x = min(max(0, x), max_x)
        y = min(max(0, y), max_y)
        size = f"{width}x{height}" if width else ""
        return f"{size}+{x}+{y}"

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
        dark = self._resolve_dark()
        self.dark_mode.set(dark)
        colors = build_colors(dark)
        self._theme.apply(
            dark,
            self.table,
            self._classic_widgets,
            alert_table=self.alerts,
            detail_tree=self.detail,
            issue_table=self.error_list,
        )
        for widget, options in self._themed:
            try:
                if not widget.winfo_exists():
                    continue
                widget.configure(**{option: colors[key] for option, key in options.items()})
            except (tk.TclError, KeyError):
                continue
        for menu in self._menus:
            apply_menu(menu, colors)
        for header in self._panel_headers:
            header.apply_colors(colors)
        for card in self._stat_cards.values():
            card.apply_colors(colors)
        self._register_hex_tags()
        self._restyle_rail()
        self._refresh_alert_colors()
        self._refresh_detail_colors()
        self._update_indicator()
        self.event_generate("<<ThemeChanged>>", when="tail")
        self._schedule_config_save()

    def _restyle_rail(self) -> None:
        """操作轨按钮的样式随状态变化（暂停时高亮、无数据时禁用），换肤后要重算。"""
        self._sync_rail_styles()

    def _refresh_detail_colors(self) -> None:
        """解析树的 tag 前景色由主题决定，但已插入的行需要重新打 tag 才生效。"""
        nodes = self._detail_nodes
        if not nodes:
            return
        rows = self.detail.get_children()
        self._retag_detail_rows(rows, nodes, self.detail)

    def _retag_detail_rows(self, rows: tuple[str, ...], nodes: dict[str, DetailNode], tree: ttk.Treeview) -> None:
        for iid in rows:
            node = nodes.get(iid)
            if node is None:
                continue
            with suppress(tk.TclError):
                tree.item(iid, tags=(node.kind,))
            self._retag_detail_rows(tree.get_children(iid), nodes, tree)

    def _cycle_theme_mode(self) -> None:
        """顶栏按钮：在跟随系统 → 浅色 → 深色之间循环。"""
        order = ("system", "light", "dark")
        current = self.theme_mode.get()
        index = order.index(current) if current in order else 0
        self._set_theme_mode(order[(index + 1) % len(order)])
        self._log(f"主题已切换为{_THEME_MODE_LABELS[self.theme_mode.get()]}")

    def _refresh_alert_colors(self) -> None:
        """主题切换后重刷既有告警行前景色（per-row 颜色只在插入时设置过）。"""
        for iid in self.alerts.get_children():
            alert = self._alert_by_row.get(iid)
            if alert is None:
                continue
            try:
                self.alerts.item(iid, tags=(severity_key(alert),))
            except tk.TclError:
                return

    def _set_theme_mode(self, mode: str) -> None:
        self.theme_mode.set(mode)
        self._apply_theme()
        if mode == "system":
            self._start_system_theme_poll()

    def _start_system_theme_poll(self) -> None:
        """启动系统主题轮询；用哨兵防止重复启动叠加多条轮询链。"""
        if getattr(self, "_system_theme_poll_active", False):
            return
        self._system_theme_poll_active = True
        self.after(SYSTEM_THEME_POLL_MS, self._poll_system_theme)

    def _poll_system_theme(self) -> None:
        if self.__dict__.get("_destroyed", False) or self.theme_mode.get() != "system":
            self._system_theme_poll_active = False
            return
        if detect_system_dark() != self.dark_mode.get():
            self._apply_theme()
        self.after(SYSTEM_THEME_POLL_MS, self._poll_system_theme)

    def _load_config(self) -> dict[str, Any]:
        return self._config.to_dict()

    def _schedule_config_save(self) -> None:
        if not self._config_ready:
            return
        if self._config_save_after_id is not None:
            with suppress(tk.TclError):
                self.after_cancel(self._config_save_after_id)
        self._config_save_after_id = self.after(CONFIG_SAVE_DEBOUNCE_MS, self._save_config)

    def _collect_layout_state(self) -> None:
        window = self._config.window
        if not self.__dict__.get("_destroyed", False):
            try:
                if self.state() != "zoomed":
                    window.geometry = self.geometry()
                window.zoomed = self.state() == "zoomed"
            except tk.TclError:
                pass
        for name, pane in (
            ("workspace", getattr(self, "_workspace", None)),
            ("main", getattr(self, "_main_panes", None)),
        ):
            if pane is None:
                continue
            try:
                count = max(0, len(pane.panes()) - 1)
                pos = [pane.sashpos(i) for i in range(count)]
                if pos and all(isinstance(p, int) and p > 0 for p in pos):
                    window.sashes[name] = pos
            except tk.TclError:
                continue
        with suppress(tk.TclError):
            window.columns = {col: int(self.table.column(col, "width")) for col in self.table["columns"]}
        window.sort_column = self._sort_column
        window.sort_descending = self._sort_descending
        # 保存内部设备名而非显示名，恢复时按 device.name 匹配（两者在 Windows 上不同）
        window.last_device = self._selected_device_name() if hasattr(self, "device_var") else ""
        if hasattr(self, "bpf_var"):
            window.bpf = self.bpf_var.get()
        if hasattr(self, "display_filter"):
            window.display_filter = self.display_filter.get()

    def _save_config(self) -> None:
        self._config_save_after_id = None
        if not self._config_ready:
            return
        self._collect_layout_state()
        self._config.theme_mode = self.theme_mode.get()
        self._config.save()

    # --- 界面搭建 ---------------------------------------------------------

    def _paint(self, widget: _W, **options: str) -> _W:
        """登记原生控件的配色选项，让它在主题切换时自动换色。

        原生 tk 控件不参与 ttk 样式表，逐个在 ``_apply_theme`` 里 configure 会
        散落到几十处；这里把「控件 + 选项 → 颜色令牌名」集中登记，主题切换时统一重刷。

        返回原控件（保留具体类型），方便直接链式 ``.pack()`` / ``.grid()``。
        """
        self._themed.append((widget, options))
        return widget

    def _new_panel(self, parent: tk.Misc, title: str, *, accent_key: str = "accent") -> tuple[tk.Frame, tk.Frame]:
        """建一个卡片式面板（1px 边框 + 表面底色 + 标题栏），返回 (面板, 内容区)。"""
        colors = build_colors(self.dark_mode.get())
        panel = tk.Frame(parent, highlightthickness=1, borderwidth=0)
        self._paint(panel, background="surface", highlightbackground="border", highlightcolor="border")
        header = PanelHeader(panel, title, accent_key=accent_key, font_heading=self._theme.font_heading)
        header.pack(fill=tk.X)
        self._panel_headers.append(header)
        self._paint(hline(panel, colors["border"]), background="border").pack(fill=tk.X)
        body = tk.Frame(panel, borderwidth=0, highlightthickness=0)
        self._paint(body, background="surface")
        body.pack(fill=tk.BOTH, expand=True)
        return panel, body

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self._build_title_bar()
        self._build_shell()
        self._build_log_strip()
        self._build_status_bar()
        self._build_table_menu()
        self._build_tooltips()
        self._set_initial_empty_state()
        self.after(50, self._apply_sash_positions)

    def _build_title_bar(self) -> None:
        """顶栏：品牌标识 + 抓包状态胶囊 + 主题切换 + 后台任务提示。"""
        bar = tk.Frame(self, height=40, borderwidth=0, highlightthickness=0)
        self._paint(bar, background="surface_2")
        bar.grid(row=0, column=0, sticky=tk.EW)
        bar.pack_propagate(False)

        mark = tk.Label(bar, text="N", width=2, font=self._theme.font_heading)
        self._paint(mark, background="accent", foreground="on_accent")
        mark.pack(side=tk.LEFT, padx=(12, 8))
        self._paint(
            tk.Label(bar, text="NetGuard", font=self._theme.font_title),
            background="surface_2",
            foreground="text",
        ).pack(side=tk.LEFT)
        self._paint(
            tk.Label(bar, text=f"v{__version__}", font=self._theme.font_tiny),
            background="surface_2",
            foreground="text_faint",
        ).pack(side=tk.LEFT, padx=(6, 0))
        self._paint(vline(bar, build_colors(self.dark_mode.get())["border_strong"]), background="border_strong").pack(
            side=tk.LEFT, fill=tk.Y, padx=(12, 10), pady=11
        )

        self._pill = StatusPill(bar, font=self._theme.font_small)
        self._pill.pack(side=tk.LEFT)

        self._busy_label = self._paint(
            tk.Label(bar, textvariable=self.busy_text_var, font=self._theme.font_small),
            background="surface_2",
            foreground="text_dim",
        )
        self._busy_label.pack(side=tk.RIGHT, padx=(0, 12))
        self._theme_btn = ttk.Button(bar, text="◐ 主题", width=8, style="Ghost.TButton", command=self._cycle_theme_mode)
        self._theme_btn.pack(side=tk.RIGHT, padx=(0, 6))

    def _build_shell(self) -> None:
        shell = tk.Frame(self, borderwidth=0, highlightthickness=0)
        self._paint(shell, background="canvas")
        shell.grid(row=1, column=0, sticky=tk.NSEW)
        # 第 0 列是操作轨、第 1 列是 1px 分隔线（_build_rail 负责）、第 2 列是内容区
        shell.columnconfigure(2, weight=1)
        shell.rowconfigure(0, weight=1)

        self._build_rail(shell)

        content = tk.Frame(shell, borderwidth=0, highlightthickness=0)
        self._paint(content, background="canvas")
        content.grid(row=0, column=2, sticky=tk.NSEW)
        content.columnconfigure(0, weight=1)
        content.rowconfigure(3, weight=1)
        self._build_capture_bar(content)
        self._build_kpi_strip(content)
        self._build_filter_bar(content)
        self._build_workspace(content)

    def _build_rail(self, parent: tk.Misc) -> None:
        """左侧操作轨：把最高频的动作从工具栏搬到固定的竖向位置。"""
        colors = build_colors(self.dark_mode.get())
        rail = tk.Frame(parent, width=62, borderwidth=0, highlightthickness=0)
        self._rail = rail
        self._paint(rail, background="surface_2")
        rail.grid(row=0, column=0, sticky=tk.NS)
        rail.grid_propagate(False)
        # 操作轨与内容区之间的 1px 分隔线：必须独占第 1 列，和内容区放在同一格里
        # 会被后创建的内容帧整块盖住（sticky=NS 只纵向拉伸，横向停在单元格中间）
        self._paint(vline(parent, colors["border"]), background="border").grid(row=0, column=1, sticky=tk.NS)

        spec: list[tuple[str, str, str, str, str, Callable[[], None]] | None] = [
            ("start", "▶", "开始", "开始抓包（F5）", "RailAccent.TButton", self._start),
            ("stop", "■", "停止", "停止抓包（Shift+F5）", "RailDanger.TButton", self._stop),
            ("pause", "‖", "暂停", "暂停/恢复界面刷新（Ctrl+P）", "Rail.TButton", self._toggle_pause),
            ("clear", "×", "清空", "清空已捕获的数据（Ctrl+L）", "Rail.TButton", self._clear),
            None,
            ("open", "▤", "打开", "打开 pcap 文件离线分析（Ctrl+O）", "Rail.TButton", self._open_pcap),
            ("save", "▣", "保存", "把已捕获的数据包保存为 pcap（Ctrl+S）", "Rail.TButton", self._save_pcap),
            ("export", "▦", "导出", "导出 IDS 告警（Ctrl+E）", "Rail.TButton", self._export_alerts),
            None,
            ("gen", "⇄", "发包", "打开测试发包工具", "Rail.TButton", self._open_traffic_gen),
            ("scan", "◎", "扫描", "打开网段扫描", "Rail.TButton", self._open_subnet_scan),
            ("rules", "≡", "规则", "根据已捕获流量自动生成 IDS 规则", "Rail.TButton", self._show_rule_suggestions),
        ]
        for entry in spec:
            if entry is None:
                self._paint(hline(rail, colors["border"]), background="border").pack(fill=tk.X, padx=13, pady=5)
                continue
            key, glyph, label, hint, style, command = entry
            button = ttk.Button(rail, text=self._rail_text(glyph, label), style=style, width=5, command=command)
            button.pack(padx=5, pady=1)
            self._rail_buttons[key] = button
            self._rail_glyphs[key] = glyph
            self._rail_labels[key] = label
            self._tooltips.append(
                Tooltip(button, hint, dark=self.dark_mode.get(), dark_provider=lambda: self.dark_mode.get())
            )

    @staticmethod
    def _rail_text(glyph: str, label: str) -> str:
        return f"{glyph}\n{label}"

    def _set_rail_text(self, key: str, label: str) -> None:
        """更新操作轨按钮的文字，图标保持不变。"""
        button = self._rail_buttons.get(key)
        if button is None:
            return
        glyph = self._rail_glyphs.get(key, "")
        self._rail_labels[key] = label
        with suppress(tk.TclError):
            button.configure(text=self._rail_text(glyph, label))

    def _build_capture_bar(self, parent: tk.Misc) -> None:
        colors = build_colors(self.dark_mode.get())
        bar = tk.Frame(parent, padx=12, pady=9, borderwidth=0, highlightthickness=0)
        self._paint(bar, background="surface")
        bar.grid(row=0, column=0, sticky=tk.EW)
        self._paint(hline(bar, colors["border"]), background="border").pack(side=tk.BOTTOM, fill=tk.X)

        self._paint(
            tk.Label(bar, text="网卡", font=self._theme.font_small), background="surface", foreground="text_dim"
        ).pack(side=tk.LEFT, padx=(0, 7))
        self.device_var = tk.StringVar()
        self.device_box = ttk.Combobox(bar, textvariable=self.device_var, width=30, state="readonly")
        self.device_box.pack(side=tk.LEFT)
        self.device_box.bind("<<ComboboxSelected>>", lambda _: self._on_device_selected())

        self._paint(
            tk.Label(bar, text="捕获过滤 BPF", font=self._theme.font_small),
            background="surface",
            foreground="text_dim",
        ).pack(side=tk.LEFT, padx=(14, 7))
        # 空 BPF 表示抓全部流量，不要用 or 回退默认值
        self.bpf_var = tk.StringVar(value=self._config.window.bpf)
        bpf_entry = ttk.Entry(bar, textvariable=self.bpf_var, style="Filter.TEntry", width=24)
        self.bpf_var_entry = bpf_entry
        bpf_entry.pack(side=tk.LEFT)
        bpf_entry.bind("<Return>", lambda _: self._apply_bpf_entry())
        ttk.Button(bar, text="应用", width=6, style="Accent.TButton", command=self._apply_bpf_entry).pack(
            side=tk.LEFT, padx=(7, 0)
        )
        ttk.Button(bar, text="模板", width=6, style="Ghost.TButton", command=self._show_bpf_templates).pack(
            side=tk.LEFT, padx=(6, 0)
        )

        self._drop_hint = self._paint(
            tk.Label(bar, text="丢弃 0 · 解析异常 0", font=self._theme.font_small),
            background="surface",
            foreground="text_faint",
        )
        self._drop_hint.pack(side=tk.RIGHT)

    #: KPI 卡定义：(键, 标题, 单位, 是否告警色)
    _KPI_SPEC = (
        ("packets", "数据包总数", "", False),
        ("rate", "包速率", "包/秒", False),
        ("bytes_rate", "吞吐量", "字节/秒", False),
        ("sessions", "活动会话", "", False),
        ("alerts", "IDS 告警", "", True),
    )

    def _build_kpi_strip(self, parent: tk.Misc) -> None:
        """KPI 指标条：用 1px 间隙分隔的等宽指标卡，替代原来挤在一行的小字。"""
        colors = build_colors(self.dark_mode.get())
        strip = tk.Frame(parent, borderwidth=0, highlightthickness=0)
        self._paint(strip, background="border")
        strip.grid(row=1, column=0, sticky=tk.EW)
        for index, (key, label, unit, alarm) in enumerate(self._KPI_SPEC):
            card = StatCard(
                strip,
                label=label,
                value="0",
                unit=unit,
                alarm=alarm,
                font_metric=self._theme.font_metric,
                font_small=self._theme.font_small,
                colors=colors,
            )
            # 卡片之间靠 1px 的容器底色露出分隔线
            card.grid(row=0, column=index, sticky=tk.NSEW, padx=(0 if index == 0 else 1, 0))
            strip.columnconfigure(index, weight=1)
            self._stat_cards[key] = card
        self._paint(hline(strip, colors["border"]), background="border").grid(
            row=1, column=0, columnspan=len(self._KPI_SPEC), sticky=tk.EW
        )

    def _build_filter_bar(self, parent: tk.Misc) -> None:
        colors = build_colors(self.dark_mode.get())
        bar = tk.Frame(parent, padx=12, pady=8, borderwidth=0, highlightthickness=0)
        self._paint(bar, background="surface_2")
        bar.grid(row=2, column=0, sticky=tk.EW)
        self._paint(hline(bar, colors["border"]), background="border").pack(side=tk.BOTTOM, fill=tk.X)

        self._paint(
            tk.Label(bar, text="显示过滤", font=self._theme.font_small), background="surface_2", foreground="text_dim"
        ).pack(side=tk.LEFT, padx=(0, 8))
        self.display_filter = tk.StringVar(value=self._config.window.display_filter)
        entry = ttk.Entry(bar, textvariable=self.display_filter, style="Filter.TEntry")
        self.display_filter_entry = entry
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry.bind("<KeyRelease>", lambda _: self._debounced_refilter())
        ttk.Button(bar, text="模板", width=6, style="Ghost.TButton", command=self._show_display_filter_templates).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        self._match_chip = self._paint(
            tk.Label(bar, text="0 / 0 条匹配", font=self._theme.font_small),
            background="tint_accent",
            foreground="accent",
        )
        self._match_chip.pack(side=tk.LEFT, padx=(10, 0), ipadx=8, ipady=2)

    def _build_workspace(self, parent: tk.Misc) -> None:
        workspace = ttk.PanedWindow(parent, orient=tk.VERTICAL, style="Content.TPanedwindow")
        workspace.grid(row=3, column=0, sticky=tk.NSEW, padx=10, pady=10)
        main_area = ttk.PanedWindow(workspace, orient=tk.HORIZONTAL, style="Content.TPanedwindow")
        bottom = ttk.Frame(workspace, style="Surface.TFrame")
        workspace.add(main_area, weight=5)
        workspace.add(bottom, weight=3)
        self._workspace = workspace
        self._main_panes = main_area
        # 窗格自身尺寸变化时就重算分隔条：窗口缩放、兄弟控件请求尺寸变化都会
        # 让窗格变窄，若只在窗口 Configure 时重算，尾部窗格仍会被压扁
        for name, pane in (("workspace", workspace), ("main", main_area)):
            pane.bind("<Configure>", partial(self._on_pane_configure, name), add="+")

        self._build_packet_panel(main_area)
        self._build_inspector_panel(main_area)
        self._build_bottom_tabs(bottom)

    def _build_packet_panel(self, parent: ttk.PanedWindow) -> None:
        panel, body = self._new_panel(parent, "数据包列表")
        parent.add(panel, weight=3)
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        columns = ("time", "src", "dst", "proto", "len", "summary")
        headings = {
            "time": "时间",
            "src": "源地址",
            "dst": "目的地址",
            "proto": "协议",
            "len": "长度",
            "summary": "摘要",
        }
        self.table = ttk.Treeview(body, columns=columns, show="headings", height=14)
        # 列宽预算：时间/协议/长度定宽，地址与摘要按比例伸缩。
        # 详情面板与数据包列表并排，两组默认列宽之和必须落在最小窗口（MIN_WINDOW_SIZE）
        # 之内，否则最小尺寸下右侧内容会被推到窗口外（tests/test_gui_layout.py 守住）。
        for col, (width, stretch) in _DEFAULT_PACKET_COLUMNS.items():
            self.table.heading(col, text=headings[col], command=partial(self._sort, col))
            self.table.column(col, width=width, minwidth=48, anchor=tk.W, stretch=stretch)
        self.table.column("len", anchor=tk.E)
        self.table.column("proto", anchor=tk.CENTER)
        table_scroll = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.table.yview)
        table_hscroll = ttk.Scrollbar(body, orient=tk.HORIZONTAL, command=self.table.xview)
        self.table.configure(yscrollcommand=table_scroll.set, xscrollcommand=table_hscroll.set)
        self.table.grid(row=0, column=0, sticky=tk.NSEW)
        table_scroll.grid(row=0, column=1, sticky=tk.NS)
        table_hscroll.grid(row=1, column=0, sticky=tk.EW)
        self.table.bind("<<TreeviewSelect>>", lambda _: self._show_selected())
        header = self._panel_headers[-1]
        self._table_hint = self._paint(
            tk.Label(header.actions, text="", font=self._theme.font_small),
            background="surface_2",
            foreground="text_faint",
        )
        self._table_hint.pack(side=tk.LEFT)

    def _build_inspector_panel(self, parent: ttk.PanedWindow) -> None:
        """详情面板：解析树与原始字节两个视图，用标签页切换以省下纵向空间。"""
        panel, body = self._new_panel(parent, "数据包检视")
        parent.add(panel, weight=2)
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        notebook = ttk.Notebook(body, style="Card.TNotebook")
        notebook.grid(row=0, column=0, sticky=tk.NSEW)

        tree_frame = ttk.Frame(notebook, style="Surface.TFrame")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.detail = ttk.Treeview(tree_frame, columns=("value",), show="tree headings", height=8)
        self.detail.heading("#0", text="字段", anchor=tk.W)
        self.detail.heading("value", text="值", anchor=tk.W)
        # 与数据包列表同理：这两列的默认宽度决定了检视面板的最小宽度，
        # 必须让 MIN_WINDOW_SIZE 放得下（_SASH_MIN_SIZES 的尾部下限取 340）。
        self.detail.column("#0", width=_DEFAULT_DETAIL_COLUMNS["#0"], minwidth=90, anchor=tk.W, stretch=False)
        self.detail.column("value", width=_DEFAULT_DETAIL_COLUMNS["value"], minwidth=80, anchor=tk.W, stretch=True)
        detail_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_scroll.set)
        self.detail.grid(row=0, column=0, sticky=tk.NSEW)
        detail_scroll.grid(row=0, column=1, sticky=tk.NS)
        notebook.add(tree_frame, text="解析树")

        hex_frame = ttk.Frame(notebook, style="Surface.TFrame")
        hex_frame.rowconfigure(0, weight=1)
        hex_frame.columnconfigure(0, weight=1)
        self.hex_view = tk.Text(hex_frame, height=8, width=1, wrap=tk.NONE, padx=8, pady=6)
        self._classic_widgets.append(self.hex_view)
        hex_scroll = ttk.Scrollbar(hex_frame, orient=tk.VERTICAL, command=self.hex_view.yview)
        hex_hscroll = ttk.Scrollbar(hex_frame, orient=tk.HORIZONTAL, command=self.hex_view.xview)
        self.hex_view.configure(yscrollcommand=hex_scroll.set, xscrollcommand=hex_hscroll.set)
        self.hex_view.grid(row=0, column=0, sticky=tk.NSEW)
        hex_scroll.grid(row=0, column=1, sticky=tk.NS)
        hex_hscroll.grid(row=1, column=0, sticky=tk.EW)
        notebook.add(hex_frame, text="原始字节")
        self._register_hex_tags()

    def _register_hex_tags(self) -> None:
        """十六进制视图的三段配色；tag 需在 Text 上注册，主题切换时重刷。"""
        colors = build_colors(self.dark_mode.get())
        for tag, key in (("offset", "text_faint"), ("bytes", "text"), ("ascii", "text_dim")):
            self.hex_view.tag_configure(tag, foreground=colors[key])
        self.hex_view.tag_configure("offset", font=self._theme.font_mono_small)
        self.hex_view.tag_configure("bytes", font=self._theme.font_mono_small)

    def _build_bottom_tabs(self, parent: tk.Misc) -> None:
        """底部区域：告警 / 解析问题 / 流量统计 / IDS 规则。

        原来这三个区域是并排的窄列，每个都放不下内容；改成标签页后
        同一块高度只服务一个视图，信息密度反而更低、可读性更高。
        """
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        notebook = ttk.Notebook(parent, style="Card.TNotebook")
        notebook.grid(row=0, column=0, sticky=tk.NSEW)
        self._bottom_tabs = notebook

        self._build_alert_tab(notebook)
        self._alert_tab_index = 0
        self._build_issue_tab(notebook)
        self._issue_tab_index = 1
        self._build_stats_tab(notebook)
        self._build_rules_tab(notebook)

    def _build_alert_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, style="Surface.TFrame")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        columns = ("time", "severity", "source", "msg", "tuple")
        self.alerts = ttk.Treeview(frame, columns=columns, show="headings", height=6)
        for col, (title, width, anchor) in zip(
            columns,
            (
                ("时间", 118, tk.W),
                ("级别", 48, tk.CENTER),
                ("来源", 104, tk.W),
                ("告警信息", 520, tk.W),
                ("五元组", 250, tk.W),
            ),
            strict=True,
        ):
            self.alerts.heading(col, text=title, command=partial(self._sort_alerts, col))
            self.alerts.column(col, width=width, anchor=cast("Any", anchor), stretch=col == "msg")
        self.alerts.column("time", stretch=False)
        self.alerts.column("severity", stretch=False)
        self.alerts.column("source", stretch=False)
        alert_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.alerts.yview)
        self.alerts.configure(yscrollcommand=alert_scroll.set)
        self.alerts.grid(row=0, column=0, sticky=tk.NSEW)
        alert_scroll.grid(row=0, column=1, sticky=tk.NS)
        self.alerts.bind("<Double-Button-1>", lambda _: self._jump_to_alert_packet())
        self.alerts.bind("<Return>", lambda _: self._jump_to_alert_packet())
        self._paint(
            tk.Label(frame, text="双击告警可定位到对应数据包", font=self._theme.font_tiny),
            background="surface",
            foreground="text_faint",
        ).grid(row=1, column=0, sticky=tk.W, padx=10, pady=(2, 4))
        notebook.add(frame, text="告警")

    def _build_issue_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, style="Surface.TFrame")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        columns = ("time", "layer", "message", "tuple")
        self.error_list = ttk.Treeview(frame, columns=columns, show="headings", height=6)
        for col, (title, width, anchor) in zip(
            columns,
            (
                ("时间", 88, tk.W),
                ("协议层", 82, tk.W),
                ("说明", 480, tk.W),
                ("五元组", 250, tk.W),
            ),
            strict=True,
        ):
            self.error_list.heading(col, text=title)
            self.error_list.column(col, width=width, anchor=cast("Any", anchor), stretch=col == "message")
        error_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.error_list.yview)
        self.error_list.configure(yscrollcommand=error_scroll.set)
        self.error_list.grid(row=0, column=0, sticky=tk.NSEW)
        error_scroll.grid(row=0, column=1, sticky=tk.NS)
        self.error_list.bind("<Double-Button-1>", lambda _: self._jump_to_error_packet())
        self._paint(
            tk.Label(
                frame,
                text="异常包不会被丢弃，而是标记问题后继续流转；双击可定位到对应数据包",
                font=self._theme.font_tiny,
            ),
            background="surface",
            foreground="text_faint",
        ).grid(row=1, column=0, sticky=tk.W, padx=10, pady=(2, 4))
        self.error_summary_var = tk.StringVar(value="解析问题 0 · 致命异常 0")
        self._paint(
            tk.Label(frame, textvariable=self.error_summary_var, font=self._theme.font_tiny),
            background="surface",
            foreground="danger",
        ).grid(row=1, column=0, sticky=tk.E, padx=10, pady=(2, 4))
        notebook.add(frame, text="解析问题")

    #: 流量统计页里固定展示的协议与它们的配色键
    _STATS_PROTOCOLS = ("TCP", "UDP", "HTTP", "DNS", "ICMP", "OTHER")

    def _build_stats_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, style="Surface.TFrame", padding=(12, 10))
        frame.columnconfigure(0, weight=1)
        notebook.add(frame, text="流量统计")

        totals = tk.Frame(frame, borderwidth=0, highlightthickness=0)
        self._paint(totals, background="surface")
        totals.grid(row=0, column=0, sticky=tk.EW)
        totals_spec = (
            ("total_bytes", "总字节"),
            ("total_packets", "总数据包"),
            ("dropped", "队列丢弃"),
            ("parse_errors", "致命异常"),
        )
        for column, (key, title) in enumerate(totals_spec):
            cell = tk.Frame(totals, borderwidth=0, highlightthickness=0)
            self._paint(cell, background="surface")
            cell.grid(row=0, column=column, sticky=tk.W, padx=(0, 34))
            self._paint(
                tk.Label(cell, text=title, font=self._theme.font_tiny), background="surface", foreground="text_faint"
            ).pack(anchor=tk.W)
            value = self._paint(
                tk.Label(cell, text="0", font=self._theme.font_mono), background="surface", foreground="text"
            )
            value.pack(anchor=tk.W)
            self._stats_cells[key] = value

        self._paint(
            tk.Label(frame, text="协议分布", font=self._theme.font_heading), background="surface", foreground="text_dim"
        ).grid(row=1, column=0, sticky=tk.W, pady=(12, 6))

        bars = tk.Frame(frame, borderwidth=0, highlightthickness=0)
        self._paint(bars, background="surface")
        bars.grid(row=2, column=0, sticky=tk.EW)
        # 名称 / 进度条 / 计数三段左对齐成一簇，多出来的宽度由末尾空白列吸收；
        # 否则计数会被推到面板最右侧，和它对应的协议名隔了半屏。
        bars.columnconfigure(_STATS_BAR_SPACER_COLUMN, weight=1)
        for row, proto in enumerate(self._STATS_PROTOCOLS):
            self._paint(
                tk.Label(bars, text=proto, width=6, anchor=tk.W, font=self._theme.font_mono_small),
                background="surface",
                foreground=protocol_color(build_colors(self.dark_mode.get()), proto),
            ).grid(row=row, column=0, sticky=tk.W, pady=1)
            track = tk.Frame(bars, height=6, width=_STATS_BAR_WIDTH, borderwidth=0, highlightthickness=0)
            self._paint(track, background="surface_3")
            track.grid(row=row, column=1, sticky=tk.W)
            track.grid_propagate(False)
            fill = tk.Frame(track, height=6, borderwidth=0, highlightthickness=0)
            self._paint(fill, background=PROTOCOL_COLOR_KEYS.get(proto.lower(), "proto_other"))
            fill.place(x=0, y=0, relwidth=0.0, relheight=1.0)
            count = self._paint(
                tk.Label(bars, text="0", width=8, anchor=tk.W, font=self._theme.font_mono_small),
                background="surface",
                foreground="text_dim",
            )
            count.grid(row=row, column=2, sticky=tk.W, padx=(10, 0))
            self._proto_bars[proto] = (track, fill, count)

    def _build_rules_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, style="Surface.TFrame")
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)
        actions = tk.Frame(frame, borderwidth=0, highlightthickness=0, padx=10, pady=7)
        self._paint(actions, background="surface")
        actions.grid(row=0, column=0, sticky=tk.EW)
        for text, hint, command in (
            ("加载规则", "把编辑框中的规则编译进 IDS 引擎", self._load_rules),
            ("规则模板", "从常用模板快速插入规则", self._show_ids_rule_templates),
            ("自动生成", "根据已捕获流量生成规则建议", self._show_rule_suggestions),
            ("清空规则", "清空编辑框中的全部规则", self._clear_rules),
        ):
            button = ttk.Button(actions, text=text, style="Ghost.TButton", command=command)
            button.pack(side=tk.LEFT, padx=(0, 6))
            self._tooltips.append(
                Tooltip(button, hint, dark=self.dark_mode.get(), dark_provider=lambda: self.dark_mode.get())
            )
        self._rule_count_label = self._paint(
            tk.Label(actions, text="已加载 0 条规则", font=self._theme.font_small),
            background="surface",
            foreground="text_faint",
        )
        self._rule_count_label.pack(side=tk.RIGHT)

        text_frame = tk.Frame(frame, borderwidth=0, highlightthickness=0)
        self._paint(text_frame, background="surface")
        text_frame.grid(row=1, column=0, sticky=tk.NSEW)
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)
        self.rules_text = tk.Text(text_frame, height=6, width=1, wrap=tk.NONE, padx=10, pady=8)
        self._classic_widgets.append(self.rules_text)
        rules_scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.rules_text.yview)
        self.rules_text.configure(yscrollcommand=rules_scroll.set)
        self.rules_text.grid(row=0, column=0, sticky=tk.NSEW)
        rules_scroll.grid(row=0, column=1, sticky=tk.NS)
        notebook.add(frame, text="IDS 规则")

    def _build_log_strip(self) -> None:
        colors = build_colors(self.dark_mode.get())
        strip = tk.Frame(self, height=30, borderwidth=0, highlightthickness=0)
        self._paint(strip, background="surface_2")
        strip.grid(row=2, column=0, sticky=tk.EW)
        strip.pack_propagate(False)
        self._log_strip = strip
        self._paint(hline(strip, colors["border"]), background="border").pack(side=tk.TOP, fill=tk.X)
        self._paint(
            tk.Label(strip, text="日志", font=self._theme.font_tiny), background="surface_2", foreground="text_faint"
        ).pack(side=tk.LEFT, padx=(12, 8))

        self._log_text = tk.Text(
            strip, height=1, width=1, wrap=tk.NONE, padx=0, pady=0, borderwidth=0, highlightthickness=0
        )
        self._classic_widgets.append(self._log_text)
        # 单行模式下只占一行的高度（fill=X，不纵向拉伸）：30px 的栏比一行文字
        # 高 9px，拉伸开就会露出上一行的下半截，看起来像两行文字叠在一起
        self._log_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._log_text.configure(state=tk.DISABLED)

        self._log_expand_btn = ttk.Button(strip, text="展开", width=5, style="Tiny.TButton", command=self._toggle_log)
        self._log_expand_btn.pack(side=tk.RIGHT, padx=6)
        self._error_badge = self._paint(
            tk.Label(strip, text="", font=self._theme.font_tiny), background="surface_2", foreground="danger"
        )
        self._error_badge.pack(side=tk.RIGHT, padx=(0, 4))

    def _build_status_bar(self) -> None:
        colors = build_colors(self.dark_mode.get())
        bar = tk.Frame(self, height=27, borderwidth=0, highlightthickness=0)
        self._paint(bar, background="surface")
        bar.grid(row=3, column=0, sticky=tk.EW)
        bar.pack_propagate(False)
        self._paint(hline(bar, colors["border"]), background="border").pack(side=tk.BOTTOM, fill=tk.X)

        self._status_bar = self._paint(
            tk.Label(bar, textvariable=self.status_text_var, font=self._theme.font_small),
            background="surface",
            foreground="text_dim",
        )
        self._status_bar.pack(side=tk.LEFT, padx=(12, 10))
        self._status_detail = self._paint(
            tk.Label(bar, text="", font=self._theme.font_small), background="surface", foreground="text_faint"
        )
        self._status_detail.pack(side=tk.LEFT)
        self._paint(
            tk.Label(bar, text=f"NetGuard {__version__}", font=self._theme.font_small),
            background="surface",
            foreground="text_faint",
        ).pack(side=tk.RIGHT, padx=(0, 12))

    def _build_tooltips(self) -> None:
        pairs = [
            (self.device_box, "选择用于抓包或扫描的网络接口"),
            (self.bpf_var_entry, "BPF 捕获过滤表达式，开始抓包时生效（如 tcp port 80）"),
            (self.display_filter_entry, "在当前已捕获数据中筛选（Ctrl+F 聚焦）"),
        ]
        for widget, text in pairs:
            if widget is not None:
                self._tooltips.append(
                    Tooltip(widget, text, dark=self.dark_mode.get(), dark_provider=lambda: self.dark_mode.get())
                )

    def _build_menu(self) -> None:
        menubar = tk.Menu(self, tearoff=0)
        self._menus = [menubar]

        file_menu = self._submenu(menubar, "文件")
        file_menu.add_command(label="打开 pcap…", accelerator="Ctrl+O", command=self._open_pcap)
        file_menu.add_command(label="保存 pcap…", accelerator="Ctrl+S", command=self._save_pcap)
        file_menu.add_command(label="导出告警…", accelerator="Ctrl+E", command=self._export_alerts)
        file_menu.add_command(label="导出数据包 CSV…", command=self._export_packets_csv)
        file_menu.add_separator()
        file_menu.add_command(label="退出", accelerator="Ctrl+Q", command=self._exit)
        menubar.add_cascade(label="文件", menu=file_menu)

        capture_menu = self._submenu(menubar, "捕获")
        capture_menu.add_command(label="开始抓包", accelerator="F5", command=self._start)
        capture_menu.add_command(label="停止抓包", accelerator="Shift+F5", command=self._stop)
        capture_menu.add_command(label="暂停/恢复刷新", accelerator="Ctrl+P", command=self._toggle_pause)
        capture_menu.add_separator()
        capture_menu.add_command(label="清空数据", accelerator="Ctrl+L", command=self._clear)
        capture_menu.add_command(label="应用推荐网卡", command=self._apply_recommended_device)
        menubar.add_cascade(label="捕获", menu=capture_menu)

        view_menu = self._submenu(menubar, "视图")
        theme_menu = self._submenu(view_menu, "主题")
        for label, mode in (("浅色", "light"), ("深色", "dark"), ("跟随系统", "system")):
            theme_menu.add_radiobutton(
                label=label,
                value=mode,
                variable=self.theme_mode,
                command=partial(self._set_theme_mode, mode),
            )
        view_menu.add_cascade(label="主题", menu=theme_menu)
        view_menu.add_command(label="聚焦显示过滤", accelerator="Ctrl+F", command=self._focus_display_filter)
        menubar.add_cascade(label="视图", menu=view_menu)

        tools_menu = self._submenu(menubar, "工具")
        tools_menu.add_command(label="测试发包…", command=self._open_traffic_gen)
        tools_menu.add_command(label="网段扫描…", command=self._open_subnet_scan)
        tools_menu.add_separator()
        tools_menu.add_command(label="加载 IDS 规则", command=self._load_rules)
        tools_menu.add_command(label="IDS 规则模板…", command=self._show_ids_rule_templates)
        tools_menu.add_command(label="自动生成规则…", command=self._show_rule_suggestions)
        menubar.add_cascade(label="工具", menu=tools_menu)

        help_menu = self._submenu(menubar, "帮助")
        help_menu.add_command(label="快捷键说明", accelerator="F1", command=self._show_shortcuts)
        menubar.add_cascade(label="帮助", menu=help_menu)

        self.configure(menu=menubar)

    def _submenu(self, parent: tk.Menu, _label: str) -> tk.Menu:
        menu = tk.Menu(parent, tearoff=0)
        self._menus.append(menu)
        return menu

    @staticmethod
    def _invoke_ignoring_event(callback: Callable[[], None], _event: tk.Event | None = None) -> None:
        """适配 Tk 的 event 回调约定：丢弃 event，只调用无参回调。"""
        callback()

    def _bind_shortcuts(self) -> None:
        # 绑定到主窗口而非 bind_all，避免对话框打开时快捷键误触发主窗口动作
        mapping = {
            "<F5>": self._start,
            "<Shift-F5>": self._stop,
            "<Control-p>": self._toggle_pause,
            "<Control-l>": self._clear,
            "<Control-o>": self._open_pcap,
            "<Control-s>": self._save_pcap,
            "<Control-e>": self._export_alerts,
            "<Control-f>": self._focus_display_filter,
            "<Control-q>": self._exit,
            "<F1>": self._show_shortcuts,
            "<Escape>": self._on_escape,
        }
        for sequence, callback in mapping.items():
            self.bind(sequence, partial(self._invoke_ignoring_event, callback))
        # Tk Text 类绑定了 <Control-o>（自插入换行），与「打开 pcap」冲突。
        # 控件级绑定先于类绑定执行，这里直接执行打开动作并返回 "break"，
        # 一次按键只打开文件、不再插入换行。注意不能只返回 "break"：那会连同
        # 主窗口的绑定一起吃掉，快捷键看起来彻底失效。
        for text in (self._log_text, self.hex_view, self.rules_text):
            if text is not None:
                text.bind("<Control-o>", self._open_pcap_from_text)

    def _open_pcap_from_text(self, _event: tk.Event | None = None) -> str:
        """Text 控件内的 Ctrl+O：执行打开动作并阻断 Tk 的默认换行插入。"""
        self._open_pcap()
        return "break"

    def _on_escape(self) -> None:
        # 焦点在输入框时 Esc 是取消/收起输入的惯例，不应弹"停止抓包"确认框
        focused = self.focus_get()
        if isinstance(focused, (tk.Entry, ttk.Entry, tk.Text, ttk.Combobox, tk.Spinbox)):
            return
        self._stop()

    def _focus_display_filter(self) -> None:
        self.display_filter_entry.focus_set()
        self.display_filter_entry.select_range(0, tk.END)

    def _show_shortcuts(self) -> None:
        lines = [f"{label}：{accel}" for label, accel, _seq in SHORTCUTS]
        messagebox.showinfo("快捷键说明", "\n".join(lines), parent=self)

    def _build_table_menu(self) -> None:
        menu = tk.Menu(self, tearoff=0)
        self._menus.append(menu)
        menu.add_command(label="复制摘要", command=lambda: self._copy_selected("summary"))
        menu.add_command(label="复制整行", command=lambda: self._copy_selected("row"))
        menu.add_command(label="复制源→目的", command=lambda: self._copy_selected("endpoints"))
        menu.add_command(label="复制解析详情", command=lambda: self._copy_selected("detail"))
        menu.add_command(label="复制十六进制", command=lambda: self._copy_selected("hex"))
        menu.add_separator()
        menu.add_command(label="用摘要筛选", command=self._filter_by_selected_summary)
        menu.add_command(label="定位告警", command=self._jump_to_alert_packet)
        menu.add_separator()
        menu.add_command(label="自适应列宽", command=self._autofit_columns)
        menu.add_command(label="导出数据包 CSV…", command=self._export_packets_csv)
        self._table_menu = menu
        self.table.bind("<Button-3>", self._popup_table_menu)
        if sys.platform == "darwin":
            self.table.bind("<Control-Button-1>", self._popup_table_menu)
        self.table.bind("<Control-c>", lambda _e: self._copy_selected("row"))
        self.table.bind("<ButtonRelease-1>", self._maybe_autofit_separator, add="+")

    def _autofit_columns(self) -> None:
        """按当前表格内容计算每列宽度（双击表头分隔线或右键菜单触发）。"""
        padding = 18
        for col in self.table["columns"]:
            try:
                header = self.table.heading(col, "text").replace(" ▲", "").replace(" ▼", "")
            except tk.TclError:
                continue
            max_len = len(str(header))
            for row in self.table.get_children():
                value = self.table.set(row, col)
                if len(value) > max_len:
                    max_len = len(value)
            width = max(48, min(560, max_len * 7 + padding))
            try:
                self.table.column(col, width=width)
            except tk.TclError:
                continue
        self._schedule_config_save()

    def _maybe_autofit_separator(self, event: tk.Event) -> None:
        """双击表头分隔线时对该列做内容自适应。"""
        if self.table.identify_region(event.x, event.y) != "separator":
            return
        if self._last_separator_click is not None:
            last_time, last_x = self._last_separator_click
            if event.time - last_time < 500 and abs(event.x - last_x) < 8:
                col_id = self.table.identify_column(event.x)
                if col_id:
                    self._autofit_columns()
                self._last_separator_click = None
                return
        self._last_separator_click = (event.time, event.x)

    def _export_packets_csv(self) -> None:
        if not self.events:
            messagebox.showinfo("导出 CSV", "当前没有可导出的数据包。", parent=self)
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")],
            parent=self,
        )
        if not path:
            return
        # 在主线程快照（遵循过滤条件），后台只做文件写入
        rows = [
            self.events[idx - self.event_offset].packet
            for idx in self.filtered
            if 0 <= idx - self.event_offset < len(self.events)
        ]

        def work() -> int:
            import csv

            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["时间", "源地址", "源端口", "目的地址", "目的端口", "协议", "长度", "摘要"])
                for packet in rows:
                    writer.writerow(
                        [
                            f"{packet.timestamp:.3f}",
                            packet.src,
                            packet.src_port or "",
                            packet.dst,
                            packet.dst_port or "",
                            packet.protocol,
                            packet.length,
                            packet.summary,
                        ]
                    )
            return len(rows)

        def done(count: int) -> None:
            self._log(f"已导出 {count} 条数据包到 {path}")

        self._run_in_background(work, done, "正在导出 CSV…", "导出错误")

    def _popup_table_menu(self, event: tk.Event) -> None:
        row = self.table.identify_row(event.y)
        if row:
            self.table.selection_set(row)
            self.table.focus(row)
        try:
            apply_menu(self._table_menu, build_colors(self.dark_mode.get()))
            self._table_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._table_menu.grab_release()

    def _selected_event(self) -> PacketEvent | None:
        selection = self.table.selection()
        if not selection:
            return None
        try:
            return self._event_at(int(selection[0]))
        except (TypeError, ValueError):
            return None

    def _copy_selected(self, mode: str) -> None:
        event = self._selected_event()
        if event is None:
            return
        packet = event.packet
        if mode == "summary":
            text = packet.summary
        elif mode == "endpoints":
            text = f"{packet.src}:{packet.src_port or ''} -> {packet.dst}:{packet.dst_port or ''}"
        elif mode == "hex":
            text = "\n".join(
                f"{offset}  {hex_text:<48}  {ascii_text}" for offset, hex_text, ascii_text in hex_rows(packet.raw)
            )
        elif mode == "detail":
            text = _format_packet(packet)
        else:
            text = "\t".join(packet_row(packet))
        self.clipboard_clear()
        self.clipboard_append(text)
        self._log("已复制到剪贴板")

    def _filter_by_selected_summary(self) -> None:
        event = self._selected_event()
        if event is None:
            return
        self.display_filter.set(event.packet.protocol)
        self._refilter()

    def _update_sort_indicator(self) -> None:
        base = {
            "time": "时间",
            "src": "源地址",
            "dst": "目的地址",
            "proto": "协议",
            "len": "长度",
            "summary": "摘要",
        }
        for col, text in base.items():
            if col == self._sort_column:
                text += " ▼" if self._sort_descending else " ▲"
            try:
                self.table.heading(col, text=text)
            except tk.TclError:
                continue

    # --- 后台执行 ---------------------------------------------------------

    def _run_in_background(
        self, work: Callable[[], _T], on_done: Callable[[_T], None], busy_text: str, error_title: str
    ) -> None:
        """在后台线程执行耗时工作，完成后由主线程回调。

        结果通过线程安全队列回传，由 `_pump_background` 在主线程消费——绝不在
        子线程调用 Tk（`after` 在非 mainloop 线程下不可靠）。队列里存的是已绑定
        好结果的零参回调，主线程只需调用，无需再做类型判断。
        """
        self._begin_busy(busy_text)

        def runner() -> None:
            try:
                result = work()
            except Exception as exc:
                logger.exception("后台任务失败：%s", busy_text)
                self._background_queue.put(("error", error_title, str(exc), None))
                return
            self._background_queue.put(("ok", None, None, lambda: on_done(result)))

        threading.Thread(target=runner, name="netguard-bg", daemon=True).start()

    def _pump_background(self) -> None:
        """主线程消费后台任务结果（由 _tick 调用）。"""
        while True:
            try:
                kind, title, message, payload = self._background_queue.get_nowait()
            except queue.Empty:
                return
            self._end_busy()
            if kind == "error":
                messagebox.showerror(title or "错误", message or "", parent=self)
            else:
                callback = payload
                if callback is None:
                    continue
                try:
                    callback()
                except Exception:
                    logger.exception("后台任务回调异常")

    def _begin_busy(self, text: str) -> None:
        self._busy_count += 1
        self.busy_text_var.set(text)
        with suppress(tk.TclError):
            self.configure(cursor="watch")

    def _end_busy(self) -> None:
        self._busy_count = max(0, self._busy_count - 1)
        if self._busy_count == 0:
            self.busy_text_var.set("")
            with suppress(tk.TclError):
                self.configure(cursor="")

    def _on_busy(self, text: str) -> None:
        self.busy_text_var.set(text)

    def _load_devices(self) -> None:
        self._log("正在加载网卡...")
        # 走 _run_in_background：结果经 _background_queue 由主线程派发，不在子线程碰 Tk
        self._run_in_background(
            self.pipeline.list_devices,
            self._set_devices,
            "正在加载网卡…",
            "网卡加载失败",
        )

    def _set_devices(self, devices: list[CaptureDevice]) -> None:
        self.device_displays = build_device_displays(devices)
        values = [item.display_name for item in self.device_displays]
        self.display_to_device = {item.display_name: item.device.name for item in self.device_displays}
        self.device_box["values"] = values
        _fit_combobox_width(self.device_box, values, max_width=42)
        if not values:
            self._log("未找到可用网卡")
            self._update_control_states()
            return
        remembered = self._config.window.last_device
        restored = False
        for item in self.device_displays:
            if item.device.name == remembered:
                self.device_var.set(item.display_name)
                self._log(f"已恢复上次使用的网卡：{item.friendly_name}")
                restored = True
                break
        if not restored:
            self._apply_recommended_device(f"已加载 {len(values)} 个网卡，已自动选择推荐网卡")
        self._update_control_states()

    def _set_initial_empty_state(self) -> None:
        # 空状态的文字要短：解析树的两列是定宽（字段 120px / 值 200px），
        # Treeview 单元格不会换行，长句子会被直接截断成半句
        self._show_empty_detail("未选中数据包", "点选一行查看协议字段")
        self._set_hex_message("未选中数据包", "点选数据包后这里显示原始字节（十六进制 + ASCII）。")
        if self._table_hint is not None:
            self._table_hint.configure(text="尚未捕获任何数据包 · 点击左侧「开始」或按 F5 启动")

    def _show_empty_detail(self, title: str, hint: str) -> None:
        """详情面板的空状态：清空解析树并给出下一步提示。"""
        self._clear_detail_tree()
        self.detail.insert("", tk.END, iid="__empty__", text=f"  {title}", values=("",), tags=("group",))
        self.detail.insert("", tk.END, iid="__empty_hint__", text="", values=(hint,), tags=("key",))
        self._detail_nodes["__empty__"] = DetailNode(title, kind="group")
        self._detail_nodes["__empty_hint__"] = DetailNode(hint, kind="key")

    def _set_hex_message(self, title: str, hint: str) -> None:
        self.hex_view.configure(state=tk.NORMAL)
        self.hex_view.delete("1.0", tk.END)
        self.hex_view.insert(tk.END, f"{title}\n\n{hint}")
        self.hex_view.configure(state=tk.DISABLED)

    def _clear_detail_tree(self) -> None:
        self._detail_nodes.clear()
        with suppress(tk.TclError):
            self.detail.delete(*self.detail.get_children())

    def _update_control_states(self) -> None:
        has_device = bool(self._selected_device_name())
        states = {
            "start": tk.NORMAL if has_device and not self.capturing else tk.DISABLED,
            "stop": tk.NORMAL if self.capturing else tk.DISABLED,
            "pause": tk.NORMAL if self.capturing else tk.DISABLED,
            "export": tk.NORMAL if self._real_alert_count() > 0 else tk.DISABLED,
            "save": tk.NORMAL if self.events else tk.DISABLED,
        }
        for key, state in states.items():
            button = self._rail_buttons.get(key)
            if button is not None:
                with suppress(tk.TclError):
                    button.configure(state=state)
        self._sync_rail_styles()
        self._update_indicator()

    def _sync_rail_styles(self) -> None:
        """按运行状态为操作轨按钮选样式：抓包中把「停止」提为主操作。"""
        mapping = {
            "start": "RailAccent.TButton" if not self.capturing else "Rail.TButton",
            "stop": "RailDanger.TButton" if self.capturing else "Rail.TButton",
            "pause": "RailActive.TButton" if self.capturing and self.paused else "Rail.TButton",
        }
        for key, style in mapping.items():
            button = self._rail_buttons.get(key)
            if button is None:
                continue
            with suppress(tk.TclError):
                button.configure(style=style)

    def _log(self, msg: str) -> None:
        if self._log_text is None:
            return
        self._log_text.configure(state=tk.NORMAL)
        # 行间换行写在「下一条」之前，日志末尾不留换行：Text 末尾的换行会多出一条
        # 空显示行，滚到底部时看到的是那条空行，最后一条日志反被挤到可视区之外
        # （单行模式下表现为整条日志看不见，或只露出上半截）。
        prefix = "" if self._log_text.index("end-1c") == "1.0" else "\n"
        self._log_text.insert(tk.END, f"{prefix}{msg}")
        lines = int(self._log_text.index("end-1c").split(".")[0])
        if lines > 200:
            self._log_text.delete("1.0", f"{lines - 150}.0")
        self._log_text.yview_moveto(1.0)
        self._log_text.configure(state=tk.DISABLED)

    def _toggle_log(self) -> None:
        """日志条在单行与 8 行之间切换；单行模式下始终显示最新一条。"""
        self._log_expanded = not self._log_expanded
        if self._log_strip is None or self._log_text is None:
            return
        self._log_strip.configure(height=30 if not self._log_expanded else 138)
        self._log_text.configure(height=1 if not self._log_expanded else 7)
        # 展开时把文本域纵向铺满，收起时只占一行（多出来的高度会露出上一行）
        self._log_text.pack_configure(fill=tk.BOTH if self._log_expanded else tk.X)
        if self._log_expand_btn is not None:
            self._log_expand_btn.configure(text="展开" if not self._log_expanded else "收起")
        self._log_text.yview_moveto(1.0)

    def _update_indicator(self) -> None:
        colors = build_colors(self.dark_mode.get())
        if self.capturing and not self.paused:
            state, text, detail = "capturing", "抓包中", self._active_bpf_filter or "全部流量"
        elif self.capturing and self.paused:
            state, text, detail = "paused", "已暂停", "界面刷新已暂停，抓包仍在继续"
        else:
            state, text, detail = "idle", "空闲", "未开始抓包"
        self.status_text_var.set(text)
        if self._pill is not None:
            self._pill.set_state(text, colors, state)
        if self._status_bar is not None:
            token = "success" if state == "capturing" else "warning" if state == "paused" else "text_dim"
            self._status_bar.configure(foreground=colors[token])
        if self._status_detail is not None:
            self._status_detail.configure(text=f"· {detail}")

    def _real_alert_count(self) -> int:
        """告警表里真实告警的行数（表头计数、KPI 卡与导出都以它为准）。"""
        return len(self.alerts.get_children())

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

    def _load_rules(self) -> None:
        text = self.rules_text.get("1.0", tk.END)

        def work() -> int:
            return self.pipeline.load_rules(text)

        def done(failed: int) -> None:
            failed_count = failed
            loaded = self.pipeline.rule_count
            if failed_count:
                self._log(f"已加载 {loaded} 条规则，跳过 {failed_count} 条无效规则")
            else:
                self._log(f"已加载 {loaded} 条 IDS 规则")

        self._run_in_background(work, done, "正在加载 IDS 规则…", "规则错误")

    def _load_rules_now(self) -> int:
        """同步加载规则；供 _start 在抓包前调用，确保规则已生效。"""
        failed = self.pipeline.load_rules(self.rules_text.get("1.0", tk.END))
        loaded = self.pipeline.rule_count
        if failed:
            self._log(f"已加载 {loaded} 条规则，跳过 {failed} 条无效规则")
        else:
            self._log(f"已加载 {loaded} 条 IDS 规则")
        return failed

    def _clear_rules(self) -> None:
        self.rules_text.delete("1.0", tk.END)
        self._log("已清空 IDS 规则")

    def _open_traffic_gen(self) -> None:
        TrafficGenDialog(self)

    def _open_subnet_scan(self) -> None:
        display = self._selected_device_display()
        if display is None:
            messagebox.showwarning("网段扫描", "请先在主窗口选择一个网卡。", parent=self)
            return
        SubnetScanDialog(
            self,
            display,
            self.device_displays,
            self.bpf_var,
            on_switch_device=self._switch_to_device,
            on_add_bpf_template=self._add_bpf_template,
        )

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
                messagebox.showwarning("网卡", "请先选择一个网络接口。", parent=self)
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
                parent=self,
            ):
                current = self._format_bpf_for_log(getattr(self, "_active_bpf_filter", ""))
                self._log(f"已取消应用 BPF，当前抓包仍使用：{current}")
                return
            self.bpf_var.set(value)
            self.paused = False
            self._set_rail_text("pause", "暂停")
            self.pipeline.stop()
            self.pipeline.reset_state()
            self._clear_capture_data()
            try:
                self._load_rules_now()
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
                messagebox.showerror("抓包错误", str(exc), parent=self)
        else:
            self.bpf_var.set(value)
            self._log(f"BPF 过滤条件已更新，开始抓包时生效：{self._format_bpf_for_log(value)}")

    def _open_pcap(self) -> None:
        if self.capturing:
            messagebox.showinfo("打开 pcap", "请先停止当前抓包，再打开 pcap 文件。", parent=self)
            return
        path = filedialog.askopenfilename(
            title="打开 pcap 文件",
            filetypes=[("pcap 文件", "*.pcap *.cap"), ("所有文件", "*.*")],
            parent=self,
        )
        if not path:
            return
        try:
            self._clear_capture_data()
            self.pipeline.start_file(path)
            self.capturing = True
            self.paused = False
            self._active_bpf_filter = ""
            self._set_rail_text("pause", "暂停")
            self._log(f"正在离线回放 {path}")
            self._update_control_states()
        except Exception as exc:
            self.capturing = False
            self._update_control_states()
            messagebox.showerror("打开失败", str(exc), parent=self)

    def _save_pcap(self) -> None:
        if not self.events:
            messagebox.showinfo("保存 pcap", "当前没有可保存的数据包。", parent=self)
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("pcap 文件", "*.pcap"), ("所有文件", "*.*")],
            parent=self,
        )
        if not path:
            return
        raws = [
            RawPacket(event.packet.timestamp, event.packet.raw, len(event.packet.raw), event.packet.length)
            for event in self.events
        ]

        def work() -> int:
            return write_pcap(path, raws)

        def done(count: int) -> None:
            self._log(f"已保存 {count} 个数据包到 {path}")

        self._run_in_background(work, done, "正在保存 pcap…", "保存错误")

    def _clear_capture_data(self) -> None:
        self.events.clear()
        self.event_offset = 0
        self.filtered.clear()
        self._alert_by_row.clear()
        self._alert_seq = 0
        self._last_error_refresh = 0.0
        self._last_error_state = None
        self.table.delete(*self.table.get_children())
        self.alerts.delete(*self.alerts.get_children())
        self._clear_detail_tree()
        self._reset_stats_display()
        self._update_packet_count()
        # 标签页标题带实时计数，清空后必须一起归零，否则会一直显示「告警（N）」
        self._update_alert_tab_label()
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

    def _apply_sash_positions(self, attempt: int = 0) -> None:
        """等窗口真正成形后再恢复分隔条位置。

        ttk.PanedWindow 会把 sashpos 钳制到「当前」可用空间：在窗口还没完成
        首次布局时写入，请求的 554 会被夹成 0，主区域就塌成一条线。
        这里先 update_idletasks 逼出一次布局，必要时有限次重试。
        """
        with suppress(tk.TclError):
            self.update_idletasks()
        if self.winfo_height() <= 100 and attempt < _SASH_RETRY_LIMIT:
            self.after(60, lambda: self._apply_sash_positions(attempt + 1))
            return
        self._apply_saved_sashes()

    def _restore_layout_state(self) -> None:
        window = self._config.window
        for col, width in window.columns.items():
            try:
                self.table.column(col, width=width)
            except tk.TclError:
                continue
        if window.sort_column in {"time", "src", "dst", "proto", "len", "summary"}:
            self._sort_column = window.sort_column
            self._sort_descending = window.sort_descending
            self._update_sort_indicator()
        # 未知列名（配置损坏/旧版残留）直接丢弃：恢复后首次过滤重建会在
        # 排序步骤抛 TclError，中断整个重建链
        # 上次网卡在设备异步加载完成后恢复（见 _set_devices）

    def _apply_saved_sashes(self) -> None:
        w = self.winfo_width()
        h = self.winfo_height()
        if w <= 100 or h <= 100:
            return
        saved = self._config.window.sashes
        # 旧布局的底部是「告警│统计│规则」三栏，它的 "bottom" 键在新布局里没有对应
        # 窗格。看到它就说明配置来自重构前，此时整组分割位置都不可信，直接用默认值，
        # 免得老用户升级后看到一格被压扁的窗口。
        if "bottom" in saved:
            saved = {}
        # 默认分割比例：数据包列表约占六成，底部标签页留三分之一。
        # 关键是用「窗格自身的尺寸」算，而不是窗口尺寸——否则底部会被挤成一条缝。
        for name, pane in (("workspace", self._workspace), ("main", self._main_panes)):
            span = pane.winfo_height() if name == "workspace" else pane.winfo_width()
            if span <= 1:
                continue
            positions = saved.get(name) or [int((span - 8) * 0.62)]
            self._set_sash_positions(name, pane, positions)

    def _set_sash_positions(self, name: str, pane: ttk.PanedWindow, positions: list[int]) -> None:
        """钳制后写入分隔条位置：两侧窗格都要留够显示内容的最小尺寸。

        ttk.PanedWindow 的分隔条位置是绝对值，窗口变窄时不会自动回退；不钳制的话
        检视面板会被压成一条缝，值列（面板里唯一的内容）直接被裁掉。
        尾部下限取「常量与尾部窗格请求尺寸中的较大者」，这样用户把检视面板的列拖宽
        之后，缩窗口也不会把值列裁掉。
        """
        span = pane.winfo_height() if name == "workspace" else pane.winfo_width()
        if span <= 1:
            return
        min_lead, min_tail = _SASH_MIN_SIZES[name]
        min_tail = max(min_tail, self._tail_pane_min(pane, horizontal=name == "main"))
        if span < min_lead + min_tail:
            # 空间不足以同时满足两侧时均分，总比让一侧彻底塌掉好
            min_lead = min_tail = span // 2
        for index, pos in enumerate(positions):
            clamped = max(min_lead, min(min(int(pos), span - min_tail), span - min_lead))
            try:
                if pane.sashpos(index) == clamped:
                    # 已经是合法位置：不写回，避免无谓的重新布局（也避免回调自激）
                    continue
                pane.sashpos(index, clamped)
            except (tk.TclError, IndexError):
                break

    def _tail_pane_min(self, pane: ttk.PanedWindow, *, horizontal: bool) -> int:
        """尾部窗格的请求尺寸（内容决定的最小可用宽度/高度）；取不到时返回 0。"""
        panes = pane.panes()
        if len(panes) < 2:
            return 0
        try:
            widget = self.nametowidget(panes[-1])
        except tk.TclError:
            return 0
        size = widget.winfo_reqwidth() if horizontal else widget.winfo_reqheight()
        return max(0, int(size))

    def _on_pane_configure(self, name: str, _event: tk.Event | None = None) -> None:
        """窗格尺寸变化后重新钳制分隔条。

        每次事件都排一个空闲回调（不合并）：一次拖动会连发多个事件，而回调读的是
        窗格「当时」的尺寸——只有最后那次读到的才是最终布局。
        """
        self.after_idle(partial(self._clamp_sash_now, name))

    def _clamp_sash_now(self, name: str) -> None:
        """只处理当前分隔条位置，不回到配置里的旧值——用户拖动过的位置要保留。"""
        pane = self._workspace if name == "workspace" else self._main_panes
        try:
            positions = [pane.sashpos(index) for index in range(max(0, len(pane.panes()) - 1))]
        except tk.TclError:
            return
        if positions:
            self._set_sash_positions(name, pane, positions)

    def _apply_display_filter_template(self, value: str) -> None:
        self.display_filter.set(value)
        self._refilter()

    def _show_rule_suggestions(self) -> None:
        if not self.events:
            messagebox.showinfo(
                "自动生成规则", "当前还没有可用于生成 IDS 规则的 TCP、UDP、HTTP 或 DNS 数据包。", parent=self
            )
            return
        self._log("正在分析数据包生成 IDS 规则建议...")
        # 主线程快照，避免后台线程遍历 self.events 时与 _tick 的裁剪竞争
        packets = [event.packet for event in self.events]
        self._run_in_background(
            lambda: generate_rule_suggestions(packets, limit=8),
            self._show_suggestions_result,
            "正在生成规则建议…",
            "自动生成规则",
        )

    def _show_suggestions_result(self, suggestions: list[RuleSuggestion]) -> None:
        if not suggestions:
            self._log("自动生成规则：无可用建议")
            messagebox.showinfo(
                "自动生成规则", "当前还没有可用于生成 IDS 规则的 TCP、UDP、HTTP 或 DNS 数据包。", parent=self
            )
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
        if self.capturing:
            # F5 快捷键绕过按钮禁用状态；抓包中重复 start 会静默重启并清零统计
            return
        device = self._selected_device_name()
        if not device:
            messagebox.showwarning("网卡", "请先选择一个网络接口。", parent=self)
            return
        bpf_filter = self.bpf_var.get().strip()
        self.bpf_var.set(bpf_filter)
        try:
            self._load_rules_now()
            self.pipeline.start(device, bpf_filter)
            self.capturing = True
            self._active_bpf_filter = bpf_filter
            self.paused = False
            self._set_rail_text("pause", "暂停")
            self._log(f"正在监听 {self.device_var.get()}，BPF：{self._format_bpf_for_log(bpf_filter)}")
            self._update_control_states()
        except Exception as exc:
            self.capturing = False
            self._active_bpf_filter = ""
            self._update_control_states()
            self._log("抓包启动失败")
            messagebox.showerror("抓包错误", str(exc), parent=self)

    def _stop(self) -> None:
        if not self.capturing:
            return
        if not messagebox.askokcancel("停止抓包", "确定要停止抓包吗？", parent=self):
            return
        self.pipeline.stop()
        self.capturing = False
        self._active_bpf_filter = ""
        self.paused = False
        self._set_rail_text("pause", "暂停")
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
        if not messagebox.askokcancel("退出程序", msg, parent=self):
            return
        if was_capturing:
            self.pipeline.stop()
            self.capturing = False
            self.paused = False
        # 后台写盘线程是 daemon，直接 destroy 会被硬杀，保存的 pcap/告警
        # 文件静默截断；退出前在主线程等待任务排空
        self._wait_background_tasks()
        self._save_config()
        self.destroy()

    def _wait_background_tasks(self, timeout: float = 10.0) -> None:
        """等待后台任务（保存 pcap、导出告警等）完成再退出。"""
        if self._busy_count <= 0:
            return
        self._begin_busy("正在等待后台写盘完成…")
        deadline = time.monotonic() + timeout
        try:
            while self._busy_count > 1 and time.monotonic() < deadline:
                self._pump_background()
                try:
                    self.update_idletasks()
                except tk.TclError:
                    break
                time.sleep(0.02)
            self._pump_background()
        finally:
            self._end_busy()

    def _toggle_pause(self) -> None:
        if not self.capturing:
            return
        self.paused = not self.paused
        if self.paused:
            self._pause_event_total = self.event_offset + len(self.events)
            self._set_rail_text("pause", "恢复")
            self._log("已暂停刷新")
        else:
            self._set_rail_text("pause", "暂停")
            self._log("已恢复刷新")
            self._refilter()
            self._catch_up_paused_alerts()
        self._update_indicator()

    def _catch_up_paused_alerts(self) -> None:
        pause_total = getattr(self, "_pause_event_total", 0)
        rows: list[tuple[int, Alert]] = []
        for local_idx, event in enumerate(self.events):
            global_idx = self.event_offset + local_idx
            if global_idx < pause_total:
                continue
            rows.extend((global_idx, alert) for alert in event.alerts)
        self._insert_alert_rows(rows)

    def _update_packet_count(self) -> None:
        shown = len(self.filtered)
        total = len(self.events)
        if self._match_chip is not None:
            self._match_chip.configure(text=f"{shown:,} / {total:,} 条匹配")
        if self._table_hint is not None:
            hint = f"共 {total:,} 条 · 显示 {shown:,}" if total else "尚未捕获任何数据包 · 点击左侧「开始」或按 F5 启动"
            self._table_hint.configure(text=hint)

    def _clear(self) -> None:
        self._clear_capture_data()
        self._update_control_states()

    def _tick(self) -> None:
        if self.__dict__.get("_destroyed", False):
            return
        try:
            self._pump_background()
            t0 = time.monotonic()
            capture_error = self.pipeline.capture_error
            if capture_error and self.capturing:
                self._log(f"抓包错误：{capture_error}")
                self.pipeline.stop()
                self.capturing = False
                self.paused = False
                self._set_rail_text("pause", "暂停")
                self._log("抓包已因错误停止，请检查网卡权限或重新选择网卡后重试")
                self._update_control_states()
            events = self.pipeline.pump(PUMP_BATCH)
            if not events and self.capturing and not self.paused and self.pipeline.replay_finished:
                self._log("pcap 回放已完成")
                self.capturing = False
                self.paused = False
                self._set_rail_text("pause", "暂停")
                self._update_control_states()
            if events:
                start_idx = self.event_offset + len(self.events)
                self.events.extend(events)
                if len(self.events) > MAX_EVENTS:
                    self._drop_oldest_events(len(self.events) - MAX_EVENTS)
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
        rows = [(start_idx + offset, alert) for offset, event in enumerate(events) for alert in event.alerts]
        self._insert_alert_rows(rows)

    def _insert_alert_rows(self, rows: list[tuple[int, Alert]]) -> None:
        """把 (数据包全局索引, 告警) 追加进告警表。

        行 iid 形如 ``"{数据包索引}:{序号}"``，双击定位时直接解析，无需额外映射表。
        表格按时间正序增长（最新在最下方），只有当用户本来就停在底部时才自动
        跟随滚动——否则正在翻看历史告警的人会被不断跳走。
        """
        if not rows:
            return
        follower = self._tree_at_bottom(self.alerts)
        # 斑马纹的奇偶从插入前的行数起算；get_children 是 Tcl 往返，不能每插一行调一次
        parity = len(self.alerts.get_children())
        for packet_idx, alert in rows:
            self._alert_seq += 1
            iid = f"{packet_idx}:{self._alert_seq}"
            self._alert_by_row[iid] = alert
            self.alerts.insert(
                "",
                tk.END,
                iid=iid,
                values=alert_row(alert),
                tags=(severity_key(alert), "even" if parity % 2 else "odd"),
            )
            parity += 1
        if follower:
            last = self.alerts.get_children()
            if last:
                self.alerts.see(last[-1])
        self._trim_alerts()
        self._update_alert_tab_label()
        self._update_control_states()

    @staticmethod
    def _tree_at_bottom(tree: ttk.Treeview) -> bool:
        try:
            return tree.yview()[1] >= 0.999
        except tk.TclError:
            return True

    def _update_alert_tab_label(self) -> None:
        self._set_alert_tab_label(self._real_alert_count())

    def _set_alert_tab_label(self, count: int) -> None:
        """告警标签页标题带实时计数（0 时不显示括号）。"""
        if self._bottom_tabs is None:
            return
        with suppress(tk.TclError):
            self._bottom_tabs.tab(self._alert_tab_index, text=f"告警（{count}）" if count else "告警")

    def _set_issue_tab_label(self, count: int) -> None:
        if self._bottom_tabs is None:
            return
        with suppress(tk.TclError):
            self._bottom_tabs.tab(self._issue_tab_index, text=f"解析问题（{count}）" if count else "解析问题")

    def _sort_alerts(self, col: str) -> None:
        """告警表按列排序；时间与级别按语义排序而非字典序。"""
        if col == self._alert_sort_column:
            self._alert_sort_descending = not self._alert_sort_descending
        else:
            self._alert_sort_column = col
            self._alert_sort_descending = False
        reverse = self._alert_sort_descending
        rows = list(self.alerts.get_children(""))

        def key(iid: str) -> tuple[int, object]:
            alert = self._alert_by_row.get(iid)
            if alert is None:
                return (0, "")
            if col == "time":
                return (0, alert.timestamp)
            if col == "severity":
                return (0, {"high": 2, "medium": 1, "low": 0}[severity_key(alert)])
            return (0, str(self.alerts.set(iid, col)))

        rows.sort(key=key, reverse=reverse)
        for index, iid in enumerate(rows):
            self.alerts.move(iid, "", index)
        self._update_alert_sort_indicator()

    def _update_alert_sort_indicator(self) -> None:
        base = {"time": "时间", "severity": "级别", "source": "来源", "msg": "告警信息", "tuple": "五元组"}
        for col, text in base.items():
            if col == self._alert_sort_column:
                text += " ▼" if self._alert_sort_descending else " ▲"
            with suppress(tk.TclError):
                self.alerts.heading(col, text=text)

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

    def _insert_packet(self, idx: int, packet: PacketInfo) -> None:
        tags = ["even" if idx % 2 == 0 else "odd", packet.protocol.lower()]
        if packet.issues:
            tags.append("issue")
        self.table.insert("", 0, iid=str(idx), tags=tuple(tags), values=packet_row(packet))

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
        extra = len(self.alerts.get_children()) - MAX_ALERT_ROWS
        if extra > 0:
            rows = self.alerts.get_children()
            for iid in rows[:extra]:
                self._alert_by_row.pop(iid, None)
            self.alerts.delete(*rows[:extra])
            self._log(f"告警已裁剪 {extra} 条")

    def _drop_oldest_events(self, trim_count: int) -> None:
        """裁剪最旧的 trim_count 个事件，并同步清理表格行与各类索引。

        表格中对应被裁事件的行必须一并删除，否则它们成为永远选不中的孤儿行，
        会使 Treeview 行数突破 MAX_TABLE_ROWS 持续增长。
        """
        old_offset = self.event_offset
        del self.events[:trim_count]
        self.event_offset += trim_count
        self.filtered = [idx for idx in self.filtered if idx >= self.event_offset]
        if self._refilter_queue:
            self._refilter_queue = [idx for idx in self._refilter_queue if idx >= self.event_offset]
        rows_set = set(self.table.get_children())
        orphan_iids = [str(idx) for idx in range(old_offset, self.event_offset) if str(idx) in rows_set]
        if orphan_iids:
            self.table.delete(*orphan_iids)

    def _show_selected(self) -> None:
        selected = self.table.selection()
        if not selected:
            return
        try:
            idx = int(selected[0])
        except ValueError:
            return
        event = self._event_at(idx)
        if event is None:
            return
        packet = event.packet
        self._fill_detail_tree(packet)
        self._fill_hex_view(packet)

    def _fill_detail_tree(self, packet: PacketInfo) -> None:
        """把协议解析树写进详情面板，顶层分组默认展开。"""
        self._clear_detail_tree()
        counter = 0

        def add(nodes: list[DetailNode], parent: str, depth: int) -> None:
            nonlocal counter
            for node in nodes:
                counter += 1
                iid = f"n{counter}"
                self._detail_nodes[iid] = node
                self.detail.insert(
                    parent,
                    tk.END,
                    iid=iid,
                    text=f"  {node.label}",
                    values=(node.value,),
                    tags=(node.kind,),
                    # 只展开前两层：深层协议头默认收起，避免一次铺满整个面板
                    open=depth < 2,
                )
                if node.children:
                    add(node.children, iid, depth + 1)

        add(build_detail_tree(packet), "", 0)

    def _fill_hex_view(self, packet: PacketInfo) -> None:
        """十六进制视图：偏移 / 字节 / ASCII 三段分色，超大帧截断显示。"""
        self.hex_view.configure(state=tk.NORMAL)
        self.hex_view.delete("1.0", tk.END)
        if not packet.raw:
            self.hex_view.insert(tk.END, "该数据包没有捕获到原始字节。\n")
            self.hex_view.configure(state=tk.DISABLED)
            return
        rows = hex_rows(packet.raw[:MAX_HEX_BYTES])
        for offset, hex_text, ascii_text in rows:
            self.hex_view.insert(tk.END, f"{offset}  ", "offset")
            self.hex_view.insert(tk.END, f"{hex_text:<48}  ", "bytes")
            self.hex_view.insert(tk.END, f"{ascii_text}\n", "ascii")
        if len(packet.raw) > MAX_HEX_BYTES:
            self.hex_view.insert(
                tk.END,
                f"\n…… 仅显示前 {MAX_HEX_BYTES} 字节，共 {len(packet.raw)} 字节。\n",
                "offset",
            )
        self.hex_view.configure(state=tk.DISABLED)

    def _event_at(self, idx: int) -> PacketEvent | None:
        local_idx = idx - self.event_offset
        if local_idx < 0 or local_idx >= len(self.events):
            return None
        return self.events[local_idx]

    def _focus_packet_row(self, packet_idx: int) -> None:
        iid = str(packet_idx)
        if iid not in self.table.get_children():
            return
        self.table.selection_set(iid)
        self.table.see(iid)
        self.table.focus(iid)
        self._show_selected()

    def _jump_to_alert_packet(self) -> None:
        selection = self.alerts.selection()
        if not selection:
            return
        # 行 iid 形如 "{packet_idx}:{seq}"，直接解析出目标数据包，无需额外映射表
        try:
            packet_idx = int(selection[0].split(":", 1)[0])
        except ValueError:
            return
        self._focus_packet_row(packet_idx)

    def _jump_to_error_packet(self) -> None:
        selection = self.error_list.selection()
        if not selection:
            return
        try:
            packet_idx = int(selection[0].split(":", 1)[0])
        except ValueError:
            return
        self._focus_packet_row(packet_idx)

    def _debounced_refilter(self) -> None:
        if self._filter_after_id is not None:
            self.after_cancel(self._filter_after_id)
        self._filter_after_id = self.after(300, self._refilter)

    def _refilter(self) -> None:
        if self._filter_after_id is not None:
            with suppress(tk.TclError):
                self.after_cancel(self._filter_after_id)
        self._filter_after_id = None
        if self._refilter_after_id is not None:
            with suppress(tk.TclError):
                self.after_cancel(self._refilter_after_id)
            self._refilter_after_id = None
        self.table.delete(*self.table.get_children())
        self.filtered.clear()
        self._refilter_queue = [
            self.event_offset + local_idx
            for local_idx in range(max(0, len(self.events) - MAX_TABLE_ROWS), len(self.events))
        ]
        self._refilter_cursor = 0
        self._refilter_step()

    def _refilter_step(self) -> None:
        """分批插入匹配行，避免一次性重建数千行导致界面卡顿。"""
        needle = self.display_filter.get().strip().lower()
        processed = 0
        total = len(getattr(self, "_refilter_queue", []))
        while self._refilter_cursor < total and processed < REFILTER_BATCH:
            real_idx = self._refilter_queue[self._refilter_cursor]
            self._refilter_cursor += 1
            processed += 1
            local_idx = real_idx - self.event_offset
            if local_idx < 0 or local_idx >= len(self.events):
                continue
            event = self.events[local_idx]
            if not needle or needle in _search_text(event.packet):
                self.filtered.append(real_idx)
                self._insert_packet(real_idx, event.packet)
        if self._refilter_cursor < total:
            self._refilter_after_id = self.after(1, self._refilter_step)
        else:
            self._refilter_after_id = None
            self._update_packet_count()
            if self._sort_column:
                self._sort(self._sort_column, toggle=False)

    def _sort(self, col: str, *, toggle: bool = True) -> None:
        """按列排序；时间与长度取底层数值，其余按显示文本。

        时间列显示的是 ``HH:MM:SS.mmm``，直接对字符串排序会得到字典序而不是
        时间序；这里回查事件对象拿原始时间戳，跨天回放也不会排错。
        """
        if toggle and col == self._sort_column:
            self._sort_descending = not self._sort_descending
        elif toggle:
            self._sort_descending = False
        self._sort_column = col

        def key(iid: str) -> tuple[int, Any]:
            event = self._event_at(int(iid)) if iid.isdigit() else None
            if event is not None:
                if col == "time":
                    return (0, event.packet.timestamp)
                if col == "len":
                    return (0, event.packet.length)
            return (1, self.table.set(iid, col))

        rows = sorted(self.table.get_children(""), key=key, reverse=self._sort_descending)
        for index, iid in enumerate(rows):
            self.table.move(iid, "", index)
        self._update_sort_indicator()
        self._schedule_config_save()

    def _reset_stats_display(self) -> None:
        """清空统计页与 KPI 卡回到零值（清空数据时调用）。"""
        for card in self._stat_cards.values():
            card.set_value("0")
            card.clear()
        for key in ("total_bytes", "total_packets", "dropped", "parse_errors"):
            label = self._stats_cells.get(key)
            if label is not None:
                label.configure(text="0")
        for _track, fill, count in self._proto_bars.values():
            fill.place_configure(relwidth=0.0)
            count.configure(text="0")
        self.error_list.delete(*self.error_list.get_children())
        self.error_summary_var.set("解析问题 0 · 致命异常 0")
        # 标签页计数与摘要同步归零，不依赖下一轮 _refresh_errors
        self._set_issue_tab_label(0)

    def _refresh_stats(self) -> None:
        status = self.pipeline.status()
        alert_count = self._real_alert_count()
        self._stat_cards["packets"].set_value(f"{status.total_packets:,}")
        self._stat_cards["packets"].push_sample(status.total_packets)
        self._stat_cards["rate"].set_value(f"{status.packets_per_second:,.1f}", unit="包/秒")
        self._stat_cards["rate"].push_sample(status.packets_per_second)
        self._stat_cards["bytes_rate"].set_value(_compact_bytes(status.bytes_per_second), unit="字节/秒")
        self._stat_cards["bytes_rate"].push_sample(status.bytes_per_second)
        self._stat_cards["sessions"].set_value(f"{status.active_sessions:,}")
        self._stat_cards["sessions"].push_sample(status.active_sessions)
        self._stat_cards["alerts"].set_value(f"{alert_count:,}")
        self._stat_cards["alerts"].push_sample(alert_count)

        if self._drop_hint is not None:
            self._drop_hint.configure(text=f"丢弃 {status.dropped_packets:,} · 解析异常 {status.parse_errors:,}")

        self._stats_cells["total_bytes"].configure(text=_compact_bytes(status.total_bytes))
        self._stats_cells["total_packets"].configure(text=f"{status.total_packets:,}")
        self._stats_cells["dropped"].configure(text=f"{status.dropped_packets:,}")
        self._stats_cells["parse_errors"].configure(text=f"{status.parse_errors:,}")

        total = sum(status.protocol_counts.values()) or 1
        for proto, (_track, fill, count) in self._proto_bars.items():
            value = status.protocol_counts.get(proto, 0)
            count.configure(text=f"{value:,}")
            fill.place_configure(relwidth=min(1.0, value / total))
        self._refresh_errors(status)

    def _refresh_errors(self, status: PipelineStatus | None = None) -> None:
        if status is None:
            status = self.pipeline.status()
        dropped = status.dropped_packets
        parse_errs = status.parse_errors
        issue_count = 0
        recent_issues: list[tuple[str, str, str, str, int]] = []
        # 从最新事件向旧事件遍历，收集最多 50 条异常及对应包索引
        start = max(0, len(self.events) - 300)
        for local_idx in range(len(self.events) - 1, start - 1, -1):
            event = self.events[local_idx]
            packet = event.packet
            if not packet.issues:
                continue
            issue_count += 1
            if len(recent_issues) >= 50:
                continue
            global_idx = self.event_offset + local_idx
            endpoint = (
                f"{format_endpoint(packet.src, packet.src_port)} → {format_endpoint(packet.dst, packet.dst_port)}"
            )
            for issue in reversed(packet.issues):
                if len(recent_issues) >= 50:
                    break
                recent_issues.append((f"{packet.timestamp:.3f}", issue.layer, issue.message, endpoint, global_idx))
        # 变更检测 + 节流：最多每 2 秒重建一次表格
        new_state = (dropped, parse_errs, issue_count, repr(recent_issues[:50]))
        now = time.monotonic()
        if new_state == self._last_error_state and now - self._last_error_refresh < 2.0:
            return
        self._last_error_state = new_state
        self._last_error_refresh = now
        parts = [f"解析问题 {issue_count}"]
        if dropped:
            parts.append(f"队列丢弃 {dropped}")
        parts.append(f"致命异常 {parse_errs}")
        self.error_summary_var.set(" · ".join(parts))
        self.error_list.delete(*self.error_list.get_children())
        for seq, (stamp, layer, message, endpoint, global_idx) in enumerate(recent_issues):
            self.error_list.insert(
                "",
                tk.END,
                iid=f"{global_idx}:{seq}",
                values=(stamp, layer, message, endpoint),
                tags=("problem", "even" if seq % 2 else "odd"),
            )
        self._set_issue_tab_label(issue_count)
        if self._error_badge is not None:
            self._error_badge.configure(text=f"解析异常 {parse_errs}" if parse_errs else "")

    def _export_alerts(self) -> None:
        if self._real_alert_count() == 0:
            messagebox.showinfo("导出告警", "当前没有可导出的 IDS 告警。", parent=self)
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON 告警", "*.json"), ("日志", "*.log"), ("文本", "*.txt")],
            parent=self,
        )
        if not path:
            return
        is_json = path.lower().endswith(".json")
        # 在主线程快照数据，后台只做文件写入，避免触碰 Tk 控件。
        # 两种格式都从同一份快照（self.events 里的全部告警）导出：改从告警表取
        # 文本行会让 JSON 与文本的条数不一致（表格有 MAX_ALERT_ROWS 上限，
        # 而且被裁剪/排序过的行并不等于全部告警）。
        alerts = [alert for event in self.events for alert in event.alerts]
        records = [alert.to_dict() for alert in alerts]
        lines = [alert_detail_text(alert).replace("\n", " · ") for alert in alerts]

        def work() -> int:
            with open(path, "w", encoding="utf-8") as handle:
                if is_json:
                    for record in records:
                        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                    return len(records)
                for item in lines:
                    handle.write(item + "\n")
                return len(lines)

        def done(count: int) -> None:
            self._log(f"已导出 {count} 条告警到 {path}")

        self._run_in_background(work, done, "正在导出告警…", "导出错误")

    def destroy(self) -> None:
        self._destroyed = True
        # 退出清理：pipeline.stop / 图标栈关闭失败不应阻止窗口销毁
        with suppress(Exception):
            self.pipeline.stop()
        self.capturing = False
        with suppress(Exception):
            self._icon_stack.close()
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
        center_on_parent(self, parent, 840, 520, 700, 440)
        self._suggestions = suggestions
        self._on_apply = on_apply
        self._parent = parent
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
            selectforeground=colors["select_text"],
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
            selectforeground=colors["select_text"],
            highlightbackground=colors["border"],
            highlightcolor=colors["accent"],
            relief=tk.FLAT,
        )
        self.detail.grid(row=1, column=0, columnspan=2, sticky=tk.NSEW, pady=(8, 0))

        actions = ttk.Frame(self, padding=(8, 0, 8, 8))
        actions.grid(row=1, column=0, sticky=tk.EW)
        actions.columnconfigure(0, weight=1)
        ttk.Button(actions, text="采用选中规则", style="Accent.TButton", command=self._apply).grid(
            row=0, column=1, padx=(0, 6)
        )
        ttk.Button(actions, text="取消", style="Secondary.TButton", command=self.destroy).grid(row=0, column=2)

        for suggestion in suggestions:
            self.listbox.insert(tk.END, f"{suggestion.title}  命中 {suggestion.match_count} 个已捕获包")
        self.listbox.selection_set(0)
        self.listbox.bind("<<ListboxSelect>>", lambda _: self._refresh_detail())
        self._refresh_detail()
        bind_dialog_keys(self, self.destroy, self._apply)
        wire_dialog_theme(self, parent, [self.listbox, self.detail])

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
        center_on_parent(self, parent, 820, 480, 680, 400)
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
            selectforeground=colors["select_text"],
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
            selectforeground=colors["select_text"],
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
            ttk.Entry(value_row, textvariable=self._value_var, style="Filter.TEntry").grid(
                row=0, column=1, sticky=tk.EW
            )

        actions = ttk.Frame(self, padding=(8, 0, 8, 8))
        actions.grid(row=1, column=0, sticky=tk.EW)
        actions.columnconfigure(0, weight=1)
        ttk.Button(actions, text="采用选中项", style="Accent.TButton", command=self._apply).grid(
            row=0, column=1, padx=(0, 6)
        )
        ttk.Button(actions, text="取消", style="Secondary.TButton", command=self.destroy).grid(row=0, column=2)

        for template in templates:
            self.listbox.insert(tk.END, template.title)
        self.listbox.selection_set(0)
        self.listbox.bind("<<ListboxSelect>>", lambda _: self._refresh_detail())
        self.listbox.bind("<Double-Button-1>", lambda _: self._apply())
        self._refresh_detail()
        bind_dialog_keys(self, self.destroy, self._apply)
        wire_dialog_theme(self, parent, [self.listbox, self.detail])

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
        center_on_parent(self, parent, 860, 680, 700, 560)
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
        self._capture_warning = tk.Label(
            self,
            text="⚠ 请先在主窗口点击「开始」启动抓包，再使用自动发包",
            font=parent._theme.font_small,
            fg=colors["warning"],
            bg=colors["bg"],
            anchor=tk.W,
            pady=4,
            padx=8,
        )
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
        ttk.Radiobutton(mode_frame, text="全部", variable=self._mode_var, value="all", command=self._filter_list).pack(
            side=tk.LEFT, padx=(0, 4)
        )
        ttk.Radiobutton(
            mode_frame, text="正常包", variable=self._mode_var, value="normal", command=self._filter_list
        ).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Radiobutton(
            mode_frame, text="异常包", variable=self._mode_var, value="abnormal", command=self._filter_list
        ).pack(side=tk.LEFT)

        # 模板列表
        list_frame = ttk.Frame(self, padding=(8, 4))
        list_frame.grid(row=2, column=0, sticky=tk.NSEW)
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        self._listbox = tk.Listbox(list_frame, selectmode=tk.BROWSE, height=14)
        self._listbox.configure(
            background=colors["field"],
            foreground=colors["text"],
            selectbackground=colors["select"],
            selectforeground=colors["select_text"],
            highlightbackground=colors["border"],
            highlightcolor=colors["accent"],
        )
        self._listbox.grid(row=0, column=0, sticky=tk.NSEW)
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self._listbox.yview)
        self._listbox.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky=tk.NS)

        # 快捷操作行
        quick_bar = ttk.Frame(self, padding=(8, 4, 8, 0))
        quick_bar.grid(row=3, column=0, sticky=tk.EW)
        ttk.Button(quick_bar, text="全选", style="Secondary.TButton", command=self._select_all).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Button(quick_bar, text="取消全选", style="Secondary.TButton", command=self._deselect_all).pack(side=tk.LEFT)
        self._desc_var = tk.StringVar()
        ttk.Label(quick_bar, textvariable=self._desc_var, style="Muted.TLabel", anchor=tk.E, wraplength=400).pack(
            side=tk.RIGHT
        )

        # 操作按钮行
        action_bar = ttk.Frame(self, padding=(8, 8, 8, 8))
        action_bar.grid(row=4, column=0, sticky=tk.EW)
        self._gen_status_var = tk.StringVar(value="就绪 — 勾选模板后点击开始，每 0.5 秒轮询发送")
        ttk.Label(action_bar, textvariable=self._gen_status_var, style="Status.TLabel").pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        self._toggle_btn = ttk.Button(action_bar, text="开始发包", style="Accent.TButton", command=self._toggle)
        self._toggle_btn.pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(action_bar, text="手动发一次", style="Secondary.TButton", command=self._send_once).pack(
            side=tk.RIGHT
        )

        self._populate_list()
        self._update_select_label()
        self._listbox.bind("<<ListboxSelect>>", lambda _: self._on_selection_change())
        self._listbox.bind("<ButtonRelease-1>", self._toggle_clicked_template)
        self._listbox.bind("<space>", self._toggle_focused_template)
        self._listbox.bind("<Return>", self._toggle_focused_template)
        self._listbox.bind("<Escape>", lambda _e: self._on_close())
        # _capture_warning 是警示条（固定黄底），不交给主题统一换色，避免主题切换后丢失警示样式
        wire_dialog_theme(self, parent, [self._listbox])
        self._schedule(200, self._check_capture_state)

    def _schedule(self, delay_ms: int, callback: Callable[[], None]) -> None:
        """调度回调并登记 id，已触发的 id 随即移出列表，避免 _after_ids 只增不减。"""
        after_ids = self._after_ids

        def wrapped() -> None:
            with suppress(ValueError):
                after_ids.remove(aid)
            callback()

        aid = self.after(delay_ms, wrapped)
        after_ids.append(aid)

    def _on_close(self) -> None:
        if self._generator.running:
            self._parent._log("测试发包：窗口关闭，已自动停止发包")
        self._generator.stop()
        for aid in self._after_ids:
            # after 句柄可能已触发/失效，取消失败可忽略
            with suppress(Exception):
                self.after_cancel(aid)
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

    def _toggle_clicked_template(self, event: tk.Event) -> None:
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

    def _toggle_focused_template(self, _event: tk.Event | None = None) -> str:
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
                self._gen_status_var.set("已停止 — 期间每 0.5 秒轮发一组模板")
            self._check_capture_state()
            return
        self._schedule(1000, self._poll_status)

    def destroy(self) -> None:
        self._generator.stop()
        for aid in self._after_ids:
            # after 句柄可能已触发/失效，取消失败可忽略
            with suppress(Exception):
                self.after_cancel(aid)
        self._after_ids.clear()
        super().destroy()


class SubnetScanDialog(tk.Toplevel):
    def __init__(
        self,
        parent: NetGuardApp,
        device_display: DeviceDisplay,
        all_displays: list[DeviceDisplay],
        bpf_var: tk.StringVar,
        on_switch_device: Callable[[str], None] | None = None,
        on_add_bpf_template: Callable[[str, str, str], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.title("网段扫描与管理")
        self.transient(parent)
        self.grab_set()
        center_on_parent(self, parent, 820, 700, 680, 560)
        self._parent = parent
        self._bpf_var = bpf_var
        self._on_switch_device = on_switch_device
        self._on_add_bpf_template = on_add_bpf_template
        self._current_display = device_display
        self._all_displays = all_displays
        self._displays_with_ip = [d for d in all_displays if d.ip_addresses]
        self._subnets = extract_subnets(device_display.ip_addresses, device_display.device.netmasks)
        if not self._subnets:
            self._subnets = detect_subnet_os_fallback(
                device_display.device.name,
                _device_match_aliases(device_display),
            )
        self._alive_hosts: list[str] = []
        self._host_infos: dict[str, HostInfo] = {}
        self._scanning = False
        self._resolving = False
        # 扫描与解析各用独立的取消事件：共享一个会互相取消/互相抹掉取消标志
        self._scan_cancel = threading.Event()
        self._resolve_cancel = threading.Event()
        # 工作线程只往队列投递事件，由主线程轮询消费——绝不在子线程调用 Tk
        # （winfo_exists/after 在非 mainloop 线程下依赖 _tkinter 私有 marshaling）
        self._event_queue: queue.Queue[tuple[str, tuple[Any, ...]]] = queue.Queue()
        self.after(80, self._drain_events)
        colors = build_colors(parent.dark_mode.get())
        self.configure(background=colors["bg"])
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        sw_frame = ttk.Frame(self, padding=(8, 8, 8, 0))
        sw_frame.grid(row=0, column=0, sticky=tk.EW)
        ttk.Label(sw_frame, text="网卡", style="Muted.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        self._device_var = tk.StringVar(value=device_display.display_name)
        device_names = (
            [d.display_name for d in self._displays_with_ip]
            if self._displays_with_ip
            else [device_display.display_name]
        )
        self._device_box = ttk.Combobox(
            sw_frame, textvariable=self._device_var, values=device_names, width=40, state="readonly"
        )
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
        ttk.Label(
            info_frame, textvariable=self._info_var, style="Muted.TLabel", wraplength=650, anchor=tk.W, justify=tk.LEFT
        ).pack(fill=tk.X)

        manual_row = ttk.Frame(info_frame)
        manual_row.pack(fill=tk.X, pady=(6, 0))
        ttk.Label(manual_row, text="手动网段:", style="Muted.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        self._manual_cidr = tk.StringVar()
        ttk.Entry(manual_row, textvariable=self._manual_cidr, width=22, style="Filter.TEntry").pack(
            side=tk.LEFT, padx=(0, 6)
        )
        presets = ["192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24", "10.0.1.0/24"]
        self._preset_var = tk.StringVar(value="常用网段")
        preset_box = ttk.Combobox(manual_row, textvariable=self._preset_var, values=presets, width=16, state="readonly")
        preset_box.pack(side=tk.LEFT, padx=(0, 6))
        preset_box.bind("<<ComboboxSelected>>", lambda _: self._manual_cidr.set(self._preset_var.get()))
        ttk.Button(manual_row, text="应用", width=6, style="Accent.TButton", command=self._apply_manual_subnet).pack(
            side=tk.LEFT
        )

        ctrl_frame = ttk.Frame(self, padding=(8, 4))
        ctrl_frame.grid(row=2, column=0, sticky=tk.EW)
        self._scan_btn = ttk.Button(ctrl_frame, text="开始扫描", style="Accent.TButton", command=self._toggle_scan)
        self._scan_btn.pack(side=tk.LEFT)
        if not self._subnets:
            self._scan_btn.configure(state=tk.DISABLED)
        self._status_var = tk.StringVar(value="就绪" if self._subnets else self._no_ipv4_status())
        ttk.Label(ctrl_frame, textvariable=self._status_var, style="Status.TLabel", anchor=tk.W).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0)
        )

        list_frame = ttk.Frame(self, padding=(8, 4))
        list_frame.grid(row=3, column=0, sticky=tk.EW)
        ttk.Label(list_frame, text="活跃主机", style="FilterLabel.TLabel").pack(anchor=tk.W)
        detail_list = ttk.Frame(self, padding=(8, 4))
        detail_list.grid(row=4, column=0, sticky=tk.NSEW)
        detail_list.rowconfigure(0, weight=1)
        detail_list.columnconfigure(0, weight=1)
        self._host_list = tk.Listbox(detail_list, selectmode=tk.EXTENDED, height=10)
        self._host_list.configure(
            background=colors["field"],
            foreground=colors["text"],
            selectbackground=colors["select"],
            selectforeground=colors["select_text"],
            highlightbackground=colors["border"],
            highlightcolor=colors["accent"],
        )
        self._host_list.grid(row=0, column=0, sticky=tk.NSEW)
        host_scroll = ttk.Scrollbar(detail_list, orient=tk.VERTICAL, command=self._host_list.yview)
        self._host_list.configure(yscrollcommand=host_scroll.set)
        host_scroll.grid(row=0, column=1, sticky=tk.NS)
        self._host_list.bind("<<ListboxSelect>>", lambda _: self._on_host_select())

        self._detail_text = tk.Text(detail_list, height=6, wrap=tk.WORD)
        self._detail_text.configure(
            background=colors["field"],
            foreground=colors["text"],
            insertbackground=colors["text"],
            relief=tk.FLAT,
            highlightbackground=colors["border"],
            highlightcolor=colors["accent"],
        )
        self._detail_text.grid(row=1, column=0, columnspan=2, sticky=tk.NSEW, pady=(8, 0))
        self._detail_text.insert("1.0", "选择主机后可查看详情；点击下方按钮发送 Ping 验证连通性。")

        action_bar = ttk.Frame(self, padding=(8, 8))
        action_bar.grid(row=5, column=0, sticky=tk.EW)
        self._resolve_btn = ttk.Button(
            action_bar, text="解析主机名", style="Secondary.TButton", command=self._toggle_resolve
        )
        self._resolve_btn.pack(side=tk.LEFT)
        self._resolve_btn.configure(state=tk.DISABLED)
        self._ping_btn = ttk.Button(
            action_bar, text="Ping 选中", style="Secondary.TButton", command=self._ping_selected
        )
        self._ping_btn.pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(action_bar, text="保存为 BPF 模板", style="Secondary.TButton", command=self._save_as_template).pack(
            side=tk.LEFT, padx=(6, 0)
        )
        ttk.Button(action_bar, text="应用过滤", style="Accent.TButton", command=self._apply_subnet_filter).pack(
            side=tk.LEFT, padx=(6, 0)
        )
        ttk.Button(action_bar, text="取消", style="Secondary.TButton", command=self.destroy).pack(side=tk.RIGHT)
        self.bind("<Escape>", lambda _e: self._on_close())
        wire_dialog_theme(self, parent, [self._host_list, self._detail_text])

    def _post_event(self, name: str, *args: Any) -> None:
        """工作线程调用：只投递事件，绝不直接触碰 Tk。"""
        self._event_queue.put((name, args))

    def _drain_events(self) -> None:
        """主线程轮询消费工作线程事件；对话框销毁后轮询链自然终止。"""
        try:
            while True:
                name, args = self._event_queue.get_nowait()
                handler = getattr(self, f"_ev_{name}", None)
                if handler is None:
                    continue
                try:
                    handler(*args)
                except tk.TclError:
                    return
                except Exception:
                    logger.exception("处理网段扫描事件失败：%s", name)
        except queue.Empty:
            pass
        try:
            self.after(80, self._drain_events)
        except tk.TclError:
            return

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
        self._subnets = extract_subnets(display.ip_addresses, display.device.netmasks)
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
            messagebox.showwarning(
                "手动网段", f"无效的 CIDR 格式：{cidr}\n\n请输入如 192.168.1.0/24 的格式。", parent=self
            )
            return
        # 大小校验必须在任何展开之前：list(net.hosts()) 物化 /8 会构造
        # 1677 万个对象（GB 级内存、主线程冻结数十秒）
        if net.num_addresses > MAX_SWEEP_HOSTS:
            messagebox.showwarning(
                "手动网段",
                f"网段过大（{net.num_addresses} 个地址，上限 {MAX_SWEEP_HOSTS}）。\n\n请使用 /21 或更小前缀的网段。",
                parent=self,
            )
            return
        if net.prefixlen >= 31:
            total = net.num_addresses
        else:
            total = net.num_addresses - 2  # 去网络地址与广播地址
        gw = str(net.network_address + 1) if net.prefixlen <= 30 else str(net.network_address)
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
            self._scan_cancel.set()
            return
        if not self._subnets:
            return
        self._scanning = True
        self._scan_cancel.clear()
        self._scan_btn.configure(text="停止扫描", style="Danger.TButton")
        # 扫描与解析互斥：并发运行会争用状态栏与主机列表
        self._resolve_btn.configure(state=tk.DISABLED)
        self._status_var.set("正在扫描...")
        self._host_list.delete(0, tk.END)
        self._alive_hosts.clear()

        subnet = self._subnets[0]
        thread = threading.Thread(target=self._run_sweep, args=(subnet,), name="netguard-sweep", daemon=True)
        thread.start()

    def _run_sweep(self, subnet: SubnetInfo) -> None:
        def on_progress(completed: int, total: int, last_ip: str) -> None:
            self._post_event("sweep_progress", completed, total, last_ip)

        hosts = ping_sweep(
            subnet, max_workers=100, timeout=0.8, on_progress=on_progress, cancel_event=self._scan_cancel
        )
        self._post_event("sweep_done", hosts)

    def _ev_sweep_progress(self, completed: int, total: int, last_ip: str) -> None:
        self._status_var.set(f"扫描中 {completed}/{total} — {last_ip}")

    def _ev_sweep_done(self, hosts: list[str]) -> None:
        self._scanning = False
        self._scan_btn.configure(text="重新扫描", style="Accent.TButton")
        if self._subnets:
            self._scan_btn.configure(state=tk.NORMAL)
        self._alive_hosts = hosts
        if not hosts:
            self._status_var.set("扫描完成 — 未发现活跃主机")
            return
        self._status_var.set(f"扫描完成 — 发现 {len(hosts)} 台活跃主机")
        if not self._resolving:
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
            self._post_event("ping_progress", results[:])
        self._post_event("ping_done", results)

    def _ev_ping_progress(self, results: list[tuple[str, bool]]) -> None:
        lines = [f"Ping 进度 ({len(results)} 台):"]
        for ip, ok in results:
            status = "通" if ok else "不通"
            lines.append(f"  {ip} — {status}")
        self._detail_text.delete("1.0", tk.END)
        self._detail_text.insert("1.0", "\n".join(lines))

    def _ev_ping_done(self, results: list[tuple[str, bool]]) -> None:
        ok_count = sum(1 for _, ok in results if ok)
        self._status_var.set(f"Ping 完成 — {ok_count}/{len(results)} 通")
        self._ping_btn.configure(state=tk.NORMAL)

    def _toggle_resolve(self) -> None:
        if self._resolving:
            self._resolve_cancel.set()
            return
        if not self._alive_hosts:
            return
        self._resolving = True
        self._resolve_cancel.clear()
        self._scan_btn.configure(state=tk.DISABLED)
        self._host_infos.clear()
        self._resolve_btn.configure(text="停止解析", style="Danger.TButton")
        self._status_var.set("正在解析主机名...")
        thread = threading.Thread(target=self._run_resolve, name="netguard-resolve", daemon=True)
        thread.start()

    def _run_resolve(self) -> None:
        def on_progress(completed: int, total: int, last_ip: str) -> None:
            self._post_event("resolve_progress", completed, total, last_ip)

        infos = resolve_hosts(
            self._alive_hosts, max_workers=40, timeout=2.0, on_progress=on_progress, cancel_event=self._resolve_cancel
        )
        self._post_event("resolve_done", infos)

    def _ev_resolve_progress(self, completed: int, total: int, last_ip: str) -> None:
        self._status_var.set(f"解析中 {completed}/{total} — {last_ip}")

    def _ev_resolve_done(self, infos: dict[str, HostInfo]) -> None:
        self._resolving = False
        self._resolve_btn.configure(text="重新解析", style="Secondary.TButton")
        if self._subnets:
            self._scan_btn.configure(state=tk.NORMAL)
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
        self._scan_cancel.set()
        self._resolve_cancel.set()
        self.destroy()

    def destroy(self) -> None:
        self._scan_cancel.set()
        self._resolve_cancel.set()
        super().destroy()


def _enable_high_dpi() -> None:
    """在创建窗口前启用 Windows 高 DPI 感知，避免界面模糊/缩放异常。"""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # PROCESS_SYSTEM_DPI_AWARE
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        logger.debug("无法启用高 DPI 感知", exc_info=True)


def run_gui() -> None:
    _enable_high_dpi()
    app = NetGuardApp()
    try:
        scaling = app.winfo_fpixels("1i") / 72.0
        if scaling > 1.0:
            app.tk.call("tk", "scaling", scaling)
    except tk.TclError:
        pass
    try:
        app.lift()
        app.attributes("-topmost", True)
        app.after_idle(app.attributes, "-topmost", False)
    except tk.TclError:
        pass
    app.mainloop()
