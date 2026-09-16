"""NetGuard 视觉设计系统：颜色令牌、字体阶梯与 ttk 样式。

颜色分三层，避免各处硬编码十六进制：

1. 原始令牌（``canvas`` / ``surface`` / ``border`` / ``text`` …）——设计变量本身；
2. 语义令牌（``*_active`` / ``*_text`` …）——由原始令牌派生；
3. 兼容别名（``bg`` / ``toolbar`` / ``muted`` …）——早期版本的颜色键，
   对话框与历史代码仍在引用，保留以免破坏调用方。

``build_colors()`` 返回的表同时包含全部三层。新代码请使用原始令牌。
"""

from __future__ import annotations

import logging
import platform
import subprocess
import sys
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk
from typing import Any, cast

logger = logging.getLogger(__name__)


def _pick_font(available: set[str], candidates: list[str]) -> str:
    for name in candidates:
        if name in available:
            return name
    return "TkDefaultFont"


def resolve_fonts() -> tuple[str, str]:
    """Return (cjk_family, mono_family) for the current platform."""
    available = set(tkfont.families())
    if sys.platform == "win32":
        cjk = _pick_font(available, ["Microsoft YaHei UI", "Microsoft YaHei", "SimHei", "SimSun", "FangSong", "KaiTi"])
        mono = _pick_font(available, ["Cascadia Mono", "Consolas", "Courier New", "Lucida Console"])
    elif sys.platform == "darwin":
        cjk = _pick_font(available, ["PingFang SC", "Heiti SC", "STHeiti"])
        mono = _pick_font(available, ["SF Mono", "Menlo", "Monaco"])
    else:
        cjk = _pick_font(available, ["Noto Sans CJK SC", "WenQuanYi Micro Hei", "WenQuanYi Zen Hei", "DejaVu Sans"])
        mono = _pick_font(available, ["DejaVu Sans Mono", "Liberation Mono", "Courier New", "monospace"])
    return cjk, mono


def _hex_to_rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def mix(base: str, other: str, weight: float) -> str:
    """把 ``other`` 按 ``weight``(0..1) 混入 ``base``，等价于 CSS 的 color-mix。

    用于生成悬停态、选中行底纹这类需要“同色系微调”的颜色，
    避免为每个派生状态再手写一个十六进制常量。
    """
    weight = min(1.0, max(0.0, weight))
    br, bg, bb = _hex_to_rgb(base)
    orr, og, ob = _hex_to_rgb(other)
    red = round(br + (orr - br) * weight)
    green = round(bg + (og - bg) * weight)
    blue = round(bb + (ob - bb) * weight)
    return f"#{red:02x}{green:02x}{blue:02x}"


#: 深色原始令牌
_DARK = {
    "canvas": "#0e1014",
    "surface": "#15181e",
    "surface_2": "#1b1f26",
    "surface_3": "#23272f",
    "border": "#262b34",
    "border_strong": "#333a45",
    "text": "#d5dae2",
    "text_dim": "#98a2b0",
    "text_faint": "#667085",
    "accent": "#3d7dff",
    "accent_active": "#5590ff",
    "accent_press": "#2f62cc",
    "success": "#3fb950",
    "warning": "#d29922",
    "danger": "#f85149",
    "danger_active": "#ff6b63",
    "info": "#58a6ff",
}

#: 浅色原始令牌
_LIGHT = {
    "canvas": "#f2f4f7",
    "surface": "#ffffff",
    "surface_2": "#f6f8fa",
    "surface_3": "#eaeef2",
    "border": "#d8dee4",
    "border_strong": "#c2ccd6",
    "text": "#1f2328",
    "text_dim": "#59636e",
    "text_faint": "#818b98",
    "accent": "#0969da",
    "accent_active": "#0a72e8",
    "accent_press": "#0550ae",
    "success": "#1a7f37",
    "warning": "#9a6700",
    "danger": "#cf222e",
    "danger_active": "#b81d29",
    "info": "#0550ae",
}


def build_colors(dark: bool) -> dict[str, str]:
    """返回完整颜色表：原始令牌 + 派生语义色 + 历史别名。"""
    base = dict(_DARK if dark else _LIGHT)
    colors: dict[str, str] = dict(base)

    # ---- 派生语义色 ----
    colors["on_accent"] = "#ffffff"
    colors["select"] = mix(base["surface"], base["accent"], 0.34 if dark else 0.22)
    colors["select_text"] = "#ffffff" if dark else base["text"]
    colors["hover"] = mix(base["surface_3"], base["text"], 0.08)
    colors["row_alt"] = mix(base["surface"], base["text"], 0.028)
    colors["row_issue"] = mix(base["surface"], base["danger"], 0.14 if dark else 0.10)
    colors["tint_accent"] = mix(base["surface"], base["accent"], 0.16)
    colors["tint_success"] = mix(base["surface"], base["success"], 0.16)
    colors["tint_warning"] = mix(base["surface"], base["warning"], 0.16)
    colors["tint_danger"] = mix(base["surface"], base["danger"], 0.16)

    # ---- 协议配色（参考 Wireshark 的可辨识度，但收敛到本调色板）----
    if dark:
        colors["proto_tcp"] = "#58a6ff"
        colors["proto_udp"] = "#3fb950"
        colors["proto_http"] = "#d29922"
        colors["proto_dns"] = "#bc8cff"
        colors["proto_icmp"] = "#f778ba"
    else:
        colors["proto_tcp"] = "#0969da"
        colors["proto_udp"] = "#1a7f37"
        colors["proto_http"] = "#9a6700"
        colors["proto_dns"] = "#8250df"
        colors["proto_icmp"] = "#bf3989"
    colors["proto_other"] = base["text_dim"]

    # ---- 历史别名：早期版本引用的键，对话框与旧代码仍在使用 ----
    colors.update(
        {
            "bg": base["canvas"],
            "toolbar": base["surface_2"],
            "filter": base["surface_2"],
            "summary": base["surface"],
            "panel": base["surface"],
            "panel_alt": base["surface_2"],
            "field": base["surface_2"],
            "field_alt": base["surface_3"],
            "muted": base["text_dim"],
            "accent_text": colors["on_accent"],
            "button": base["surface_3"],
            "button_active": colors["hover"],
            "focus": base["accent"],
        }
    )
    return colors


#: 抓包状态 → 颜色键（状态栏/状态胶囊共用）
STATUS_COLORS = {"capturing": "success", "paused": "warning", "idle": "muted"}

#: 告警关键字 → 严重度颜色键
_SEVERITY_HIGH = ("attack", "overflow", "injection", "exploit", "trojan", "malware", "flood", "scan", "brute", "spoof")
_SEVERITY_MEDIUM = ("suspicious", "policy", "anomaly", "attempt", "tunnel")

#: 结构化严重度 → 颜色令牌键
SEVERITY_COLORS = {"high": "danger", "medium": "warning", "low": "info"}

#: 协议名 → 颜色令牌键（数据包列表着色）
PROTOCOL_COLOR_KEYS = {
    "tcp": "proto_tcp",
    "udp": "proto_udp",
    "http": "proto_http",
    "dns": "proto_dns",
    "icmp": "proto_icmp",
}


def status_color(colors: dict[str, str], state: str) -> str:
    return colors[STATUS_COLORS.get(state, "muted")]


def severity_color(colors: dict[str, str], msg: str) -> str:
    """根据告警文本关键字返回严重度颜色。

    仅作为结构化严重度缺失时的回退，新代码请用 :func:`alert_color`。
    """
    lower = msg.lower()
    if any(key in lower for key in _SEVERITY_HIGH):
        return colors["danger"]
    if any(key in lower for key in _SEVERITY_MEDIUM):
        return colors["warning"]
    return colors["success"]


def protocol_color(colors: dict[str, str], protocol: str) -> str:
    return colors[PROTOCOL_COLOR_KEYS.get(protocol.lower(), "proto_other")]


def severity_key(alert: object) -> str:
    """把 Alert 归一化为 high/medium/low 三档。

    规则引擎与检测器都已经填好结构化 ``severity`` 字段，直接采信；
    未知取值（自定义检测器的 "critical" 之类）归入高档，其余按中档处理。
    """
    severity = getattr(alert, "severity", None)
    if isinstance(severity, str) and severity:
        lowered = severity.lower()
        if lowered in SEVERITY_COLORS:
            return lowered
        if lowered in ("critical", "severe"):
            return "high"
    return "medium"


#: 严重度 → 中文标签（告警表“级别”列）
SEVERITY_LABELS = {"high": "高", "medium": "中", "low": "低"}


def severity_label(key: str) -> str:
    return SEVERITY_LABELS.get(key, SEVERITY_LABELS["medium"])


def alert_color(colors: dict[str, str], alert: object) -> str:
    """Alert → 前景色。

    优先使用结构化 ``severity``；对象没有该字段时（历史对象、测试替身）
    才退回 :func:`severity_color` 的关键字匹配。
    """
    if isinstance(getattr(alert, "severity", None), str):
        return colors[SEVERITY_COLORS[severity_key(alert)]]
    return severity_color(colors, getattr(alert, "msg", "") or "")


def alert_source(alert: object) -> str:
    """告警来源标签：检测器名（anomaly）或规则命中（rule）。"""
    if getattr(alert, "kind", "rule") == "anomaly":
        return str(getattr(alert, "rule_id", None) or "检测器")
    return "IDS 规则"


def detect_system_dark() -> bool:
    """探测操作系统当前是否为深色外观；任何失败都回退浅色。"""
    system = platform.system().lower()
    try:
        if system == "windows":
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            ) as key:
                value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return int(value) == 0
        if system == "darwin":
            result = subprocess.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            return "dark" in result.stdout.lower()
        if system == "linux":
            result = subprocess.run(
                ["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            return "dark" in result.stdout.lower()
    except Exception:
        logger.debug("无法探测系统主题，回退浅色", exc_info=True)
    return False


def menu_colors(colors: dict[str, str]) -> dict[str, str]:
    return {
        "background": colors["panel"],
        "foreground": colors["text"],
        "activebackground": colors["accent"],
        "activeforeground": colors["accent_text"],
        "disabledforeground": colors["muted"],
    }


def apply_menu(menu: tk.Menu, colors: dict[str, str]) -> None:
    """tk.Menu 不参与 ttk 样式，需显式配置颜色（含级联子菜单）。"""
    try:
        menu.configure(**menu_colors(colors))
    except tk.TclError:
        return
    try:
        last = menu.index("end")
    except tk.TclError:
        return
    # index("end") 对空菜单返回 None，对单条目菜单返回 0，不能用电真值判断
    if last is None:
        return
    for index in range(last + 1):
        try:
            if menu.type(index) == "cascade":
                submenu_name = menu.entrycget(index, "menu")
                if submenu_name:
                    apply_menu(menu.nametowidget(submenu_name), colors)
        except tk.TclError:
            continue


def tag_tree(tree: ttk.Treeview, role: str, colors: dict[str, str]) -> None:
    """为 Treeview 注册行标签。

    ``packets`` 是数据包列表（协议着色 + 斑马纹），``alerts`` 是告警表
    （严重度着色），``detail`` 是协议解析树（层级着色）。
    """
    if role == "packets":
        tree.tag_configure("odd", background=colors["surface"])
        tree.tag_configure("even", background=colors["row_alt"])
        tree.tag_configure("issue", background=colors["row_issue"])
        for proto, key in PROTOCOL_COLOR_KEYS.items():
            tree.tag_configure(proto, foreground=colors[key])
        tree.tag_configure("other", foreground=colors["proto_other"])
    elif role == "alerts":
        tree.tag_configure("odd", background=colors["surface"])
        tree.tag_configure("even", background=colors["row_alt"])
        tree.tag_configure("high", foreground=colors["danger"])
        tree.tag_configure("medium", foreground=colors["warning"])
        tree.tag_configure("low", foreground=colors["info"])
    elif role == "detail":
        # Treeview 的 tag 作用于整行，无法给“字段名”和“值”分别上色。
        # 这里改用层级区分：分组行提亮、叶子行压暗，读起来层次反而更清楚。
        tree.tag_configure("group", foreground=colors["text"])
        tree.tag_configure("key", foreground=colors["text_dim"])
        tree.tag_configure("problem", foreground=colors["danger"])
        tree.tag_configure("issue_row", background=colors["row_issue"])
    elif role == "issues":
        tree.tag_configure("odd", background=colors["surface"])
        tree.tag_configure("even", background=colors["row_alt"])
        tree.tag_configure("problem", foreground=colors["danger"])


class ThemeManager:
    """集中管理字体阶梯与 ttk 样式；所有颜色都来自 :func:`build_colors`。"""

    def __init__(self, app: tk.Tk) -> None:
        self._app = app
        self._style = ttk.Style(app)
        self._font_body = tkfont.nametofont("TkDefaultFont")
        self._font_text = tkfont.nametofont("TkTextFont")
        self._font_mono = tkfont.nametofont("TkFixedFont")
        self._font_title = self._font_body.copy()
        self._font_heading = self._font_body.copy()
        self._font_small = self._font_body.copy()
        self._font_tiny = self._font_body.copy()
        self._font_mono_small = self._font_mono.copy()
        self._font_metric = self._font_mono.copy()
        cjk, mono = resolve_fonts()
        for font in (self._font_body, self._font_text):
            font.configure(family=cjk, size=11)
        self._font_title.configure(family=cjk, size=13, weight="bold")
        self._font_heading.configure(family=cjk, size=11, weight="bold")
        self._font_small.configure(family=cjk, size=10)
        self._font_tiny.configure(family=cjk, size=9)
        self._font_mono.configure(family=mono, size=11)
        self._font_mono_small.configure(family=mono, size=10)
        self._font_metric.configure(family=mono, size=17, weight="bold")

    # -- 字体阶梯 ---------------------------------------------------------
    @property
    def font_body(self) -> tkfont.Font:
        return self._font_body

    @property
    def font_text(self) -> tkfont.Font:
        return self._font_text

    @property
    def font_mono(self) -> tkfont.Font:
        return self._font_mono

    @property
    def font_mono_small(self) -> tkfont.Font:
        return self._font_mono_small

    @property
    def font_title(self) -> tkfont.Font:
        return self._font_title

    @property
    def font_heading(self) -> tkfont.Font:
        return self._font_heading

    @property
    def font_small(self) -> tkfont.Font:
        return self._font_small

    @property
    def font_tiny(self) -> tkfont.Font:
        return self._font_tiny

    @property
    def font_metric(self) -> tkfont.Font:
        return self._font_metric

    def theme_use(self, theme_name: str) -> None:
        self._style.theme_use(theme_name)

    def _style_classic(self, widget: tk.Widget, colors: dict[str, str]) -> None:
        supported = set(widget.keys())
        is_text = isinstance(widget, tk.Text)
        options = {
            "background": colors["surface_2"] if is_text else colors["surface"],
            "foreground": colors["text"],
            "insertbackground": colors["text"],
            "selectbackground": colors["select"],
            "selectforeground": colors["select_text"],
            "highlightbackground": colors["border"],
            "highlightcolor": colors["accent"],
            "highlightthickness": 1,
            "relief": tk.FLAT,
            "borderwidth": 0,
            "font": self._font_mono if is_text else self._font_body,
        }
        widget.configure(**{key: value for key, value in options.items() if key in supported})

    # -- ttk 样式 ---------------------------------------------------------
    def _configure_scrollbars(self, colors: dict[str, str]) -> None:
        """细轨无箭头滚动条，贴近现代桌面应用。"""
        for orient, prefix in (("vertical", "Vertical"), ("horizontal", "Horizontal")):
            style_name = f"{prefix}.TScrollbar"
            self._style.configure(
                style_name,
                background=colors["border_strong"],
                troughcolor=colors["surface"],
                bordercolor=colors["surface"],
                darkcolor=colors["border_strong"],
                lightcolor=colors["border_strong"],
                arrowcolor=colors["text_faint"],
                gripcount=0,
                relief=tk.FLAT,
                borderwidth=0,
            )
            self._style.map(
                style_name,
                background=[("pressed", colors["text_faint"]), ("active", colors["text_dim"])],
            )
            thumb = f"{prefix}.Scrollbar.thumb"
            # 去掉上下箭头，只留细滚动块，贴近现代桌面应用
            element = f"{prefix}.Scrollbar.trough"
            sticky = "ns" if orient == "vertical" else "ew"
            # typeshed 的 _Layout 类型无法表达嵌套 children，这里按 Tk 的实际契约传入
            layout = [(element, {"sticky": sticky, "children": [(thumb, {"expand": "1", "sticky": "nswe"})]})]
            self._style.layout(style_name, cast("Any", layout))

    def apply(
        self,
        dark: bool,
        table: ttk.Treeview,
        classic_widgets: list[tk.Widget],
        *,
        alert_table: ttk.Treeview | None = None,
        detail_tree: ttk.Treeview | None = None,
        issue_table: ttk.Treeview | None = None,
    ) -> None:
        colors = build_colors(dark)
        app = self._app
        style = self._style

        app.configure(bg=colors["bg"])
        app.option_add("*TCombobox*Listbox.background", colors["surface_2"])
        app.option_add("*TCombobox*Listbox.foreground", colors["text"])
        app.option_add("*TCombobox*Listbox.selectBackground", colors["select"])
        app.option_add("*TCombobox*Listbox.selectForeground", colors["select_text"])
        style.configure(
            ".",
            background=colors["canvas"],
            foreground=colors["text"],
            fieldbackground=colors["surface_2"],
            bordercolor=colors["border"],
            lightcolor=colors["border"],
            darkcolor=colors["border"],
            troughcolor=colors["surface_2"],
            focuscolor=colors["accent"],
            font=self._font_body,
        )

        # -- 容器 ---------------------------------------------------------
        style.configure("TFrame", background=colors["canvas"])
        style.configure("Surface.TFrame", background=colors["surface"])
        style.configure("Surface2.TFrame", background=colors["surface_2"])
        style.configure("Surface3.TFrame", background=colors["surface_3"])
        style.configure("Rail.TFrame", background=colors["surface_2"])
        style.configure("TitleBar.TFrame", background=colors["surface_2"])
        style.configure("Border.TFrame", background=colors["border"])
        # 历史样式名，保留供旧代码/对话框使用
        style.configure("Toolbar.TFrame", background=colors["toolbar"])
        style.configure("FilterBar.TFrame", background=colors["filter"])
        style.configure("Summary.TFrame", background=colors["summary"])
        style.configure("Panel.TFrame", background=colors["panel"])
        style.configure(
            "Content.TPanedwindow", background=colors["canvas"], sashwidth=8, sashrelief=tk.FLAT, borderwidth=0
        )
        style.configure(
            "Sash",
            sashthickness=8,
            gripcount=0,
            background=colors["canvas"],
            bordercolor=colors["canvas"],
            lightcolor=colors["canvas"],
            darkcolor=colors["canvas"],
        )
        style.configure("TPanedwindow", background=colors["canvas"], sashwidth=8, sashrelief=tk.FLAT, borderwidth=0)
        # 面板用 Labelframe 语义承载标题；这里保持无边框，标题由 PanelHead 单独绘制
        style.configure(
            "TLabelframe",
            background=colors["surface"],
            foreground=colors["text"],
            bordercolor=colors["border"],
            relief=tk.SOLID,
            borderwidth=1,
        )
        style.configure(
            "TLabelframe.Label", background=colors["surface"], foreground=colors["text_dim"], font=self._font_heading
        )
        style.configure(
            "Card.TLabelframe",
            background=colors["surface"],
            bordercolor=colors["border"],
            relief=tk.SOLID,
            borderwidth=1,
        )
        style.configure(
            "Card.TLabelframe.Label",
            background=colors["surface"],
            foreground=colors["text_dim"],
            font=self._font_heading,
        )

        # -- 文本 ---------------------------------------------------------
        style.configure("TLabel", background=colors["canvas"], foreground=colors["text"])
        style.configure("Surface.TLabel", background=colors["surface"], foreground=colors["text"])
        style.configure(
            "PanelTitle.TLabel",
            background=colors["surface"],
            foreground=colors["text"],
            font=self._font_heading,
        )
        style.configure(
            "SectionLabel.TLabel",
            background=colors["surface"],
            foreground=colors["text_faint"],
            font=self._font_small,
        )
        style.configure(
            "MetricValue.TLabel",
            background=colors["surface"],
            foreground=colors["text"],
            font=self._font_metric,
        )
        style.configure(
            "MetricLabel.TLabel",
            background=colors["surface"],
            foreground=colors["text_faint"],
            font=self._font_small,
        )
        style.configure(
            "Dim.TLabel", background=colors["surface"], foreground=colors["text_dim"], font=self._font_small
        )
        style.configure(
            "Muted.TLabel", background=colors["toolbar"], foreground=colors["text_dim"], font=self._font_small
        )
        style.configure(
            "AppTitle.TLabel", background=colors["toolbar"], foreground=colors["text"], font=self._font_title
        )
        style.configure(
            "FilterLabel.TLabel", background=colors["filter"], foreground=colors["text"], font=self._font_small
        )
        style.configure(
            "Status.TLabel", background=colors["toolbar"], foreground=colors["success"], font=self._font_small
        )
        style.configure(
            "Hint.TLabel", background=colors["surface_2"], foreground=colors["text_faint"], font=self._font_small
        )
        style.configure(
            "Rail.TLabel", background=colors["surface_2"], foreground=colors["text_dim"], font=self._font_tiny
        )

        # -- 按钮 ---------------------------------------------------------
        def button_style(
            name: str,
            *,
            bg: str,
            fg: str,
            border: str,
            hover: str,
            pressed: str | None = None,
        ) -> None:
            style.configure(
                name,
                background=bg,
                foreground=fg,
                bordercolor=border,
                focuscolor=colors["accent"],
                focusthickness=1,
                relief=tk.FLAT,
                padding=(10, 4),
            )
            style.map(
                name,
                background=[
                    ("pressed", pressed or hover),
                    ("active", hover),
                    ("disabled", colors["surface_3"]),
                ],
                foreground=[("disabled", colors["text_faint"])],
                bordercolor=[("disabled", colors["border"])],
            )

        button_style(
            "TButton",
            bg=colors["surface_3"],
            fg=colors["text"],
            border=colors["border_strong"],
            hover=colors["hover"],
            pressed=colors["accent_press"],
        )
        button_style(
            "Secondary.TButton",
            bg=colors["surface_3"],
            fg=colors["text"],
            border=colors["border_strong"],
            hover=colors["hover"],
            pressed=colors["accent_press"],
        )
        button_style(
            "Ghost.TButton",
            bg=colors["surface_2"],
            fg=colors["text"],
            border=colors["border"],
            hover=colors["surface_3"],
        )
        # 日志条这类 30px 高的紧凑栏放不下常规按钮（需要 34px，会被压扁截字），
        # 单独给一个低内边距的变体
        style.configure(
            "Tiny.TButton",
            background=colors["surface_2"],
            foreground=colors["text_dim"],
            bordercolor=colors["border"],
            focuscolor=colors["accent"],
            focusthickness=0,
            relief=tk.FLAT,
            padding=(8, 1),
            font=self._font_tiny,
        )
        style.map(
            "Tiny.TButton",
            background=[("pressed", colors["surface_3"]), ("active", colors["surface_3"])],
            foreground=[("active", colors["text"]), ("disabled", colors["text_faint"])],
        )
        button_style(
            "Accent.TButton",
            bg=colors["accent"],
            fg=colors["on_accent"],
            border=colors["accent"],
            hover=colors["accent_active"],
        )
        button_style(
            "Danger.TButton",
            bg=colors["danger"],
            fg="#ffffff",
            border=colors["danger"],
            hover=colors["danger_active"],
        )
        button_style(
            "Success.TButton",
            bg=colors["success"],
            fg="#ffffff",
            border=colors["success"],
            hover=mix(colors["success"], "#ffffff", 0.18),
        )

        # -- 左侧操作轨：图标在上、文字在下 -------------------------------
        def rail_style(name: str, *, bg: str, fg: str, hover: str, pressed: str) -> None:
            style.configure(
                name,
                background=bg,
                foreground=fg,
                bordercolor=bg,
                focuscolor=colors["accent"],
                focusthickness=0,
                relief=tk.FLAT,
                padding=(4, 6),
                anchor=tk.CENTER,
                font=self._font_tiny,
            )
            style.map(
                name,
                background=[("pressed", pressed), ("active", hover)],
                foreground=[("active", colors["text"]), ("disabled", colors["text_faint"])],
            )

        rail_style(
            "Rail.TButton",
            bg=colors["surface_2"],
            fg=colors["text_dim"],
            hover=colors["surface_3"],
            pressed=colors["surface_3"],
        )
        rail_style(
            "RailAccent.TButton",
            bg=colors["accent"],
            fg=colors["on_accent"],
            hover=colors["accent_active"],
            pressed=colors["accent_press"],
        )
        rail_style(
            "RailDanger.TButton",
            bg=colors["tint_danger"],
            fg=colors["danger"],
            hover=mix(colors["tint_danger"], colors["danger"], 0.35),
            pressed=colors["danger"],
        )
        rail_style(
            "RailActive.TButton",
            bg=colors["tint_warning"],
            fg=colors["warning"],
            hover=mix(colors["tint_warning"], colors["warning"], 0.3),
            pressed=colors["warning"],
        )

        # -- 选择器 -------------------------------------------------------
        style.configure("TCheckbutton", background=colors["canvas"], foreground=colors["text"])

        style.configure(
            "Switch.TCheckbutton", background=colors["surface_2"], foreground=colors["text"], font=self._font_small
        )
        style.configure(
            "Surface.TCheckbutton", background=colors["surface"], foreground=colors["text"], font=self._font_small
        )
        style.map(
            "TCheckbutton",
            background=[("active", colors["canvas"])],
            foreground=[("active", colors["text"]), ("disabled", colors["text_faint"])],
            indicatorcolor=[("selected", colors["accent"]), ("!selected", colors["surface_2"])],
        )
        style.map(
            "Switch.TCheckbutton",
            background=[("active", colors["surface_2"])],
            foreground=[("active", colors["text"])],
            indicatorcolor=[("selected", colors["accent"]), ("!selected", colors["surface_3"])],
        )
        style.map(
            "Surface.TCheckbutton",
            background=[("active", colors["surface"])],
            foreground=[("active", colors["text"])],
            indicatorcolor=[("selected", colors["accent"]), ("!selected", colors["surface_3"])],
        )
        style.configure("TRadiobutton", background=colors["surface"], foreground=colors["text"], font=self._font_small)
        style.map(
            "TRadiobutton",
            background=[("active", colors["surface"])],
            foreground=[("active", colors["text"]), ("disabled", colors["text_faint"])],
            indicatorcolor=[("selected", colors["accent"]), ("!selected", colors["surface_3"])],
        )

        # -- 输入 ---------------------------------------------------------
        for name, border in (("TEntry", colors["border_strong"]), ("Filter.TEntry", colors["accent"])):
            style.configure(
                name,
                fieldbackground=colors["surface_2"],
                foreground=colors["text"],
                insertcolor=colors["text"],
                bordercolor=border,
                lightcolor=border,
                darkcolor=border,
                borderwidth=1,
                relief=tk.FLAT,
                padding=(6, 4),
            )
        style.map(
            "TEntry",
            bordercolor=[("focus", colors["accent"])],
            lightcolor=[("focus", colors["accent"])],
            darkcolor=[("focus", colors["accent"])],
        )
        style.configure(
            "TCombobox",
            fieldbackground=colors["surface_2"],
            background=colors["surface_3"],
            foreground=colors["text"],
            arrowcolor=colors["text_dim"],
            bordercolor=colors["border_strong"],
            lightcolor=colors["border_strong"],
            darkcolor=colors["border_strong"],
            borderwidth=1,
            relief=tk.FLAT,
            padding=(6, 4),
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", colors["surface_2"]), ("active", colors["surface_3"])],
            foreground=[("readonly", colors["text"])],
            bordercolor=[("focus", colors["accent"])],
            arrowcolor=[("active", colors["text"])],
        )

        # -- 标签页 -------------------------------------------------------
        style.configure(
            "Card.TNotebook",
            background=colors["surface"],
            bordercolor=colors["border"],
            lightcolor=colors["surface_2"],
            darkcolor=colors["surface_2"],
            borderwidth=0,
            tabmargins=(6, 5, 6, 0),
        )
        style.configure(
            "Card.TNotebook.Tab",
            background=colors["surface_2"],
            foreground=colors["text_dim"],
            lightcolor=colors["surface_2"],
            darkcolor=colors["surface_2"],
            bordercolor=colors["surface_2"],
            padding=(12, 5),
            font=self._font_small,
        )
        style.map(
            "Card.TNotebook.Tab",
            background=[("selected", colors["surface"]), ("active", colors["surface_3"])],
            foreground=[("selected", colors["text"]), ("active", colors["text"])],
            lightcolor=[("selected", colors["surface"])],
            darkcolor=[("selected", colors["surface"])],
            bordercolor=[("selected", colors["surface"])],
            expand=[("selected", (0, 0, 0, 0))],
        )

        # -- 表格 ---------------------------------------------------------
        style.configure(
            "Treeview",
            background=colors["surface"],
            foreground=colors["text"],
            fieldbackground=colors["surface"],
            bordercolor=colors["border"],
            lightcolor=colors["border"],
            darkcolor=colors["border"],
            borderwidth=0,
            relief=tk.FLAT,
            rowheight=23,
            font=self._font_body,
        )
        style.configure(
            "Treeview.Heading",
            background=colors["surface_2"],
            foreground=colors["text_faint"],
            bordercolor=colors["border"],
            lightcolor=colors["border"],
            darkcolor=colors["border"],
            relief=tk.FLAT,
            borderwidth=0,
            font=self._font_heading,
            padding=(8, 5),
        )
        style.map(
            "Treeview",
            background=[("selected", colors["select"])],
            foreground=[("selected", colors["select_text"])],
        )
        style.map(
            "Treeview.Heading",
            background=[("active", colors["surface_3"])],
            foreground=[("active", colors["text"])],
        )

        # -- 滚动条 -------------------------------------------------------
        self._configure_scrollbars(colors)

        # -- 数据行标签 ---------------------------------------------------
        tag_tree(table, "packets", colors)
        if alert_table is not None:
            tag_tree(alert_table, "alerts", colors)
        if detail_tree is not None:
            tag_tree(detail_tree, "detail", colors)
        if issue_table is not None:
            tag_tree(issue_table, "issues", colors)

        for widget in classic_widgets:
            try:
                if not widget.winfo_exists():
                    continue
            except tk.TclError:
                continue
            # 已销毁的控件直接跳过：中断会跳过后续重主题与 <<ThemeChanged>> 广播
            self._style_classic(widget, colors)
