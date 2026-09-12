from __future__ import annotations

import sys
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk


def _pick_font(available: set[str], candidates: list[str]) -> str:
    for name in candidates:
        if name in available:
            return name
    return "TkDefaultFont"


def resolve_fonts() -> tuple[str, str]:
    """Return (cjk_family, mono_family) for the current platform."""
    available = set(tkfont.families())
    if sys.platform == "win32":
        cjk = _pick_font(available, ["Microsoft YaHei", "SimHei", "SimSun", "FangSong", "KaiTi"])
        mono = _pick_font(available, ["Consolas", "Courier New", "Lucida Console"])
    elif sys.platform == "darwin":
        cjk = _pick_font(available, ["PingFang SC", "Heiti SC", "STHeiti"])
        mono = _pick_font(available, ["Menlo", "Monaco", "SF Mono"])
    else:
        cjk = _pick_font(available, ["Noto Sans CJK SC", "WenQuanYi Micro Hei", "WenQuanYi Zen Hei", "DejaVu Sans"])
        mono = _pick_font(available, ["DejaVu Sans Mono", "Liberation Mono", "Courier New", "monospace"])
    return cjk, mono


def build_colors(dark: bool) -> dict[str, str]:
    return {
        "bg": "#080e16" if dark else "#eef2f5",
        "toolbar": "#0e1824" if dark else "#dde6ef",
        "filter": "#111b29" if dark else "#d7ebf8",
        "summary": "#0c1522" if dark else "#f8fafc",
        "panel": "#182536" if dark else "#ffffff",
        "panel_alt": "#131f2f" if dark else "#f3f7fb",
        "field": "#0b1523" if dark else "#ffffff",
        "field_alt": "#111e2e" if dark else "#ecf2f8",
        "text": "#f3f7fb" if dark else "#102033",
        "muted": "#a6b4c3" if dark else "#536475",
        "accent": "#2d9ed4" if dark else "#0067a0",
        "accent_active": "#3fb5e8" if dark else "#005484",
        "accent_text": "#ffffff",
        "danger": "#ff6b5f" if dark else "#b42318",
        "danger_active": "#ff8a80" if dark else "#8f1d15",
        "success": "#3ddc84" if dark else "#1f7a3f",
        "info": "#2dd4bf" if dark else "#0d9488",
        "warning": "#ffcc66" if dark else "#9a5b00",
        "select": "#1a527c" if dark else "#b8dffc",
        "button": "#1b2a3c" if dark else "#edf3f8",
        "button_active": "#253649" if dark else "#dce8f1",
        "border": "#243241" if dark else "#b7c6d3",
        "focus": "#5dbdf0" if dark else "#0067a0",
    }


class ThemeManager:
    def __init__(self, app: tk.Tk) -> None:
        self._app = app
        self._style = ttk.Style(app)
        self._font_body = tkfont.nametofont("TkDefaultFont")
        self._font_text = tkfont.nametofont("TkTextFont")
        self._font_mono = tkfont.nametofont("TkFixedFont")
        self._font_heading = self._font_body.copy()
        self._font_small = self._font_body.copy()
        cjk, mono = resolve_fonts()
        for font in (self._font_body, self._font_text):
            font.configure(family=cjk, size=13)
        self._font_heading.configure(family=cjk, size=15, weight="bold")
        self._font_small.configure(family=cjk, size=11)
        self._font_mono.configure(family=mono, size=13)

    @property
    def font_body(self) -> tkfont.Font: return self._font_body
    @property
    def font_text(self) -> tkfont.Font: return self._font_text
    @property
    def font_mono(self) -> tkfont.Font: return self._font_mono
    @property
    def font_heading(self) -> tkfont.Font: return self._font_heading
    @property
    def font_small(self) -> tkfont.Font: return self._font_small

    def theme_use(self, theme_name: str) -> None:
        self._style.theme_use(theme_name)

    def apply(self, dark: bool, table: ttk.Treeview, classic_widgets: list[tk.Widget]) -> None:
        colors = build_colors(dark)
        app = self._app
        style = self._style

        app.configure(bg=colors["bg"])
        app.option_add("*TCombobox*Listbox.background", colors["field"])
        app.option_add("*TCombobox*Listbox.foreground", colors["text"])
        app.option_add("*TCombobox*Listbox.selectBackground", colors["select"])
        app.option_add("*TCombobox*Listbox.selectForeground", "#ffffff" if dark else colors["text"])
        style.configure(
            ".", background=colors["bg"], foreground=colors["text"],
            fieldbackground=colors["field"], bordercolor=colors["border"],
            lightcolor=colors["border"], darkcolor=colors["border"],
            troughcolor=colors["field"], font=self._font_body,
        )
        style.configure("TFrame", background=colors["bg"])
        style.configure("Toolbar.TFrame", background=colors["toolbar"])
        style.configure("FilterBar.TFrame", background=colors["filter"])
        style.configure("Summary.TFrame", background=colors["summary"])
        style.configure("Panel.TFrame", background=colors["panel"])
        style.configure("Content.TPanedwindow", background=colors["bg"])
        style.configure("TLabelframe", background=colors["panel"], foreground=colors["text"],
                        bordercolor=colors["border"], relief=tk.SOLID)
        style.configure("TLabelframe.Label", background=colors["panel"], foreground=colors["muted"],
                        font=self._font_heading)
        style.configure("TLabel", background=colors["bg"], foreground=colors["text"])
        style.configure("Muted.TLabel", background=colors["toolbar"], foreground=colors["muted"], font=self._font_small)
        style.configure("AppTitle.TLabel", background=colors["toolbar"], foreground=colors["text"], font=self._font_heading)
        style.configure("FilterLabel.TLabel", background=colors["filter"], foreground=colors["text"], font=self._font_small)
        style.configure("Metric.TLabel", background=colors["summary"], foreground=colors["muted"], font=self._font_small)
        style.configure("Status.TLabel", background=colors["toolbar"], foreground=colors["success"], font=self._font_small)
        style.configure("TButton", background=colors["button"], foreground=colors["text"],
                        bordercolor=colors["border"], focusthickness=2, focuscolor=colors["focus"], padding=(10, 5))
        style.map("TButton", background=[("pressed", colors["field"]), ("active", colors["button_active"])],
                  foreground=[("disabled", colors["muted"])])
        style.configure("Secondary.TButton", background=colors["button"], foreground=colors["text"],
                        bordercolor=colors["border"], padding=(10, 5))
        style.map("Secondary.TButton", background=[("pressed", colors["field"]), ("active", colors["button_active"])])
        style.configure("Accent.TButton", background=colors["accent"], foreground=colors["accent_text"],
                        bordercolor=colors["accent"], padding=(10, 5))
        style.map("Accent.TButton", background=[("pressed", colors["accent_active"]), ("active", colors["accent_active"])])
        style.configure("Danger.TButton", background=colors["danger"], foreground="#ffffff",
                        bordercolor=colors["danger"], padding=(10, 5))
        style.map("Danger.TButton", background=[("pressed", colors["danger_active"]), ("active", colors["danger_active"])])
        style.configure("TCheckbutton", background=colors["bg"], foreground=colors["text"])
        style.configure("Switch.TCheckbutton", background=colors["toolbar"], foreground=colors["text"], font=self._font_small)
        style.map("TCheckbutton", background=[("active", colors["bg"])],
                  foreground=[("active", colors["text"]), ("disabled", colors["muted"])],
                  indicatorcolor=[("selected", colors["accent"]), ("!selected", colors["field"])])
        style.map("Switch.TCheckbutton", background=[("active", colors["toolbar"])], foreground=[("active", colors["text"])])
        style.configure("TEntry", fieldbackground=colors["field"], foreground=colors["text"],
                        insertcolor=colors["text"], bordercolor=colors["border"], padding=(6, 4))
        style.configure("Filter.TEntry", fieldbackground=colors["field"], foreground=colors["text"],
                        insertcolor=colors["text"], bordercolor=colors["accent"], padding=(7, 4))
        style.configure("TCombobox", fieldbackground=colors["field"], foreground=colors["text"],
                        arrowcolor=colors["muted"], bordercolor=colors["border"], padding=(6, 4))
        style.map("TCombobox", fieldbackground=[("readonly", colors["field"]), ("active", colors["field_alt"])],
                  foreground=[("readonly", colors["text"])])
        style.configure("Treeview", background=colors["field"], foreground=colors["text"],
                        fieldbackground=colors["field"], bordercolor=colors["border"], rowheight=32, font=self._font_body)
        style.configure("Treeview.Heading", background=colors["field_alt"], foreground=colors["muted"],
                        bordercolor=colors["border"], font=self._font_heading, padding=(6, 5))
        style.map("Treeview", background=[("selected", colors["select"])],
                  foreground=[("selected", "#ffffff" if dark else colors["text"])])
        style.map("Treeview.Heading", background=[("active", colors["button_active"])])
        table.tag_configure("odd", background=colors["field"])
        table.tag_configure("even", background=colors["field_alt"])
        table.tag_configure("tcp", foreground=colors["accent"])
        table.tag_configure("udp", foreground=colors["success"])
        table.tag_configure("http", foreground=colors["warning"])
        table.tag_configure("dns", foreground=colors["info"])
        table.tag_configure("issue", foreground=colors["danger"])
        for widget in classic_widgets:
            supported = set(widget.keys())
            is_text = isinstance(widget, tk.Text)
            options = {
                "background": colors["field"], "foreground": colors["text"],
                "insertbackground": colors["text"], "selectbackground": colors["select"],
                "selectforeground": "#ffffff" if dark else colors["text"],
                "highlightbackground": colors["border"], "highlightcolor": colors["accent"],
                "highlightthickness": 1, "relief": tk.FLAT, "borderwidth": 0,
                "font": self._font_mono if is_text else self._font_body,
            }
            widget.configure(**{key: value for key, value in options.items() if key in supported})
