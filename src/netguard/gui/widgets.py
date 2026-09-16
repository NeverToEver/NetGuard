"""可复用的自绘控件：悬停提示、KPI 指标卡、迷你走势图与面板标题栏。

这些控件承担新界面的“视觉骨架”。Tkinter 没有圆角与阴影，因此层次感靠
边框色、表面色阶、内边距和字号阶梯来表达，而不是靠装饰。
"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from collections.abc import Callable
from contextlib import suppress

from netguard.gui.theme import build_colors, mix


class Tooltip:
    """轻量悬停提示。

    在控件上延迟显示一行说明文字；离开或按下时消失。用于给工具栏按钮补充
    键盘快捷键等信息，避免用户只能靠猜。
    """

    def __init__(
        self,
        widget: tk.Widget,
        text: str,
        *,
        delay_ms: int = 500,
        dark: bool = False,
        dark_provider: Callable[[], bool] | None = None,
    ) -> None:
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self.dark = dark
        # 显示时实时查询当前主题（dark_provider），避免主题切换后悬停提示
        # 仍用旧配色；provider 不可用时回退到构造时的快照值
        self.dark_provider = dark_provider
        self._after_id: str | None = None
        self._tip: tk.Toplevel | None = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event: tk.Event | None = None) -> None:
        self._cancel()
        self._after_id = self.widget.after(self.delay_ms, self._show)

    def _cancel(self) -> None:
        if self._after_id is not None:
            with suppress(tk.TclError):
                self.widget.after_cancel(self._after_id)
            self._after_id = None

    def _show(self) -> None:
        if self._tip is not None or not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + 12
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        except tk.TclError:
            return
        tip = tk.Toplevel(self.widget)
        tip.wm_overrideredirect(True)
        tip.wm_geometry(f"+{x}+{y}")
        # 跟随当前主题配色，而非固定深色
        dark = self.dark_provider() if self.dark_provider is not None else self.dark
        colors = build_colors(dark)
        label = tk.Label(
            tip,
            text=self.text,
            justify=tk.LEFT,
            background=colors["surface_3"],
            foreground=colors["text"],
            relief=tk.SOLID,
            borderwidth=1,
            padx=8,
            pady=4,
            font=("TkDefaultFont", 10),
        )
        label.pack()
        self._tip = tip

    def _hide(self, _event: tk.Event | None = None) -> None:
        self._cancel()
        if self._tip is not None:
            with suppress(tk.TclError):
                self._tip.destroy()
            self._tip = None


class Sparkline(tk.Canvas):
    """极简走势图：把最近若干个采样点画成柱状，用于 KPI 卡里的趋势提示。

    刻意不依赖任何绘图库——锯齿由 ``create_rectangle`` 画成；
    采样点数固定后，绘制开销恒定，抓包高峰期也不会拖慢刷新。
    """

    def __init__(
        self,
        master: tk.Misc,
        *,
        height: int = 16,
        capacity: int = 28,
        background: str,
        color: str,
    ) -> None:
        super().__init__(
            master,
            # Canvas 默认宽 10 厘米（约 378px）。这里由父容器 pack/grid 决定宽度，
            # 否则五个 KPI 卡会把窗口的“请求宽度”推到 2000px 以上。
            width=1,
            height=height,
            background=background,
            highlightthickness=0,
            borderwidth=0,
        )
        self._height = height
        self._capacity = capacity
        self._color = color
        self._samples: list[float] = []

    def configure_colors(self, *, background: str, color: str) -> None:
        self.configure(background=background)
        self._color = color
        self.redraw()

    def push(self, value: float) -> None:
        """追加一个采样点并重绘；超过容量时丢弃最旧的点。"""
        self._samples.append(max(0.0, float(value)))
        if len(self._samples) > self._capacity:
            del self._samples[: len(self._samples) - self._capacity]
        self.redraw()

    def clear(self) -> None:
        self._samples.clear()
        self.delete("all")

    def redraw(self) -> None:
        self.delete("all")
        if not self._samples:
            return
        width = self.winfo_width()
        if width <= 1:
            # 尚未完成第一次布局，用请求宽度兜底，避免画出 1px 宽的图
            width = self.winfo_reqwidth()
        width = max(int(width), 1)
        height = self._height
        peak = max(self._samples)
        if peak <= 0:
            # 全零时画一条基线，避免整卡在该行完全空白
            self.create_rectangle(0, height - 1, width, height, fill=self._color, outline="")
            return
        slot = width / len(self._samples)
        bar = max(2.0, slot - 2.0)
        for index, value in enumerate(self._samples):
            bar_height = max(1.0, (value / peak) * (height - 2))
            x0 = index * slot
            self.create_rectangle(
                x0,
                height - bar_height,
                x0 + bar,
                height,
                fill=self._color,
                outline="",
            )


class StatCard(tk.Frame):
    """KPI 指标卡：小标题 + 大号等宽数字 + 迷你走势图。

    ``alarm=True`` 时数字转为告警色并在左侧画一条 2px 强调竖条，
    让最需要被注意的指标（告警数）在一排同类卡片里跳出来。
    """

    def __init__(
        self,
        master: tk.Misc,
        *,
        label: str,
        value: str = "0",
        unit: str = "",
        alarm: bool = False,
        sparkline: bool = True,
        font_metric: tkfont.Font | str = "TkDefaultFont",
        font_small: tkfont.Font | str = "TkDefaultFont",
        colors: dict[str, str] | None = None,
    ) -> None:
        colors = colors or build_colors(False)
        surface = colors["surface"]
        super().__init__(master, background=surface, highlightthickness=0, borderwidth=0)
        self._alarm = alarm

        self._bar = tk.Frame(self, width=2, background=surface, borderwidth=0, highlightthickness=0)
        self._bar.pack(side=tk.LEFT, fill=tk.Y)

        self._inner = tk.Frame(self, background=surface, borderwidth=0, highlightthickness=0)
        self._inner.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(11, 12), pady=(7, 8))

        self._label = tk.Label(
            self._inner, text=label, anchor=tk.W, font=font_small, background=surface, foreground=colors["text_faint"]
        )
        self._label.pack(fill=tk.X)

        self._value_row = tk.Frame(self._inner, background=surface, borderwidth=0, highlightthickness=0)
        self._value_row.pack(fill=tk.X)
        self._value = tk.Label(
            self._value_row, text=value, anchor=tk.W, font=font_metric, background=surface, foreground=colors["text"]
        )
        self._value.pack(side=tk.LEFT)
        self._unit_label = tk.Label(
            self._value_row,
            text=unit,
            anchor=tk.SW,
            font=font_small,
            background=surface,
            foreground=colors["text_faint"],
        )
        if unit:
            self._unit_label.pack(side=tk.LEFT, padx=(4, 0), pady=(0, 2))

        self._spark: Sparkline | None = None
        if sparkline:
            self._spark = Sparkline(self._inner, background=surface, color=colors["accent"])
            self._spark.pack(fill=tk.X, pady=(2, 0))

        self.apply_colors(colors)

    @property
    def sparkline(self) -> Sparkline | None:
        return self._spark

    def set_value(self, text: str, *, unit: str | None = None) -> None:
        self._value.configure(text=text)
        if unit is not None:
            self._unit_label.configure(text=unit)

    def push_sample(self, value: float) -> None:
        if self._spark is not None:
            self._spark.push(value)

    def clear(self) -> None:
        if self._spark is not None:
            self._spark.clear()

    def apply_colors(self, colors: dict[str, str]) -> None:
        surface = colors["surface"]
        self.configure(background=surface)
        self._inner.configure(background=surface)
        for widget in (self._label, self._value_row, self._value, self._unit_label):
            widget.configure(background=surface)

        if self._alarm:
            value_color = colors["danger"]
            label_color = mix(colors["danger"], colors["text_faint"], 0.45)
            bar_color = colors["danger"]
            spark_color = mix(surface, colors["danger"], 0.55)
        else:
            value_color = colors["text"]
            label_color = colors["text_faint"]
            bar_color = surface
            spark_color = mix(surface, colors["accent"], 0.6)

        self._bar.configure(background=bar_color)
        self._value.configure(foreground=value_color)
        self._label.configure(foreground=label_color)
        self._unit_label.configure(foreground=colors["text_faint"])
        if self._spark is not None:
            self._spark.configure_colors(background=surface, color=spark_color)


class StatusPill(tk.Frame):
    """标题栏中的状态胶囊：圆点 + 状态文字整体换色。"""

    def __init__(self, master: tk.Misc, *, font: tkfont.Font | str = "TkDefaultFont") -> None:
        colors = build_colors(False)
        super().__init__(master, background=colors["surface_2"], highlightthickness=1, borderwidth=0)
        self._dot = tk.Label(self, text="●", font=font, background=colors["surface_2"], foreground=colors["text_dim"])
        self._dot.pack(side=tk.LEFT, padx=(7, 0))
        self._text = tk.Label(
            self, text="空闲", font=font, background=colors["surface_2"], foreground=colors["text_dim"]
        )
        self._text.pack(side=tk.LEFT, padx=(3, 9))

    def set_state(self, text: str, colors: dict[str, str], state: str) -> None:
        """按 idle / capturing / paused 切换配色。"""
        token = "success" if state == "capturing" else "warning" if state == "paused" else "text_dim"
        fg = colors[token]
        bg = colors["surface_2"] if state == "idle" else mix(colors["surface_2"], colors[token], 0.18)
        self.configure(background=bg, highlightbackground=fg, highlightcolor=fg)
        self._dot.configure(background=bg, foreground=fg)
        self._text.configure(text=text, background=bg, foreground=fg)


class PanelHeader(tk.Frame):
    """面板标题栏：左侧强调竖条 + 标题，右侧 ``actions`` 帧承载操作控件。"""

    def __init__(
        self,
        master: tk.Misc,
        title: str,
        *,
        accent_key: str = "accent",
        font_heading: tkfont.Font | str = "TkDefaultFont",
    ) -> None:
        colors = build_colors(False)
        surface2 = colors["surface_2"]
        super().__init__(master, background=surface2, height=30, borderwidth=0, highlightthickness=0)
        self.pack_propagate(False)
        self._accent_key = accent_key
        self._bar = tk.Frame(self, width=3, height=12, background=colors["accent"], borderwidth=0, highlightthickness=0)
        self._bar.pack(side=tk.LEFT, padx=(11, 8))
        self._title = tk.Label(
            self, text=title, font=font_heading, background=surface2, foreground=colors["text_dim"], anchor=tk.W
        )
        self._title.pack(side=tk.LEFT)
        self.actions = tk.Frame(self, background=surface2, borderwidth=0, highlightthickness=0)
        self.actions.pack(side=tk.RIGHT, padx=(0, 10))

    def apply_colors(self, colors: dict[str, str]) -> None:
        background = colors["surface_2"]
        self.configure(background=background)
        self._title.configure(background=background, foreground=colors["text_dim"])
        self.actions.configure(background=background)
        self._bar.configure(background=colors[self._accent_key])


def hline(master: tk.Misc, color: str, *, thickness: int = 1) -> tk.Frame:
    """一条 1px 分隔线：Tk 的 relief 分隔线在深色主题下不够干净，直接画色块。"""
    return tk.Frame(master, height=thickness, background=color, borderwidth=0, highlightthickness=0)


def vline(master: tk.Misc, color: str, *, thickness: int = 1) -> tk.Frame:
    return tk.Frame(master, width=thickness, background=color, borderwidth=0, highlightthickness=0)
