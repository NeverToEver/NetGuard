from __future__ import annotations

import tkinter as tk


class Tooltip:
    """轻量悬停提示。

    在控件上延迟显示一行说明文字；离开或按下时消失。用于给工具栏按钮补充
    键盘快捷键等信息，避免用户只能靠猜。
    """

    def __init__(self, widget: tk.Widget, text: str, *, delay_ms: int = 500, dark: bool = False) -> None:
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self.dark = dark
        self._after_id: str | None = None
        self._tip: tk.Toplevel | None = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None) -> None:
        self._cancel()
        self._after_id = self.widget.after(self.delay_ms, self._show)

    def _cancel(self) -> None:
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except tk.TclError:
                pass
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
        from netguard.gui.theme import build_colors

        colors = build_colors(self.dark)
        label = tk.Label(
            tip, text=self.text, justify=tk.LEFT,
            background=colors["field_alt"], foreground=colors["text"],
            relief=tk.SOLID, borderwidth=1, padx=6, pady=3,
        )
        label.pack()
        self._tip = tip

    def _hide(self, _event=None) -> None:
        self._cancel()
        if self._tip is not None:
            try:
                self._tip.destroy()
            except tk.TclError:
                pass
            self._tip = None
