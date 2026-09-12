"""GUI 冒烟测试：真实构造 Tk 窗口并演练关键交互，无显示环境自动跳过。

一个进程内反复创建/销毁 Tk 根窗口会让 Tcl 解释器失效，因此这里用模块级
单例窗口，每个用例只重置状态、不重建窗口。
"""
from __future__ import annotations

import time

import pytest

tk = pytest.importorskip("tkinter")

_app = None
_skip_reason = ""


def _get_app():
    global _app, _skip_reason
    if _app is not None:
        return _app
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        _skip_reason = f"无可用显示：{exc}"
        return None
    root.withdraw()
    from netguard.gui.main_ui import NetGuardApp

    _app = NetGuardApp()
    _app.withdraw()
    _app.update_idletasks()
    _app.update()
    return _app


@pytest.fixture()
def app():
    application = _get_app()
    if application is None:
        pytest.skip(_skip_reason)
    # 每测重置可变状态，避免用例间互相污染
    application.events = []
    application.filtered = []
    application.event_offset = 0
    application._sort_column = ""
    application._sort_descending = False
    application._set_theme_mode("system")
    application.update_idletasks()
    application.update()
    yield application


def test_main_window_builds_with_menu_and_status_bar(app) -> None:
    assert app.cget("menu")
    assert app.status_text_var.get()
    assert app.theme_mode.get() in {"light", "dark", "system"}


def test_theme_switching_updates_dark_flag(app) -> None:
    app._set_theme_mode("dark")
    assert app.dark_mode.get() is True
    app._set_theme_mode("light")
    assert app.dark_mode.get() is False
    app._set_theme_mode("system")


def test_sort_toggles_direction(app) -> None:
    app._sort("time")
    assert app._sort_column == "time"
    assert app._sort_descending is False
    app._sort("time")
    assert app._sort_descending is True


def test_refilter_batches_without_blocking(app) -> None:
    from netguard.parser.packet import PacketInfo
    from netguard.pipeline import PacketEvent

    app.events = [
        PacketEvent(
            PacketInfo(
                timestamp=float(i), length=60, raw=b"GET / HTTP/1.1\r\n\r\n",
                protocol="HTTP", src="10.0.0.1", dst="10.0.0.2",
                src_port=1, dst_port=80, summary="GET",
            ),
            (),
        )
        for i in range(1200)
    ]
    app._refilter()
    for _ in range(400):
        app.update()
        if app._refilter_after_id is None:
            break
        time.sleep(0.005)
    assert len(app.filtered) == 1200


def test_background_helper_marshals_result(app) -> None:
    result: dict[str, object] = {}
    app._run_in_background(lambda: 7, lambda value: result.setdefault("value", value), "busy", "错误")
    for _ in range(200):
        app._pump_background()
        if "value" in result:
            break
        time.sleep(0.005)
    assert result.get("value") == 7
    assert app.busy_text_var.get() == ""


def test_background_helper_reports_failure(app, monkeypatch) -> None:
    from netguard.gui import main_ui

    captured = {}
    monkeypatch.setattr(main_ui.messagebox, "showerror",
                        lambda title, message, **kw: captured.update(title=title, message=message))

    def boom():
        raise ValueError("nope")

    app._run_in_background(boom, lambda _r: None, "busy", "错误")
    for _ in range(200):
        app._pump_background()
        if app._busy_count == 0:
            break
        time.sleep(0.005)
    assert app._busy_count == 0
    assert app.busy_text_var.get() == ""
    assert captured.get("title") == "错误"
    assert "nope" in str(captured.get("message"))
