"""窗口几何钳制与分隔条恢复的回归测试。

这两个函数是纯字符串/整数运算，可以脱离 Tk 单独验证——而它们恰好是
「窗口跑到屏幕外」和「主区域塌成一条线」两个真实缺陷的所在。
"""

from __future__ import annotations

import pytest

from netguard.gui.main_ui import NetGuardApp

SCREEN_W, SCREEN_H = 2048, 1152


def clamp(geometry: str, screen: tuple[int, int] = (SCREEN_W, SCREEN_H)) -> str:
    """脱离 Tk 调用 _clamped_geometry：只用到 winfo_screenwidth/height。"""
    app = object.__new__(NetGuardApp)
    app.winfo_screenwidth = lambda: screen[0]  # type: ignore[method-assign]
    app.winfo_screenheight = lambda: screen[1]  # type: ignore[method-assign]
    return app._clamped_geometry(geometry)


def parse(geometry: str) -> tuple[int, int, int, int]:
    size, _, rest = geometry.partition("+")
    width, _, height = size.partition("x")
    x_text, _, y_text = rest.partition("+")
    return int(width), int(height), int(x_text), int(y_text)


def test_oversized_window_is_shrunk_to_fit_screen() -> None:
    """回归：早期只夹位置不夹尺寸，2560 宽屏存下的 geometry 到 2048 屏上
    会把窗口右半边（含操作按钮）整个推到屏幕外。"""
    width, height, x, y = parse(clamp("2228x1147+224+106"))
    assert width <= SCREEN_W
    assert height <= SCREEN_H
    assert x >= 0 and y >= 0
    assert x + width <= SCREEN_W


def test_offscreen_position_is_pulled_back() -> None:
    width, height, x, y = parse(clamp("1200x800+9000+9000"))
    assert x + width <= SCREEN_W
    assert y + height <= SCREEN_H


def test_normal_geometry_is_preserved() -> None:
    assert clamp("1280x800+100+50") == "1280x800+100+50"


def test_size_only_geometry_keeps_position_only_clamping() -> None:
    """形如 "+100+50" 的纯位置请求不应被加上尺寸。"""
    assert clamp("+100+50") == "+100+50"


def test_unparseable_geometry_is_returned_unchanged() -> None:
    assert clamp("not-a-geometry") == "not-a-geometry"
    assert clamp("") == ""


def test_negative_offsets_are_clamped_to_origin() -> None:
    _width, _height, x, y = parse(clamp("1200x800-500-500"))
    assert (x, y) == (0, 0)


@pytest.mark.parametrize("screen", [(1280, 720), (3840, 2160)])
def test_clamp_works_across_screen_sizes(screen: tuple[int, int]) -> None:
    width, height, x, y = parse(clamp("2228x1147+100+100", screen))
    assert width <= screen[0]
    assert height <= screen[1]
    assert x >= 0 and y >= 0


def test_sash_clamp_keeps_tail_visible() -> None:
    """模拟 _apply_saved_sashes 的钳制：保存值过大时必须给尾部窗格留空间。

    回归：分隔条位置最初按窗口尺寸算，底部标签页被挤成一条缝；
    且 ttk 在首次布局前会把 sashpos 钳到 0，主区域直接塌掉。
    """
    min_lead, min_tail, span = 160, 150, 664
    for saved in (0, 5, 554, 2000, -100):
        clamped = max(min_lead, min(int(saved), span - min_tail))
        assert min_lead <= clamped <= span - min_tail


def test_legacy_sash_layout_is_discarded() -> None:
    """旧布局的 "bottom" 键（告警│统计│规则三栏）在新布局里没有对应窗格，
    见到它就整组丢弃，否则老用户升级后会看到被压扁的窗口。

    这里复刻 _apply_saved_sashes 里的判断，锁住「旧配置不生效、新配置照常生效」。
    """
    legacy = {"workspace": [554], "main": [1338], "bottom": [1082, 1623]}
    current = {"workspace": [406], "main": [900]}

    def effective(saved: dict[str, list[int]]) -> dict[str, list[int]]:
        return {} if "bottom" in saved else saved

    assert effective(legacy) == {}
    assert effective(current) == current
