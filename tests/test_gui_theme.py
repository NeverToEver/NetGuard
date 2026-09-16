from __future__ import annotations

import netguard.gui.theme as theme


def test_build_colors_has_select_text() -> None:
    for dark in (True, False):
        colors = theme.build_colors(dark)
        assert "select_text" in colors
        assert colors["select_text"]


def test_severity_color_maps_known_keywords() -> None:
    colors = theme.build_colors(False)
    assert theme.severity_color(colors, "检测到 port scan") == colors["danger"]
    assert theme.severity_color(colors, "suspicious anomaly") == colors["warning"]
    assert theme.severity_color(colors, "普通 GET 请求") == colors["success"]


def test_status_color_maps_states() -> None:
    colors = theme.build_colors(True)
    assert theme.status_color(colors, "capturing") == colors["success"]
    assert theme.status_color(colors, "paused") == colors["warning"]
    assert theme.status_color(colors, "idle") == colors["muted"]
    assert theme.status_color(colors, "unknown") == colors["muted"]


def test_detect_system_dark_returns_bool_without_crashing() -> None:
    assert isinstance(theme.detect_system_dark(), bool)


def test_detect_system_dark_windows_dark(monkeypatch) -> None:
    fake_winreg = type(
        "W",
        (),
        {
            "HKEY_CURRENT_USER": 1,
            "OpenKey": staticmethod(lambda *a, **k: _Ctx()),
            "QueryValueEx": staticmethod(lambda *a, **k: (0, 4)),
        },
    )
    monkeypatch.setattr(theme.platform, "system", lambda: "Windows")
    monkeypatch.setitem(__import__("sys").modules, "winreg", fake_winreg)
    assert theme.detect_system_dark() is True


def test_detect_system_dark_linux_light(monkeypatch) -> None:
    class Result:
        stdout = "'default'\n"

    monkeypatch.setattr(theme.platform, "system", lambda: "Linux")
    monkeypatch.setattr(theme.subprocess, "run", lambda *a, **k: Result())
    assert theme.detect_system_dark() is False


def test_detect_system_dark_swallows_errors(monkeypatch) -> None:
    def boom(*a, **k):
        raise OSError("no tool")

    monkeypatch.setattr(theme.platform, "system", lambda: "Linux")
    monkeypatch.setattr(theme.subprocess, "run", boom)
    assert theme.detect_system_dark() is False


class _Ctx:
    def __enter__(self) -> _Ctx:
        return self

    def __exit__(self, *args) -> bool:
        return False
