from __future__ import annotations

import netguard.gui.theme as theme
from netguard.rules.engine import Alert


def make_alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "timestamp": 1.0,
        "msg": "通用告警",
        "protocol": "TCP",
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "src_port": 1,
        "dst_port": 2,
        "summary": "x",
    }
    base.update(overrides)
    return Alert(**base)  # type: ignore[arg-type]


def test_build_colors_has_select_text() -> None:
    for dark in (True, False):
        colors = theme.build_colors(dark)
        assert "select_text" in colors
        assert colors["select_text"]


def test_build_colors_exposes_new_tokens_and_legacy_aliases() -> None:
    """新代码用语义令牌，旧对话框仍引用历史键名——两套必须都在。"""
    colors = theme.build_colors(True)
    for token in (
        "canvas",
        "surface",
        "surface_2",
        "surface_3",
        "border",
        "border_strong",
        "text",
        "text_dim",
        "text_faint",
        "accent",
        "proto_tcp",
        "proto_dns",
    ):
        assert colors[token], token
    for legacy in ("bg", "toolbar", "panel", "field", "field_alt", "muted", "accent_text"):
        assert colors[legacy], legacy


def test_legacy_aliases_point_at_the_new_tokens() -> None:
    colors = theme.build_colors(False)
    assert colors["bg"] == colors["canvas"]
    assert colors["panel"] == colors["surface"]
    assert colors["toolbar"] == colors["surface_2"]
    assert colors["muted"] == colors["text_dim"]
    assert colors["accent_text"] == colors["on_accent"]


def test_every_protocol_color_key_exists() -> None:
    for dark in (True, False):
        colors = theme.build_colors(dark)
        for key in theme.PROTOCOL_COLOR_KEYS.values():
            assert colors[key], key


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


# --- 结构化严重度 -----------------------------------------------------------


def test_severity_key_prefers_structured_field() -> None:
    assert theme.severity_key(make_alert(severity="high")) == "high"
    assert theme.severity_key(make_alert(severity="medium")) == "medium"
    assert theme.severity_key(make_alert(severity="low")) == "low"


def test_severity_key_maps_unknown_values_conservatively() -> None:
    # 自定义检测器写了 critical/severe → 按高档；其余未知一律中档
    assert theme.severity_key(make_alert(severity="critical")) == "high"
    assert theme.severity_key(make_alert(severity="weird")) == "medium"


def test_severity_key_defaults_to_medium_without_field() -> None:
    assert theme.severity_key(object()) == "medium"


def test_alert_color_uses_severity_not_message_keywords() -> None:
    """规则命中的消息里带 "scan" 也不该升级为高危——以结构化字段为准。"""
    colors = theme.build_colors(True)
    alert = make_alert(msg="检测到端口扫描", kind="rule", severity="medium")
    assert theme.alert_color(colors, alert) == colors["warning"]

    high = make_alert(msg="普通提示", kind="anomaly", severity="high", rule_id="syn-flood")
    assert theme.alert_color(colors, high) == colors["danger"]


def test_alert_color_falls_back_to_keywords_without_severity_field() -> None:
    colors = theme.build_colors(True)

    class Legacy:
        msg = "检测到 port scan"

    assert theme.alert_color(colors, Legacy()) == colors["danger"]


def test_alert_source_distinguishes_detectors_from_rules() -> None:
    assert theme.alert_source(make_alert(kind="anomaly", rule_id="port-scan")) == "port-scan"
    assert theme.alert_source(make_alert(kind="rule")) == "IDS 规则"


def test_severity_label_is_localized() -> None:
    assert theme.severity_label("high") == "高"
    assert theme.severity_label("medium") == "中"
    assert theme.severity_label("low") == "低"
    assert theme.severity_label("bogus") == "中"


# --- 颜色混合 ---------------------------------------------------------------


def test_mix_interpolates_and_clamps() -> None:
    assert theme.mix("#000000", "#ffffff", 0.0) == "#000000"
    assert theme.mix("#000000", "#ffffff", 1.0) == "#ffffff"
    assert theme.mix("#000000", "#ffffff", 0.5) == "#808080"
    # 越界的权重被夹到 [0, 1]，不会产生非法颜色
    assert theme.mix("#000000", "#ffffff", 5.0) == "#ffffff"
    assert theme.mix("#000000", "#ffffff", -1.0) == "#000000"


def test_protocol_color_handles_unknown_protocols() -> None:
    colors = theme.build_colors(True)
    assert theme.protocol_color(colors, "TCP") == colors["proto_tcp"]
    assert theme.protocol_color(colors, "http") == colors["proto_http"]
    assert theme.protocol_color(colors, "SSH") == colors["proto_other"]


def test_derive_surface_variants_are_distinct() -> None:
    for dark in (True, False):
        colors = theme.build_colors(dark)
        assert len({colors["canvas"], colors["surface"], colors["surface_2"], colors["surface_3"]}) == 4
        assert colors["hover"] != colors["surface_3"]
        assert colors["row_alt"] != colors["surface"]


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
