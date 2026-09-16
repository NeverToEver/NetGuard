from __future__ import annotations

import json

from netguard.gui.config import AppConfig, resolve_theme_mode


def test_defaults_when_file_missing(tmp_path) -> None:
    config = AppConfig.load(tmp_path / "nope.json")
    assert config.theme_mode == "system"
    assert config.window.bpf == "tcp or udp"


def test_roundtrip(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    config = AppConfig.load(path)
    config.theme_mode = "dark"
    config.window.geometry = "1200x800+10+10"
    config.window.sashes = {"main": [500]}
    config.window.columns = {"time": 120}
    config.window.sort_column = "len"
    config.window.sort_descending = True
    config.window.last_device = r"\Device\NPF_{X}"
    config.save()

    loaded = AppConfig.load(path)
    assert loaded.theme_mode == "dark"
    assert loaded.window.geometry == "1200x800+10+10"
    assert loaded.window.sashes == {"main": [500]}
    assert loaded.window.columns == {"time": 120}
    assert loaded.window.sort_column == "len"
    assert loaded.window.sort_descending is True
    assert loaded.window.last_device == r"\Device\NPF_{X}"


def test_migrates_legacy_dark_mode_true(tmp_path) -> None:
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"dark_mode": True}), encoding="utf-8")
    assert AppConfig.load(path).theme_mode == "dark"


def test_migrates_legacy_dark_mode_false(tmp_path) -> None:
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"dark_mode": False}), encoding="utf-8")
    assert AppConfig.load(path).theme_mode == "light"


def test_corrupt_file_falls_back_to_defaults(tmp_path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not valid json", encoding="utf-8")
    config = AppConfig.load(path)
    assert config.theme_mode == "system"


def test_malformed_window_section_is_ignored(tmp_path) -> None:
    path = tmp_path / "weird.json"
    path.write_text(
        json.dumps(
            {
                "theme_mode": "dark",
                "window": {"sashes": {"a": ["x"]}, "columns": {"time": "abc"}, "bpf": 123},
            }
        ),
        encoding="utf-8",
    )
    config = AppConfig.load(path)
    assert config.theme_mode == "dark"
    assert config.window.sashes == {}
    assert config.window.columns == {}
    assert config.window.bpf == "123"


def test_resolve_theme_mode_variants() -> None:
    assert resolve_theme_mode("dark") == "dark"
    assert resolve_theme_mode("light") == "light"
    assert resolve_theme_mode("system") == "system"
    assert resolve_theme_mode(True) == "dark"
    assert resolve_theme_mode(False) == "light"
    assert resolve_theme_mode("garbage") == "system"
    assert resolve_theme_mode(None) == "system"


def test_bpf_null_falls_back_to_empty(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps({"window": {"bpf": None}}), encoding="utf-8")
    assert AppConfig.load(path).window.bpf == ""


def test_loads_utf8_bom_file(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps({"theme_mode": "dark"}), encoding="utf-8-sig")
    assert AppConfig.load(path).theme_mode == "dark"


def test_string_bools_are_parsed(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(
        json.dumps({"window": {"zoomed": "false", "sort_descending": "1"}}),
        encoding="utf-8",
    )
    window = AppConfig.load(path).window
    assert window.zoomed is False
    assert window.sort_descending is True


def test_theme_mode_normalized_and_legacy_fallback(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps({"theme_mode": "Dark"}), encoding="utf-8")
    assert AppConfig.load(path).theme_mode == "dark"

    path.write_text(json.dumps({"theme_mode": 1, "dark_mode": True}), encoding="utf-8")
    assert AppConfig.load(path).theme_mode == "dark"

    # 显式 system 不应被 legacy dark_mode 覆盖
    path.write_text(json.dumps({"theme_mode": "system", "dark_mode": True}), encoding="utf-8")
    assert AppConfig.load(path).theme_mode == "system"


def test_unknown_fields_survive_roundtrip(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text(
        json.dumps({"theme_mode": "dark", "window": {}, "future_field": {"a": 1}}),
        encoding="utf-8",
    )
    AppConfig.load(path).save()
    assert json.loads(path.read_text(encoding="utf-8"))["future_field"] == {"a": 1}


def test_save_leaves_no_temp_file(tmp_path) -> None:
    path = tmp_path / "cfg.json"
    config = AppConfig.load(path)
    config.theme_mode = "light"
    config.save()
    config.save()
    assert path.exists()
    assert not (tmp_path / "cfg.json.tmp").exists()
