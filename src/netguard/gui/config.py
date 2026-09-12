from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CONFIG_PATH = Path.home() / ".netguard_config.json"

THEME_MODES = ("light", "dark", "system")

_BOOL_TRUE = ("1", "true", "yes", "on")
_BOOL_FALSE = ("0", "false", "no", "off", "")


def resolve_theme_mode(value: Any) -> str:
    """把旧版 dark_mode(bool) 或任意输入归一化为 light/dark/system。"""
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in THEME_MODES:
            return normalized
        if normalized in _BOOL_TRUE:
            return "dark"
        if normalized in _BOOL_FALSE:
            return "light"
    if value is True:
        return "dark"
    if value is False:
        return "light"
    return "system"


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """宽松布尔解析：手工编辑的 "false"/0 等不应全部当成 True。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _BOOL_TRUE:
            return True
        if normalized in _BOOL_FALSE:
            return False
    return default


@dataclass
class WindowState:
    geometry: str = ""
    zoomed: bool = False
    sashes: dict[str, list[int]] = field(default_factory=dict)
    columns: dict[str, int] = field(default_factory=dict)
    sort_column: str = ""
    sort_descending: bool = False
    last_device: str = ""
    bpf: str = "tcp or udp"
    display_filter: str = ""


@dataclass
class AppConfig:
    """应用配置读写，带旧版字段迁移与损坏文件容错。

    纯逻辑，不依赖 Tk，便于单元测试。
    """

    theme_mode: str = "system"
    window: WindowState = field(default_factory=WindowState)
    path: Path = CONFIG_PATH
    # load 时保留的未知字段（未来版本新增或外部工具写入），save 时原样回写
    _extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | str = CONFIG_PATH) -> "AppConfig":
        config = cls(path=Path(path))
        try:
            # utf-8-sig 兼容带 BOM 的文件（Windows 记事本 "UTF-8 with BOM"）
            raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            return config
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            logger.warning("配置文件损坏，使用默认配置：%s", path)
            return config
        if not isinstance(raw, dict):
            return config
        config._apply(raw)
        config._extra = {k: v for k, v in raw.items() if k not in ("theme_mode", "window")}
        return config

    def _apply(self, raw: dict[str, Any]) -> None:
        # 兼容旧版 {"dark_mode": bool}
        if "theme_mode" in raw:
            theme_raw = raw.get("theme_mode")
            resolved = resolve_theme_mode(theme_raw)
            if resolved == "system" and theme_raw not in THEME_MODES and "dark_mode" in raw:
                # theme_mode 字段非法时回退 legacy dark_mode，避免深色设置丢失
                resolved = resolve_theme_mode(raw.get("dark_mode"))
            self.theme_mode = resolved
        elif "dark_mode" in raw:
            self.theme_mode = resolve_theme_mode(raw.get("dark_mode"))

        window_raw = raw.get("window")
        if isinstance(window_raw, dict):
            bpf_value = window_raw.get("bpf", "tcp or udp")
            self.window = WindowState(
                geometry=str(window_raw.get("geometry", "") or ""),
                zoomed=_coerce_bool(window_raw.get("zoomed", False)),
                sashes=self._coerce_int_lists(window_raw.get("sashes")),
                columns=self._coerce_int_map(window_raw.get("columns")),
                sort_column=str(window_raw.get("sort_column", "") or ""),
                sort_descending=_coerce_bool(window_raw.get("sort_descending", False)),
                last_device=str(window_raw.get("last_device", "") or ""),
                # 空 BPF 是合法值（抓全部流量），不能用 `or` 回退默认值吞掉；
                # 键存在但为 null 时回退空串，避免字面量 "None" 被当成 BPF 表达式
                bpf="" if bpf_value is None else str(bpf_value),
                display_filter=str(window_raw.get("display_filter", "") or ""),
            )

    @staticmethod
    def _coerce_int_lists(value: Any) -> dict[str, list[int]]:
        result: dict[str, list[int]] = {}
        if not isinstance(value, dict):
            return result
        for key, item in value.items():
            if isinstance(item, (list, tuple)):
                try:
                    result[str(key)] = [int(x) for x in item]
                except (TypeError, ValueError):
                    continue
        return result

    @staticmethod
    def _coerce_int_map(value: Any) -> dict[str, int]:
        result: dict[str, int] = {}
        if not isinstance(value, dict):
            return result
        for key, item in value.items():
            try:
                result[str(key)] = int(item)
            except (TypeError, ValueError):
                continue
        return result

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "theme_mode": self.theme_mode,
            "window": {
                "geometry": self.window.geometry,
                "zoomed": self.window.zoomed,
                "sashes": self.window.sashes,
                "columns": self.window.columns,
                "sort_column": self.window.sort_column,
                "sort_descending": self.window.sort_descending,
                "last_device": self.window.last_device,
                "bpf": self.window.bpf,
                "display_filter": self.window.display_filter,
            },
        }
        result.update(self._extra)
        return result

    def save(self) -> None:
        payload = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        tmp_path = self.path.parent / (self.path.name + ".tmp")
        try:
            # 原子替换：先写临时文件再 rename，写入中途崩溃不会留下半截 JSON
            tmp_path.write_text(payload, encoding="utf-8")
            os.replace(tmp_path, self.path)
        except OSError:
            logger.warning("无法保存配置文件 %s", self.path, exc_info=True)
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
