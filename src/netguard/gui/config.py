from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CONFIG_PATH = Path.home() / ".netguard_config.json"

THEME_MODES = ("light", "dark", "system")


def resolve_theme_mode(value: Any) -> str:
    """把旧版 dark_mode(bool) 或任意输入归一化为 light/dark/system。"""
    if value in THEME_MODES:
        return value
    if value is True:
        return "dark"
    if value is False:
        return "light"
    return "system"


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

    @classmethod
    def load(cls, path: Path | str = CONFIG_PATH) -> "AppConfig":
        config = cls(path=Path(path))
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return config
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            logger.warning("配置文件损坏，使用默认配置：%s", path)
            return config
        if not isinstance(raw, dict):
            return config
        config._apply(raw)
        return config

    def _apply(self, raw: dict[str, Any]) -> None:
        # 兼容旧版 {"dark_mode": bool}
        if "theme_mode" in raw:
            self.theme_mode = resolve_theme_mode(raw.get("theme_mode"))
        elif "dark_mode" in raw:
            self.theme_mode = resolve_theme_mode(raw.get("dark_mode"))

        window_raw = raw.get("window")
        if isinstance(window_raw, dict):
            self.window = WindowState(
                geometry=str(window_raw.get("geometry", "") or ""),
                zoomed=bool(window_raw.get("zoomed", False)),
                sashes=self._coerce_int_lists(window_raw.get("sashes")),
                columns=self._coerce_int_map(window_raw.get("columns")),
                sort_column=str(window_raw.get("sort_column", "") or ""),
                sort_descending=bool(window_raw.get("sort_descending", False)),
                last_device=str(window_raw.get("last_device", "") or ""),
                # 空 BPF 是合法值（抓全部流量），不能用 `or` 回退默认值吞掉
                bpf=str(window_raw.get("bpf", "tcp or udp")),
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
        return {
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

    def save(self) -> None:
        try:
            self.path.write_text(
                json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            logger.debug("无法保存配置文件 %s", self.path, exc_info=True)
