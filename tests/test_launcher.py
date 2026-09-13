"""一键启动器（scripts/launch.py）的单元测试。

只验证纯逻辑（解释器探测、自检输出、参数路由），不真正拉起 GUI 或子进程，
因此无需 libpcap / root / 显示环境。
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LAUNCH_PATH = ROOT / "scripts" / "launch.py"


def _load_launch():
    spec = importlib.util.spec_from_file_location("netguard_launch", LAUNCH_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def launch():
    return _load_launch()


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ((3, 11, 0), True),
        ((3, 12, 4), True),
        ((3, 13, 0), True),
        ((3, 10, 9), False),
        ((2, 7, 18), False),
    ],
)
def test_python_supported_boundaries(launch, version, expected) -> None:
    assert launch.python_supported(version) is expected


def test_venv_python_matches_platform(launch, tmp_path) -> None:
    resolved = launch.venv_python(tmp_path)
    assert resolved.parent.parent == tmp_path
    if sys.platform == "win32":
        assert resolved == tmp_path / "Scripts" / "python.exe"
    else:
        assert resolved == tmp_path / "bin" / "python"


def test_venv_python_default_uses_module_dir(launch) -> None:
    # 不显式传参时应读取当前 VENV_DIR，而不是定义时的快照
    assert launch.venv_python().parent.parent == launch.VENV_DIR


def test_project_paths_exist(launch) -> None:
    assert launch.MAIN_PY == ROOT / "main.py"
    assert launch.MAIN_PY.is_file()
    assert (launch.SRC_DIR / "netguard").is_dir()


def test_run_check_returns_int(launch, capsys) -> None:
    code = launch.run_check()
    out = capsys.readouterr().out
    assert code in (0, 1)
    assert "NetGuard 环境自检" in out
    assert "包导入" in out


def test_run_app_missing_entry_returns_error(launch, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(launch, "MAIN_PY", tmp_path / "missing.py")
    assert launch.run_app([]) == 1


def test_check_flag_routes_to_check(launch, monkeypatch, capsys) -> None:
    called: dict[str, int] = {}

    def fake_check() -> int:
        called["check"] = called.get("check", 0) + 1
        return 0

    monkeypatch.setattr(launch, "run_check", fake_check)
    assert launch.main(["--check"]) == 0
    assert called.get("check") == 1


def test_setup_no_run_skips_launch(launch, monkeypatch) -> None:
    state: dict[str, object] = {"setup": 0, "app": 0}

    def fake_setup() -> int:
        state["setup"] = int(state["setup"]) + 1
        return 0

    def fake_app(args):  # pragma: no cover - 不应被调用
        state["app"] = int(state["app"]) + 1
        return 0

    monkeypatch.setattr(launch, "run_setup", fake_setup)
    monkeypatch.setattr(launch, "run_app", fake_app)
    assert launch.main(["--setup", "--no-run"]) == 0
    assert state["setup"] == 1
    assert state["app"] == 0


def test_extra_args_forwarded_to_app(launch, monkeypatch) -> None:
    seen: dict[str, list[str]] = {}

    def fake_app(args):
        seen["args"] = list(args)
        return 0

    monkeypatch.setattr(launch, "run_app", fake_app)
    assert launch.main(["--read", "capture.pcap", "--alerts-json", "a.json"]) == 0
    assert seen["args"] == ["--read", "capture.pcap", "--alerts-json", "a.json"]
