"""版本号一致性。

版本此前在 pyproject.toml 与 scripts/build_unix_app.py 各硬编码一份，容易漂移。
现在收敛为 netguard/_version.py 单一来源，本用例守住这条约束。
"""

from __future__ import annotations

import importlib.metadata
import re
import tomllib
from pathlib import Path

import pytest

import netguard
from netguard import __version__

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
VERSION_MODULE = ROOT / "src" / "netguard" / "_version.py"

# 语义化版本：MAJOR.MINOR.PATCH，允许预发布/构建后缀
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def _load_pyproject() -> dict:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)


def test_version_is_valid_semver() -> None:
    assert SEMVER_RE.match(__version__), f"版本号不符合语义化版本：{__version__}"


def test_pyproject_derives_version_from_single_source() -> None:
    """pyproject 必须从 _version.py 读取版本，而不是再写一份字面量。"""
    project = _load_pyproject()["project"]
    assert "version" not in project, "pyproject 不应再硬编码 version 字面量"
    assert "version" in project["dynamic"], "version 应声明为 dynamic"

    dynamic = _load_pyproject()["tool"]["setuptools"]["dynamic"]["version"]
    assert dynamic["attr"] == "netguard._version.__version__"


def test_version_module_has_no_imports() -> None:
    """_version.py 会被打包工具在导入包之前读取，不应引入任何依赖。"""
    lines = [
        line.strip()
        for line in VERSION_MODULE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    imports = [line for line in lines if line.startswith(("import ", "from "))]
    assert not imports, f"_version.py 不应有导入语句：{imports}"

    assignments = [line for line in lines if line.startswith("__version__")]
    assert len(assignments) == 1, "应且仅应有一处 __version__ 赋值"


def test_version_matches_installed_metadata() -> None:
    """若包已安装（pip install -e .），元数据版本应与源码一致。

    未安装时跳过：仓库约定测试可在未安装状态下运行（pyproject 配了
    pythonpath = ["src"]）。
    """
    try:
        installed = importlib.metadata.version("netguard")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("netguard 未安装，跳过元数据比对")
    assert installed == __version__


def test_dunder_all_exports_version() -> None:
    assert "__version__" in netguard.__all__
