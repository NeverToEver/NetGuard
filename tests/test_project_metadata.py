"""项目元数据与文档完整性。

对应两类真实出现过的问题：
- README 引用已删除的文档，或新增文档无人索引（死链与孤立文档）；
- 版本号、CI 任务、质量门槛等元数据与配置漂移。
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
DOCS = ROOT / "docs"
PYPROJECT = ROOT / "pyproject.toml"

LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def _load_pyproject() -> dict:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)


def _local_links(text: str) -> list[str]:
    """抽出相对链接（跳过 http/https/mailto 与纯锚点），去掉 # 锚点。"""
    found: list[str] = []
    for match in LINK_RE.finditer(text):
        target = match.group(1).strip().split("#", 1)[0]
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        found.append(target)
    return found


def test_readme_relative_links_resolve() -> None:
    """README 中的每个相对链接都必须指向真实存在的文件。"""
    missing = [target for target in _local_links(README.read_text(encoding="utf-8")) if not (ROOT / target).exists()]
    assert not missing, f"README 存在失效链接：{missing}"


def test_readme_images_exist() -> None:
    """README 引用的图片文件必须存在（截图容易在重构后失联）。"""
    text = README.read_text(encoding="utf-8")
    images = [m.group(1) for m in re.finditer(r"!\[[^\]]*\]\(([^)]+)\)", text) if not m.group(1).startswith("http")]
    assert images, "README 应至少引用一张界面截图"
    for image in images:
        assert (ROOT / image).exists(), f"截图不存在：{image}"


def _tracked_docs() -> list[Path]:
    """返回 git 跟踪的 docs/*.md。

    只校验会随仓库发布的文档：docs/member-*-work.md 含真实姓名与学号，
    经 .git/info/exclude 本地排除，不属于公开文档，不应要求被索引。
    非 git 环境（如解压后的源码包）下退回全部文件。
    """
    try:
        result = subprocess.run(
            ["git", "ls-files", "docs/*.md"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):  # pragma: no cover - 取决于环境
        return sorted(DOCS.glob("*.md"))
    tracked = [ROOT / line.strip() for line in result.stdout.splitlines() if line.strip()]
    return sorted(tracked) or sorted(DOCS.glob("*.md"))


def test_docs_index_covers_all_docs() -> None:
    """docs/ 下的每份已发布文档都应出现在索引中，避免出现孤立文档。

    只校验 docs/ 的直接子文件：docs/reviews/ 与 docs/images/ 作为目录在索引中
    整体引用，无需逐个登记。
    """
    index = DOCS / "README.md"
    assert index.exists(), "缺少 docs/README.md 文档索引"
    index_text = index.read_text(encoding="utf-8")

    for doc in _tracked_docs():
        if doc.name == "README.md" or doc.parent != DOCS:
            continue
        assert doc.name in index_text, f"文档未被索引：docs/{doc.name}"


def test_docs_relative_links_resolve() -> None:
    """docs/ 下所有 markdown 的相对链接都要能解析。"""
    problems: list[str] = []
    for doc in DOCS.rglob("*.md"):
        for target in _local_links(doc.read_text(encoding="utf-8")):
            if not (doc.parent / target).exists():
                problems.append(f"{doc.relative_to(ROOT)} -> {target}")
    assert not problems, f"docs 中存在失效链接：{problems}"


def test_quality_gate_config_present() -> None:
    """四道质量门槛必须在 pyproject 中有对应配置，否则 CI 会跑空。"""
    config = _load_pyproject()
    tool = config["tool"]

    assert tool["ruff"]["line-length"] == 120
    assert "S110" in tool["ruff"]["lint"]["select"], "应启用静默异常检查"

    assert tool["mypy"]["strict"] is True
    assert tool["mypy"]["files"] == ["src/netguard"]

    assert tool["coverage"]["report"]["fail_under"] > 0
    assert tool["coverage"]["run"]["branch"] is True

    assert "addopts" in tool["pytest"]["ini_options"]


def test_dev_dependencies_declared() -> None:
    """开发工具必须在 dev 依赖组里声明，否则新环境无法复现门槛。"""
    dev = _load_pyproject()["project"]["optional-dependencies"]["dev"]
    joined = " ".join(dev)
    for tool_name in ("ruff", "mypy", "pytest", "pytest-cov", "pre-commit"):
        assert tool_name in joined, f"dev 依赖缺少 {tool_name}"


def test_test_extra_covers_ci_command() -> None:
    """CI 装的是 ``.[test]``，因此它用到的插件必须都在 test 组内。

    回归用例：pytest-cov 曾只声明在 dev 组，而 CI 以 ``.[test]`` 安装后直接
    执行 ``pytest --cov=...``，导致 6 个矩阵任务全部以
    "unrecognized arguments: --cov" 失败——本地装了 dev 依赖所以从未暴露。
    """
    config = _load_pyproject()
    extras = config["project"]["optional-dependencies"]
    test_joined = " ".join(extras["test"])

    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    assert "pytest-cov" in test_joined, "CI 使用 --cov，pytest-cov 必须在 test 组"
    assert "--cov" in workflow
    assert "[test]" in workflow, "CI 应以 .[test] 安装依赖"


def test_mypy_platform_is_pinned() -> None:
    """mypy 必须固定 platform，保证本地与 CI 结论一致。

    回归用例：gui/theme.py 用 winreg 探测系统深浅色（仅 Windows 存在）。
    未固定 platform 时 mypy 按宿主平台加载 typeshed，于是 Windows 本地通过、
    Linux CI 报 3 个 attr-defined，两边结论相反——本地验证无法预测 CI 结果。
    """
    mypy_config = _load_pyproject()["tool"]["mypy"]
    assert mypy_config.get("platform"), "mypy 未固定 platform：含平台条件导入的代码会导致本地与 CI 结论不一致"


def test_ci_workflow_runs_all_gates() -> None:
    """CI 必须实际执行 lint / 类型检查 / 测试 / 基准，而不是只做语法编译。"""
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    assert "ruff check" in workflow
    assert "ruff format --check" in workflow
    assert "mypy" in workflow
    assert "pytest" in workflow
    assert "--cov" in workflow
    assert "--fail-on-miss" in workflow, "benchmark 应作为检出质量门槛"


def test_py_typed_marker_shipped() -> None:
    """PEP 561 标记文件存在，且声明在 package-data 中。"""
    assert (ROOT / "src" / "netguard" / "py.typed").exists()
    data = _load_pyproject()["tool"]["setuptools"]["package-data"]
    assert "py.typed" in data["netguard"]


@pytest.mark.parametrize("script", ["launch.py", "benchmark.py", "build_unix_app.py"])
def test_scripts_present(script: str) -> None:
    assert (ROOT / "scripts" / script).is_file()
