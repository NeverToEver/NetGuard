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


#: 不参与文档校验的目录：构建/缓存产物与本地 scratch（tmp/ 在 .gitignore 内）
_IGNORED_DIRS = {".git", "__pycache__", "tmp", "build", "dist", "output", ".venv", ".mypy_cache", ".pytest_cache"}


def _published_docs() -> list[Path]:
    """会被发布的 markdown：排除构建产物与本地 scratch 目录。"""
    docs: list[Path] = []
    for doc in ROOT.rglob("*.md"):
        if any(part in _IGNORED_DIRS for part in doc.relative_to(ROOT).parts):
            continue
        docs.append(doc)
    return sorted(docs)


def _all_repo_paths() -> set[str]:
    """仓库内所有文件的 POSIX 相对路径（大小写原样保留，排除构建/scratch）。"""
    paths: set[str] = set()
    for path in ROOT.rglob("*"):
        parts = path.relative_to(ROOT).parts
        if any(part in _IGNORED_DIRS for part in parts):
            continue
        paths.add(path.relative_to(ROOT).as_posix())
    return paths


def _normalized_link(doc: Path, target: str) -> str:
    """把链接目标归一化为仓库相对路径（处理 ./ 与 ../）。

    doc 与 ROOT 都是绝对路径，因此先取相对 ROOT 的部分，结果才能与
    _all_repo_paths() 的返回值直接比较。
    """
    base = doc.parent.relative_to(ROOT)
    parts: list[str] = []
    for segment in (base / target).as_posix().split("/"):
        if segment == "..":
            if parts:
                parts.pop()
        elif segment not in (".", ""):
            parts.append(segment)
    return "/".join(parts)


def _case_sensitive_link_problems() -> list[str]:
    """逐份文档校验相对链接，且区分大小写。

    不能用 Path.exists()：Windows 文件系统不区分大小写，`Docs/README.md`
    这类错误在本地"存在"，到了 Linux CI 才变成 404。这里与真实的仓库路径
    集合做精确比对，使该类问题在本地即可发现。
    """
    real = _all_repo_paths()
    problems: list[str] = []
    for doc in _published_docs():
        for target in _local_links(doc.read_text(encoding="utf-8")):
            resolved = _normalized_link(doc, target)
            if resolved not in real:
                problems.append(f"{doc.relative_to(ROOT).as_posix()} -> {target}")
    return problems


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


def test_all_document_links_are_case_sensitive_valid() -> None:
    """全仓 markdown 链接必须大小写精确匹配。

    回归用例：CONTRIBUTING.md 曾写作 `[docs/technical-report.md](technical-report.md)`
    （链接文本有 docs/、目标没有），在区分大小写的 Linux 上是死链；
    修正前本项目在 Ubuntu CI 与本地 Windows 上表现不一致。
    """
    problems = _case_sensitive_link_problems()
    assert not problems, f"存在大小写或路径不匹配的链接：{problems}"


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
