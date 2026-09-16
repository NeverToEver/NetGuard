# 贡献指南

感谢参与 NetGuard。本文说明开发环境、质量门槛与提交规范。

## 开发环境

需要 **Python 3.11+**。仓库采用 src-layout，`pyproject.toml` 中已配置
`pythonpath = ["src"]` 与 `testpaths = ["tests"]`，因此不安装也能跑测试。

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Unix: source .venv/bin/activate
python -m pip install -e ".[dev]"
```

`dev` 依赖组包含 `pytest`、`pytest-cov`、`ruff`、`mypy`、`pre-commit`。

## 质量门槛

提交前请确保以下四条全部通过（CI 会逐条校验）：

```bash
python -m ruff check src tests scripts main.py    # 代码检查
python -m ruff format --check src tests scripts main.py  # 格式检查
python -m mypy                                    # 类型检查（strict）
python -m pytest tests/ --cov=netguard            # 测试 + 覆盖率门槛
```

覆盖率门槛 60%，配置在 `pyproject.toml` 的 `[tool.coverage.report]`。

安装 git 钩子后，`ruff` 与 `mypy` 会在每次提交前自动执行：

```bash
pre-commit install
```

## 代码约定

- **绝对导入**：`from netguard.parser.packet import ...`，不使用相对导入。
- **零运行时依赖**：运行时只允许标准库（`ctypes` / `tkinter`）。不要引入第三方
  运行时依赖；新增开发工具请加进 `[project.optional-dependencies].dev`。
- **时间可注入**：tracker / stats / engine / detectors 不要直接调用 `time.time()`，
  从 `netguard.clock` 取 `Clock`，测试会注入 mock 时钟。
- **解析不抛异常**：畸形包以 `ParseIssue` 记录，不得中断解析流程。
- **资源上限不可移除**：`MAX_EVENTS`、`max_sessions`、`max_protocols`、
  `_MAX_BPF_LENGTH`、检测器 `max_keys` / `max_samples` 都是有意的内存边界。
- **GUI 约定**：颜色一律来自 `gui/theme.py:build_colors()`，不要硬编码色值；
  快捷键绑定主窗口 `self.bind`（不要 `bind_all`）；对话框需 `center_on_parent`
  + `bind_dialog_keys` + `wire_dialog_theme`；耗时 I/O 走 `_run_in_background`。
- **测试不依赖环境**：测试必须能在无 libpcap、无 root、无显示器的环境下运行
  （GUI 冒烟用例通过 `pytest.importorskip` 与带超时的显示探测跳过；
  Linux CI 用 Xvfb 提供虚拟显示使其真正执行）。

详细架构说明见 [AGENTS.md](AGENTS.md) 与 [docs/technical-report.md](docs/technical-report.md)。

## 测试

```bash
python -m pytest tests/ -v                      # 全部
python -m pytest tests/test_parser.py -v        # 单文件
python -m pytest tests/ -k "syn_flood" -v       # 按名字筛选
```

新增功能请连同测试一起提交。修复 bug 时建议先写一个能复现该 bug 的失败用例，
再修复——这样门槛才有意义。

## 提交规范

提交信息使用 `<type>: <描述>` 形式，`type` 取以下之一：

| type | 含义 |
| --- | --- |
| `feat` | 新功能 |
| `fix` | 缺陷修复 |
| `docs` | 文档 |
| `style` | 格式化（不改变行为） |
| `refactor` | 重构（不改变行为） |
| `test` | 测试 |
| `chore` | 构建/工具链 |
| `ci` | CI 配置 |
| `perf` | 性能 |

描述用中文或英文均可，与仓库现有历史保持一致。正例如
`fix: 修复工具栏「夜间模式」开关无效`。

若改动影响用户可见行为，请在 `CHANGELOG.md` 的 `[Unreleased]` 下补一条。

## 文档

- 新增文档放 `docs/`，并在 `docs/README.md` 索引中登记。
- `README.md` 中的相对链接必须指向真实存在的文件（有测试校验：`tests/test_project_metadata.py`）。
- 中文文档使用中文标点；代码注释与文档保持一致语言。

## 已知不在范围内

以下项经确认不做，提 issue 前请先阅读 `docs/roadmap.md`：

- TLS 解密 / SNI / JA3 指纹识别
- IPv6 支持（当前仅解析 IPv4）
- 引入第三方运行时依赖
