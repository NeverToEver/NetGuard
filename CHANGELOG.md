# Changelog

本项目所有值得记录的变化都写在这里。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.2.0] - 2026-09-16

本轮主题是**工程化正式化**：不改动业务逻辑，补齐项目级工程配置、质量门槛、
CI 与发布流程，并修正文档中长期存在的相互矛盾。

### Added

- 工程配置：`pyproject.toml` 补 `license` / `authors` / `keywords` /
  `classifiers` / `[project.urls]` / `[project.scripts]`，新增 `dev` 依赖组。
- 类型可见性：新增 `py.typed`（PEP 561）。
- 质量门槛：接入 `ruff`（含 isort / bugbear / simplify / 静默异常规则）、
  `mypy --strict`、`pytest-cov` 覆盖率门槛（60%），并新增 `.pre-commit-config.yaml`。
- CI：`.github/workflows/tests.yml` 扩为 4 个任务——`lint`（ruff check +
  format check）、`typecheck`（mypy strict）、`pytest`（矩阵增加 macOS，
  并带覆盖率）、`benchmark`（启用 `--fail-on-miss` 作为检测质量门槛）。
- 发布：新增 `.github/workflows/release.yml`，`v*` tag 触发构建 sdist/wheel、
  校验 tag 与包版本一致、按 CHANGELOG 小节创建 GitHub Release。
- 文档：新增 `CHANGELOG.md`、`CONTRIBUTING.md`、`docs/README.md`（文档索引）。
- 元测试：`tests/test_version.py`（版本一致性）、`tests/test_project_metadata.py`
  （文档链接有效性）。
- `.editorconfig`，统一缩进/编码/换行（`.bat`/`.ps1` 为 CRLF、`.sh` 为 LF）。

### Changed

- **版本号收敛为单一来源**：新增 `netguard/_version.py`，`pyproject.toml` 改为
  `dynamic`，`scripts/build_unix_app.py` 的 `CFBundleVersion` 同步读取。
  此前 `0.1.0` 在 pyproject 与打包脚本中各硬编码一份。
- **全仓 ruff format 重排**（32 个文件，行宽 120）。
- 8 处静默 `except Exception: pass` 改为 `contextlib.suppress` 或记录日志，
  保留"退出清理 / 进度回调不应抛错"的原意。
- GUI 后台任务队列改为传递已绑定结果的零参回调，消除 6 处 `# type: ignore`。
- 文档修正：`README.md` 性能数据与基准产物对齐；`technical-report.md` /
  `experiment-workflow.md` 中关于已删除的 `dark_mode` / `_apply_theme` 的描述
  更新为当前 `gui/theme.py` 的 `ThemeManager` + `theme_mode` 模型；
  `README.md` / `usage.md` 补齐 ICMP flood 与 BruteForce 检测器说明。
- `审查报告/` 归入 `docs/reviews/`，统一仓库命名。
- `.vscode` 配置改为跨平台（原 `settings.json` 写死 Unix 解释器路径、
  `tasks.json` 调用 POSIX-only 脚本，在 Windows 上必然失败）。
- 文档语言：保持中文，补齐 README 徽章、mermaid 数据流图与界面截图。

### Fixed

- `rules/engine.py`：`rule` 变量先作 `str` 后作 `Rule` 复用造成遮蔽。
- `capture/source.py`：`enqueue_raw` 带关键字参数与返回值，签名与
  `capture_loop` 回调约定不符，已修正回调类型声明。
- `pcap_file.py` 时间戳小数部分多余的 `int()` 转换。

### Removed

- `docs/更新说明.md`（孤立文档，内容并入本文件）。
- `scripts/check_interpreter.sh`（功能由 `python scripts/launch.py --check` 覆盖）。

## [0.1.0]

课程设计阶段的功能集：抓包引擎（ctypes 绑定 libpcap/Npcap/WinPcap）、
离线 pcap 读写与回放、Ethernet→IPv4→TCP/UDP→HTTP/DNS/ICMP 解析、
类 Snort 规则引擎（含重组流回退匹配）、跨包时间窗口检测器
（SYN flood / 端口扫描 / DNS 隧道 / ICMP flood / 暴力破解）、
TCP 会话重组、滚动窗口速率统计、网段扫描与主机解析、
Tkinter 图形界面（包列表 / 协议详情 / 十六进制视图 / 告警 / 统计 / 明暗主题）、
macOS `.app` 与 Unix 便携包打包、跨平台一键启动脚本。

其中包含一轮界面与交付优化（原记录于已移除的 `docs/更新说明.md`）：

- 顶部工具栏拆分为「捕获设置区」与「操作区」两个稳定区域，解决窗口化时按钮
  被挤压显示不全的问题；按 Windows 可读名称与类型标签显示网卡并自动推荐主网卡。
- 运行方式统一为项目内 `.venv`，启动脚本自动探测解释器，不绑定某个本机发行版。
- macOS 打包兼容标准 venv 结构：通过目标解释器实际导入 Tkinter 判断支持情况，
  并复制 Tkinter / `_tkinter` / Tcl-Tk 资源到产物。

包含两轮全量代码审查修复（`docs/reviews/`）。
