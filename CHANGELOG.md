# Changelog

本项目所有值得记录的变化都写在这里。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Changed

- **界面整体重构**：主窗口改为「应用外壳 + 工作区」两层结构。
  - 新增顶栏（品牌、抓包状态胶囊、主题循环按钮）与左侧操作轨，把开始/停止/暂停/清空、
    打开/保存 pcap、导出告警、发包、扫描、规则这些高频动作从原来的三行按钮堆里移出来；
    按钮样式随抓包状态变化（抓包中时「停止」转为主操作色，暂停时「暂停」转为琥珀色）。
  - 新增 KPI 指标条：数据包总数、包速率、吞吐量、活动会话、IDS 告警五张指标卡，
    各带 Canvas 自绘的迷你走势图；告警卡以红色竖条与红色数字突出。
  - 数据包详情由纯文本堆砌改为**逐层协议解析树**（帧 → 链路层 → 网络层 → 传输层 → 应用层），
    前两层默认展开；十六进制视图按偏移 / 字节 / ASCII 三段分色，超过 4KB 截断显示。
  - 原来「详情 + 原始字节」的纵向分栏、以及并排挤在一起的「告警 / 解析问题 / 统计 / 规则」
    改为标签页：底部区域同一块高度只服务一个视图，标签标题带实时计数。
  - 告警与解析问题由 Listbox 换成 Treeview：可按时间 / 级别 / 来源排序，按严重度着色，
    并区分内置检测器告警与 IDS 规则命中。
- **配色系统重做**：`gui/theme.py` 的颜色改为三层令牌（原始令牌 / 派生语义色 / 历史别名），
  新增 `mix()` 用于派生悬停态与选中底纹，协议配色集中到 `proto_*` 令牌；
  `gui/widgets.py` 新增 `StatCard` / `Sparkline` / `StatusPill` / `PanelHeader` 四个自绘控件。
- 告警严重度改为采信结构化的 `Alert.severity`（`theme.severity_key()`），
  不再靠消息关键字猜测；`severity_color()` 降级为字段缺失时的回退。
- 数据包列表与告警表的时间列显示为 `HH:MM:SS.mmm`，不再直接打印 Unix 秒数。
- 默认窗口最小尺寸由 1180×720 调整为 1280×760，以适配并排的检视面板。

### Fixed

- **窗口超出屏幕**：恢复窗口几何时只钳制位置、不钳制尺寸，在 2560 宽屏上保存的
  `2228x1147` 搬到 2048 宽的屏幕上会把窗口右半边连操作按钮一起推到屏幕外。
- **主区域塌陷**：`ttk.PanedWindow.sashpos()` 在窗口完成首次布局前调用会被钳制到 0，
  主区域高度变成 1px。改为先 `update_idletasks()` 并在未成形时有限次重试；
  分隔条默认位置也改按窗格自身尺寸计算，并给两侧保留最小尺寸。
- **界面最小宽度虚高**：`tk.Text` 默认 80 字符宽、`tk.Canvas` 默认约 378px，
  把窗口的请求宽度推到 2558px，1600 宽的窗口右侧内容被裁掉。填充式文本域与走势图
  改为 `width=1` 后请求宽度降到 1369px。
- **日志条不显示内容**：日志以换行结尾，`see(END)` 停在最后一个空行上，
  单行模式因此看不到任何日志；改为 `see("end-1c")`。
- **双击解析问题报错**：改写跳转逻辑时残留了旧实现的三行，`iid` 未定义，
  每次双击都会 `NameError`。
- 日志条的「展开」按钮在 30px 高的栏里被压扁截字，改用低内边距的 `Tiny.TButton`。

### Added

- `tests/test_gui_view_models.py`：行构造、协议解析树、十六进制分行、时间格式的纯函数测试。
- `tests/test_gui_layout.py`：窗口几何钳制与分隔条钳制的回归测试。
- `tests/test_gui_theme.py` 补充设计令牌、`mix()`、结构化严重度与协议配色的用例。
- `tests/test_gui_state.py` 补充告警行标签、行 iid 编码、跳转定位、解析树层级等用例。

## [0.2.0] - 2026-09-16

本轮主题是**工程化正式化**：不改动业务逻辑，补齐项目级工程配置、质量门槛、
CI 与发布流程，修正文档中长期存在的相互矛盾，并把示例数据转为可复现的正式资产。

### Added

- `docs/samples/sample.pcap` 与生成脚本 `scripts/build_sample_pcap.py`：可复现的
  离线演示样本，含正常流量、端口扫描、SYN flood 与畸形包四个场景。
- `docs/troubleshooting.md`：抓包、显示、检测、运行环境的排障指南。
- `tests/test_sample_pcap.py`：校验样本可复现、可解析，确实触发文档承诺的检出，
  并强制已提交样本与当前脚本产物字节一致（防样本漂移）。
- `netguard.trafficgen` 公开底层构造器（`build_ethernet` / `build_ipv4` /
  `build_tcp` / `build_udp` / `build_dns_query` / `build_dns_response`）与
  `__all__`，供样本生成与基准复用。
- README 新增「使用边界」章节，说明授权范围与敏感数据处理要求。

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
- 文档修正：`README.md` 性能数据与基准产物对齐；`technical-report.md` 中关于
  已删除的 `dark_mode` / `_apply_theme` 的描述更新为当前 `gui/theme.py` 的
  `ThemeManager` + `theme_mode` 模型；
  `README.md` / `usage.md` 补齐 ICMP flood 与 BruteForce 检测器说明。
- `审查报告/` 归入 `docs/reviews/`，统一仓库命名。
- `.vscode` 配置改为跨平台（原 `settings.json` 写死 Unix 解释器路径、
  `tasks.json` 调用 POSIX-only 脚本，在 Windows 上必然失败）。
- 文档语言：保持中文，补齐 README 徽章、mermaid 数据流图与界面截图。
- `scripts/benchmark.py` 改用 `trafficgen` 的公开构造器，删除约 40 行重复手写的
  原始包字节拼接；示例样本生成从一次性临时脚本转为受测试保护的正式脚本。

### Fixed

- **告警列表非空时切换主题崩溃**：`_refresh_alert_colors` 用
  `Listbox.get(index, index)`（双参数返回元组）喂给 `severity_color`，
  触发 `AttributeError` 并中断主题切换。已修并补回归用例。
- **`pip install -e .` 失败**：pyproject 同时声明 PEP 639 license 表达式与旧式
  `License :: OSI Approved :: MIT License` 分类器，setuptools 拒绝该组合。
- `rules/engine.py`：`rule` 变量先作 `str` 后作 `Rule` 复用造成遮蔽。
- `capture/source.py`：`enqueue_raw` 带关键字参数与返回值，签名与
  `capture_loop` 回调约定不符，已修正回调类型声明。
- `pcap_file.py` 时间戳小数部分多余的 `int()` 转换。

### Removed

- `docs/lab-demo.md`、`docs/experiment-workflow.md`（课堂演示稿与实验验收流程）。
  排障内容整理进 `docs/troubleshooting.md`，授权说明并入 README。
- `docs/更新说明.md`（孤立文档，内容并入本文件）。
- `scripts/check_interpreter.sh`（功能由 `python scripts/launch.py --check` 覆盖）。

## [0.1.0]

首个功能完整版本：抓包引擎（ctypes 绑定 libpcap/Npcap/WinPcap）、
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
