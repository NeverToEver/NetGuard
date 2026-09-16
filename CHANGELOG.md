# Changelog

本项目所有值得记录的变化都写在这里。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Removed

- 一轮死代码清理（不做任何行为改动）：`NetGuardApp._load_config()` 与 `_on_busy()`、
  `SubnetScanDialog` 里只赋值不读取的 `_all_displays`（构造参数仍在用）、
  `CaptureSource.is_file_mode`（`replay_finished` 仍在读私有标志）、
  `ThemeManager.font_text`（私有 `_font_text` 仍参与配置 TkTextFont）、
  `PanelHeader.set_title()`、`StatCard` 的 `_colors` / `_unit` 两个只写属性。
  保留 `SubnetScanDialog` 的 `_ev_*` 处理函数与 `Clock.__call__`：前者由
  `_drain_events()` 按名字解析，后者是 Protocol 的调用签名，两者在静态引用里
  都查不到。

## [0.3.0] - 2026-09-17

本轮主题是**界面重构**：主窗口改为「应用外壳 + 工作区」两层结构，配色系统重做为三层
设计令牌，并补上自绘指标卡与解析树视图。重构之后又做了一轮代码审计，修掉了随之
引入的交互缺陷与状态残留（见下方 Fixed 的后半部分）。

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
- **列宽预算收敛到最小窗口之内**：数据包列表默认列宽 870 → 700px、
  检视面板 390 → 332px。两组默认列宽之和必须让 1280×760 的最小窗口放得下，
  否则最小尺寸下网格会把最右侧内容排到窗口外；窗口尺寸也收敛为
  `_DEFAULT_WINDOW_SIZE` / `MIN_WINDOW_SIZE` 两个常量，由测试守住这条预算。
- 导出告警的 JSON 与文本两种格式改为从同一份快照写出：此前文本走告警表，
  受表格 1000 行上限与用户排序影响，同一批数据的两种格式条数会不一致。

### Fixed

- **窗口超出屏幕**：恢复窗口几何时只钳制位置、不钳制尺寸，在 2560 宽屏上保存的
  `2228x1147` 搬到 2048 宽的屏幕上会把窗口右半边连操作按钮一起推到屏幕外。
- **主区域塌陷**：`ttk.PanedWindow.sashpos()` 在窗口完成首次布局前调用会被钳制到 0，
  主区域高度变成 1px。改为先 `update_idletasks()` 并在未成形时有限次重试；
  分隔条默认位置也改按窗格自身尺寸计算，并给两侧保留最小尺寸。
- **界面最小宽度虚高**：`tk.Text` 默认 80 字符宽、`tk.Canvas` 默认约 378px，
  把窗口的请求宽度推到 2558px，1600 宽的窗口右侧内容被裁掉。填充式文本域与走势图
  改为 `width=1` 后请求宽度回到内容本身决定的量级（1369px）。
  注意剩余宽度仍可能大于最小窗口宽度（网卡下拉框按设备名长度自适应），
  真正保证内容不被裁的是下面的分隔条回收与列宽预算，不是请求宽度本身。
- **日志条不显示内容**：日志以换行结尾，`see(END)` 停在最后一个空行上，
  单行模式因此看不到任何日志。审计时发现当时改成的 `see("end-1c")` 只是让可视区
  落在最后一条的**下半截**上：Text 末尾的换行会多出一条空显示行，滚到底部看到的是
  那条空行。现在行间换行写在下一条之前（末尾不留换行）并直接滚到底，
  单行模式完整显示最新一条；单行时也不再纵向拉伸文本域（拉伸会露出上一行的下半截）。
- **双击解析问题报错**：改写跳转逻辑时残留了旧实现的三行，`iid` 未定义，
  每次双击都会 `NameError`。
- 日志条的「展开」按钮在 30px 高的栏里被压扁截字，改用低内边距的 `Tiny.TButton`。

审计（重构后复查）修掉的问题：

- **文本框内 `Ctrl+O` 完全失效**：为屏蔽 Tk `Text` 的默认换行，三个文本框上加了
  控件级绑定并直接返回 `"break"`。但控件级绑定先于主窗口绑定执行，`break` 会把
  主窗口的「打开 pcap」一并吃掉，按下去什么都不发生。改为在控件级先执行打开动作、
  再返回 `"break"`。
- **清空数据后告警计数不归零**：标签页标题的计数只在插入告警时刷新过，Ctrl+L
  清空后表格已空而标题仍是「告警（N）」。现在清空、裁剪后都重算标题；
  「解析问题」标签页同样不再依赖下一轮统计刷新。
- **缩窄窗口把检视面板压成一条缝**：`ttk.PanedWindow` 的分隔条位置是绝对值，
  窗口变窄时不会自动回退——在宽窗口上定位后缩到最小尺寸，检视面板实测只剩 272px，
  而它要显示「字段 + 值」两列需要 344px，值列整列被裁掉。现在窗格尺寸变化后按当前
  尺寸重新钳制分隔条，尾部下限取「尾部窗格自身请求尺寸」，用户把检视列拖宽后同样不会再被裁。
- **操作轨分隔线从未显示**：操作轨与内容区之间的 1px 竖线被 grid 放在与内容帧
  同一个单元格里，`sticky="ns"` 让它停在格子中间，后创建的内容帧把它整块盖住。
  改为独占一列。
- **批量告警插入是 O(n²)**：斑马纹的奇偶对每一行都调用一次
  `Treeview.get_children()`（一次 Tcl 往返 + 返回全部行号），告警爆发时开销随行数
  平方增长。改为插入前只取一次行数。
- **检视面板空状态提示被截断**：解析树单元格不换行，而值列宽 200px，
  「在数据包列表中点选任意一行，这里会显示逐层协议字段。」这样的句子被截成半句——
  这恰好是新用户看到的第一屏。空状态文案收敛到 10 个汉字以内。
  另外「字段」列 150 → 132px、值列 240 → 200px 并入了最小窗口的列宽预算，
  提示语长度由用例按真实字体度量守住。

### Removed

- 重构后失去作用的状态：`packet_count_var`（旧指标行的 StringVar，标签已移除）、
  `alert_packet_indices` / `_error_packet_indices`（跳转改由行 iid 编码包索引后
  不再被读取，且用户排序告警表时会与表格失去同步）、`alerts_placeholder`
  （占位行已不存在，标志恒等于「告警表为空」）、`_panels` / `_body_frames` /
  `_inspector_tabs`，以及随工具栏「夜间模式」复选框一起下线的
  `_toggle_night_mode()`。

### Added

- `tests/test_gui_view_models.py`：行构造、协议解析树、十六进制分行、时间格式的纯函数测试。
- `tests/test_gui_layout.py`：窗口几何钳制与分隔条钳制的回归测试。
- `tests/test_gui_theme.py` 补充设计令牌、`mix()`、结构化严重度与协议配色的用例。
- `tests/test_gui_state.py` 补充告警行标签、行 iid 编码、跳转定位、解析树层级等用例。
- `tests/test_gui_smoke.py` 补充真窗口的不变量用例：最小尺寸下最右侧控件不出窗口、
  缩窄窗口后分隔条必须回收、操作轨分隔线独占一列、`Ctrl+O` 在文本框内仍能打开文件。

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
