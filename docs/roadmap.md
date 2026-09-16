# NetGuard 后续工作路线图

本文件记录截至当前尚未完成、或有意留待后续处理的工作，供后续开发（含 ZCode
agents）接手。按优先级与主题分组；每项给出背景、现状与建议做法。

约定：
- **[P0]** 影响正确性或可信度，应优先处理。
- **[P1]** 重要改进，收益明显。
- **[P2]** 锦上添花 / 较大工程。
- 明确**不做**的项目单列在最后，避免重复讨论。

---

## A. 检测与 IDS 能力

- [x] **[P0] 规则匹配二级索引（性能）** ✅ 已完成
  `RuleEngine` 索引改为 `{协议: {端口: 规则}}` 二级结构，匹配时只取数据包
  src_port/dst_port 命中桶与 `any` 桶；500 条规则时单包匹配中位从 ~247 µs
  降至 ~1.5 µs（P99 ~3 µs）。

- [ ] **[P1] 规则语法扩展**
  现状：仅支持 `protocol / src / src_port / direction / dst / dst_port / content / msg`。
  建议：逐步加入 `offset`、`depth`、`flags`、`threshold`（时间窗口频率）、
  `sid`/`rev` 等 Snort 风格选项；注意保持现有语法的向后兼容与 `load()` 返回失败计数的契约。

- [ ] **[P1] 双向会话重组与请求/响应对**
  现状：`SessionTracker` 以 4 元组 `(src, src_port, dst, dst_port)` 为键，单向缓冲。
  建议：维护双向流索引，配对同一条 TCP 连接的 HTTP 请求与响应，供规则与界面按
  事务维度展示；注意 `max_sessions`/`max_stream_bytes` 上限与内存。

- [x] **[P1] 更多攻击检测器** ✅ 部分完成
  已有：SYN flood、端口扫描、DNS 隧道、**ICMP flood、暴力破解**（SSH/FTP/Telnet
  等服务端口的窗口内高频 SYN）。候选剩余：ARP 欺骗/中间人、DNS DGA 域名、
  异常大流量。新增检测器须遵循 `Detector` 协议、注入 `Clock`、窗口有界
  （`max_samples`）、阈值可配置，并补阈值/窗口/误报测试。

- [ ] **[P2] pcapng 读写**
  现状：`capture/pcap_file.py` 仅支持经典 pcap（不支持 pcapng）。
  建议：新增 pcapng（多个 Section/Interface Block）解析；Keep classic pcap as the
  default writer。

- [ ] **[P2] 告警抑制与分级策略**
  同一攻击在短时间内的重复告警目前靠检测器内部去重；可进一步做全局告警抑制
  （同源同类型 N 秒内仅一次）与基于严重度的展示/导出分级。

---

## B. 协议与数据面

- [x] **[P1] 非标准端口协议识别** ✅ 已完成
  端口仍是快速路径；端口不命中时按内容探测：TCP 载荷首行匹配 HTTP 方法/状态行
  即按 HTTP 解析，UDP 载荷通过 DNS 结构校验（标志位/qdcount/标签以 0 终止）
  即按 DNS 解析。

- [ ] **[P1] IPv4 分片重组**
  现状：`parser/packet.py` 对非首片仅标记 `fragment_offset` 与摘要，不重组。
  建议：在会话/流层按 `(src, dst, ip_id, proto)` 重组分片后再交付上层解析，用于
  检出分片规避。

- [ ] **[P2] 明文应用协议解析**
  现状：仅 HTTP/DNS；TLS 加密流量不解析（见"明确不做"）。
  建议：补充 SMTP/FTP/Telnet 等的简单解析与明文口令检测（IDS 场景价值高）。

---

## C. 界面（GUI）

- [ ] **[P1] 拆分 `gui/main_ui.py`**
  现状：主窗口 + 4 个对话框集中在一个约 2500 行的文件。
  建议：按职责拆为菜单/工具栏、数据表格、详情视图、对话框、后台任务、状态栏等模块，
  保持公共入口 `run_gui()` 与 `NetGuardApp` 不变。

- [x] **[P1] 表格列宽自适应** ✅ 已完成
  表格右键菜单新增"自适应列宽"，双击表头分隔线也可触发；宽度按当前行内容计算
  并持久化到 `AppConfig`。

- [ ] **[P1] 大结果集虚拟滚动**
  现状：表格上限 `MAX_TABLE_ROWS = 5000`，超出即裁剪最旧行。
  建议：改为按可见区间增量渲染（虚拟列表），以支持更大规模查看而不丢数据。

- [ ] **[P2] 显示过滤高亮**
  在预览表与详情中高亮当前显示过滤的匹配文本。

- [ ] **[P2] 列显隐/顺序自定义并持久化**
  允许用户勾选显示哪些列、拖动列顺序，写入 `AppConfig`。

- [x] **[P2] 导出为 CSV** ✅ 已完成
  文件菜单与表格右键菜单新增"导出数据包 CSV…"，按当前显示过滤导出，
  后台线程写盘（utf-8-sig，Excel 可直接打开）。

- [ ] **[P2] 抓包状态视觉反馈**
  长时间抓包时可加轻量动态指示；注意保持零依赖与不阻塞 UI。

---

## D. 工程、测试与交付

- [x] **[P0] `PcapBackend` 单元测试** ✅ 已完成
  `tests/test_pcap_backend.py` 用 mock CDLL 覆盖符号校验、设备枚举（含释放）、
  打开/关闭、BPF 长度上限与编译失败、抓包循环（回调/超时/EOF/错误/停止）。
  真机抓包仍留作手工验证。

- [ ] **[P1] GUI 交互测试覆盖提升**
  现状：`tests/test_gui_smoke.py` 覆盖窗口/主题/排序/过滤/后台任务；多数对话框与
  表格右键、状态记忆路径仍缺测试。GUI 测试须在无显示环境自动跳过。

- [ ] **[P1] Windows 打包**
  现状：`scripts/build_unix_app.py` 仅面向 Unix/macOS。
  建议：新增 Windows 打包（PyInstaller 或嵌入运行时），在 `docs/install-windows.md`
  补充说明。

- [x] **[P1] CI 增强** ✅ 已完成
  已完成：`ruff check` + `ruff format --check`、`mypy --strict`、覆盖率门槛、
  矩阵补 macos-latest，benchmark 启用 `--fail-on-miss` 作为检出质量门槛。

- [x] **[P2] 覆盖率与质量门槛** ✅ 已完成
  已启用 `pytest-cov`（`branch = true`），全局门槛 60%（当前实测约 61%）。
  按模块的更高门槛仍可后续细分。

- [x] **[P2] 版本与发布流程** ✅ 已完成
  已有 `CHANGELOG.md`（Keep a Changelog）、版本单一来源 `_version.py`、
  `release.yml`（tag 触发构建 + 校验版本一致 + 创建 Release）。

- [ ] **[P2] macOS 签名/公证文档**
  分发 `.app` 时需要 codesign/notarization；`build_unix_app.py` 已有 codesign 调用，
  补充完整签名流程文档。

---

## E. 文档

- [x] **[P1] README 增加架构图与截图** ✅ 已完成
  已补 mermaid 数据流图、浅色/深色界面截图（`docs/images/`）、CI 徽章。
- [ ] **[P2] 中英双语/英文文档**
  便于外部评审与展示。
- [ ] **[P2] 静态检查规则扩展**
  当前启用 E/W/F/I/N/UP/B/C4/SIM/RET/PIE/RUF/S110/S112。可后续评估
  `ARG`（未使用参数）、`PTH`（os.path 迁移）、`D`（docstring 覆盖率）；
  本次刻意未启用以免 diff 失焦。

---

## 明确暂不实现（已与需求方确认）

- **TLS 解密 / SNI / JA3 指纹**：项目定位为仿 Wireshark 的基础功能，不做 HTTPS
  解密或加密流量指纹识别。
- **IPv6**：当前仅解析 IPv4（`ethertype 0x0800`）。如需支持需成套改动解析器、
  会话键与界面，暂缓。

---

## 已知限制

以下为能力边界而非待办事项，部署与评估时需纳入考虑：

- 基准数据来自合成流量（`netguard.trafficgen`），为内存态用户处理上限，不含真实
  内核抓包开销；真实丢包率未实测（需 Npcap/root）。
- 规则匹配已按协议+端口二级索引，但同一端口桶内命中大量规则时仍会退化为桶内
  全扫（见 A 组 P0）。
- 会话流内存上限：`max_stream_bytes=2MB` × `max_sessions=10000`，理论峰值较大，需
  结合部署环境调参。
- 仅解析 IPv4，不支持 IPv6；TLS 加密流量不做解密与指纹识别（见「明确暂不实现」）。
