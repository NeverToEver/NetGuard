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

- [ ] **[P0] 规则匹配二级索引（性能）**
  现状：`RuleEngine` 只按协议（TCP/UDP/HTTP/DNS/ANY）分桶，同协议规则需逐条匹配。
  基准显示 500 条同协议规则时单包匹配中位约 247 µs、P99 约 589 µs（见
  `docs/benchmark.md`）。
  建议：在协议桶内再按目的端口（及 `any` 桶）建二级索引，匹配时只取端口命中
  与端口通配的规则，降低候选集。

- [ ] **[P1] 规则语法扩展**
  现状：仅支持 `protocol / src / src_port / direction / dst / dst_port / content / msg`。
  建议：逐步加入 `offset`、`depth`、`flags`、`threshold`（时间窗口频率）、
  `sid`/`rev` 等 Snort 风格选项；注意保持现有语法的向后兼容与 `load()` 返回失败计数的契约。

- [ ] **[P1] 双向会话重组与请求/响应对**
  现状：`SessionTracker` 以 4 元组 `(src, src_port, dst, dst_port)` 为键，单向缓冲。
  建议：维护双向流索引，配对同一条 TCP 连接的 HTTP 请求与响应，供规则与界面按
  事务维度展示；注意 `max_sessions`/`max_stream_bytes` 上限与内存。

- [ ] **[P1] 更多攻击检测器**
  已有：SYN flood、端口扫描、DNS 隧道（`src/netguard/detection/detectors.py`）。
  候选：ARP 欺骗/中间人、SSH/FTP 暴力破解、ICMP flood、DNS DGA 域名、异常大流量/
  非常规端口。新增时遵循 `Detector` 协议、注入 `Clock`、窗口有界（`max_samples`）、
  阈值可配置，并补阈值/窗口/误报测试。

- [ ] **[P2] pcapng 读写**
  现状：`capture/pcap_file.py` 仅支持经典 pcap（不支持 pcapng）。
  建议：新增 pcapng（多个 Section/Interface Block）解析；Keep classic pcap as the
  default writer。

- [ ] **[P2] 告警抑制与分级策略**
  同一攻击在短时间内的重复告警目前靠检测器内部去重；可进一步做全局告警抑制
  （同源同类型 N 秒内仅一次）与基于严重度的展示/导出分级。

---

## B. 协议与数据面

- [ ] **[P1] 非标准端口协议识别**
  现状：HTTP/DNS 依赖固定端口（`HTTP_PORTS`、53）。非标准端口无法识别。
  建议：增加基于内容的协议探测（首行/魔数）作为端口判断的补充，保留端口作为快速路径。

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

- [ ] **[P1] 表格列宽自适应**
  现状：列宽固定初始值，用户手改后会持久化，但不会按内容自适应。
  建议：双击表头分隔线按内容计算列宽，或提供"自适应列宽"菜单项。

- [ ] **[P1] 大结果集虚拟滚动**
  现状：表格上限 `MAX_TABLE_ROWS = 5000`，超出即裁剪最旧行。
  建议：改为按可见区间增量渲染（虚拟列表），以支持更大规模查看而不丢数据。

- [ ] **[P2] 显示过滤高亮**
  在预览表与详情中高亮当前显示过滤的匹配文本。

- [ ] **[P2] 列显隐/顺序自定义并持久化**
  允许用户勾选显示哪些列、拖动列顺序，写入 `AppConfig`。

- [ ] **[P2] 导出为 CSV/文本**
  现状：仅支持保存 pcap 与导出告警（JSON/文本）。补充数据包表格导出为 CSV。

- [ ] **[P2] 抓包状态视觉反馈**
  长时间抓包时可加轻量动态指示；注意保持零依赖与不阻塞 UI。

---

## D. 工程、测试与交付

- [ ] **[P0] `PcapBackend` 单元测试**
  现状：真实 pcap 链路（`capture/pcap.py`）零测试；`ctypes` 结构体与 `timeval`
  平台差异、BPF 编译失败等路径都未覆盖。
  建议：mock `ctypes.CDLL`（`PcapBackend(library=...)` 已支持注入）覆盖枚举、打开、
  过滤、错误分支；真机抓包仍留作手工验证。

- [ ] **[P1] GUI 交互测试覆盖提升**
  现状：`tests/test_gui_smoke.py` 覆盖窗口/主题/排序/过滤/后台任务；多数对话框与
  表格右键、状态记忆路径仍缺测试。GUI 测试须在无显示环境自动跳过。

- [ ] **[P1] Windows 打包**
  现状：`scripts/build_unix_app.py` 仅面向 Unix/macOS。
  建议：新增 Windows 打包（PyInstaller 或嵌入运行时），在 `docs/install-windows.md`
  补充说明。

- [ ] **[P1] CI 增强**
  已有：GitHub Actions 在 Ubuntu/Windows × Python 3.11/3.12 跑测试。
  建议：加入 `mypy` 类型检查与覆盖率统计（并可设最低阈值门槛）。

- [ ] **[P2] 覆盖率与质量门槛**
  生成覆盖率报告，逐步为 `parser`、`rules`、`detection` 设定门槛。

- [ ] **[P2] 版本与发布流程**
  维护 CHANGELOG、打 tag、产出 Release 说明与构建产物。

- [ ] **[P2] macOS 签名/公证文档**
  分发 `.app` 时需要 codesign/notarization；`build_unix_app.py` 已有 codesign 调用，
  补充完整签名流程文档。

---

## E. 文档

- [ ] **[P1] README 增加架构图与截图**
  现状：仅有文字与代码块架构说明。建议补 mermaid 数据流图与界面截图/GIF。
- [ ] **[P2] 中英双语/英文文档**
  便于外部评审与展示。

---

## 明确暂不实现（已与需求方确认）

- **TLS 解密 / SNI / JA3 指纹**：项目定位为仿 Wireshark 的基础功能，不做 HTTPS
  解密或加密流量指纹识别。
- **IPv6**：当前仅解析 IPv4（`ethertype 0x0800`）。如需支持需成套改动解析器、
  会话键与界面，暂缓。

---

## 已知限制（非待办，供说明与答辩参考）

- 基准数据来自合成流量（`netguard.trafficgen`），为内存态用户处理上限，不含真实
  内核抓包开销；真实丢包率未实测（需 Npcap/root）。
- 规则匹配为按协议全量扫描（见 A 组 P0）。
- 会话流内存上限：`max_stream_bytes=2MB` × `max_sessions=10000`，理论峰值较大，需
  结合部署环境调参。
