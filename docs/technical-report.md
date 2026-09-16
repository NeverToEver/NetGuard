# NetGuard 技术报告

## 1. 项目概述

NetGuard 是一个参考 Wireshark 工作方式设计的跨平台网络监听与轻量 IDS 工具。项目使用 Python 3.11+ 开发，通过 `ctypes` 直接调用系统原生抓包库：macOS/Linux 使用 `libpcap`，Windows 使用 Npcap/WinPcap 的 `wpcap.dll` 接口。

项目目标是在授权实验环境中完成网络接口枚举、BPF 过滤、数据包捕获、协议解析、会话统计、IDS 规则匹配和图形化展示，帮助用户理解不同平台下网络抓包的工作方式。

## 2. 运行环境与跨平台依赖

NetGuard 的核心依赖来自操作系统提供的抓包能力。

| 平台 | 抓包接口 | 常见设备名 | 运行要求 |
| --- | --- | --- | --- |
| macOS | libpcap / BPF | `en0`, `en1`, `lo0` | 通常需要 `sudo` 或 BPF 权限 |
| Linux | libpcap | `eth0`, `wlan0`, `lo` | 通常需要 root 或 capture capability |
| Windows | Npcap / WinPcap | `\Device\NPF_{GUID}` | 安装 Npcap，必要时管理员运行 |

Windows 与 macOS 的接口命名机制不同。macOS 使用 BSD 风格接口名，例如 `en0` 通常代表默认无线或主要物理网卡；Windows Npcap 返回的是设备路径和 GUID，例如 `\Device\NPF_{...}`。因此 Windows 不会原生出现 `en0`，项目通过可读名称、类型标签与自动推荐来帮助选择接口（见第 5 节）。

## 3. 系统架构

项目采用分层结构，主要模块如下：

| 模块 | 路径 | 职责 |
| --- | --- | --- |
| 启动入口 | `main.py`, `src/netguard/app.py` | 命令行参数处理、GUI/控制台模式启动 |
| 抓包后端 | `src/netguard/capture/pcap.py` | 加载 pcap 库、枚举设备、打开网卡、设置 BPF、读取原始包 |
| 接口映射 | `src/netguard/capture/interface_mapping.py` | 生成跨平台网卡显示名、类型标签与自动推荐 |
| 数据管线 | `src/netguard/pipeline.py` | 捕获线程、解析线程、事件队列、统计与告警分发 |
| 协议解析 | `src/netguard/parser/packet.py` | Ethernet、IPv4、TCP、UDP、HTTP、DNS 解析 |
| IDS 规则 | `src/netguard/rules/engine.py` | 简化规则加载与匹配 |
| 会话跟踪 | `src/netguard/session/tracker.py` | TCP 会话记录、重组与超时清理 |
| 流量统计 | `src/netguard/statistics/traffic_stats.py` | 包数、字节数、协议分布、速率统计 |
| 图形界面 | `src/netguard/gui/main_ui.py` | 网卡选择、BPF 输入、包列表、检视面板（解析树 / 原始字节）、告警、统计与明暗主题 |

整体数据流如下：

```text
pcap/Npcap 原始包
  -> Capture Backend
  -> RawPacket Queue
  -> Packet Parser
  -> Session Tracker / Traffic Stats / Rule Engine
  -> GUI Event Queue
  -> 包列表、协议详情、告警、统计面板
```

## 4. 抓包后端设计

`PcapBackend` 是项目的底层抓包封装。它根据当前操作系统加载不同候选库：

- Windows：`wpcap.dll`, `Packet.dll`
- macOS：`libpcap.dylib`
- Linux：`libpcap.so.1`, `libpcap.so`

后端通过 `pcap_findalldevs()` 枚举设备，通过 `pcap_open_live()` 打开接口，并在用户填写 BPF 时调用 `pcap_compile()` 和 `pcap_setfilter()` 设置内核层过滤条件。捕获循环使用 `pcap_next_ex()` 读取数据包，再封装为 `RawPacket` 交给上层管线。

这种设计避免了对第三方 Python 抓包库的强依赖，也能更清楚地展示 libpcap/Npcap 的原生工作方式。

## 5. Windows 接口适配

### 5.1 问题背景

macOS 上通常选择 `en0` 完成抓包，但 Windows 上只能看到 Npcap 设备路径，例如：

```text
\Device\NPF_{0AFD3ED9-02C8-0811-124D-1682118B6574}
```

这不是程序错误，而是平台接口命名方式不同。为了保持接近 Wireshark 的操作体验，
NetGuard 在界面中为每个网卡显示可读名称、类型标签，并自动推荐最可能联网的网卡。

### 5.2 网卡显示与分类规则

`capture/interface_mapping.py` 按平台生成显示信息。Windows 下先识别类型，再给出中文标签：

| Windows 网卡类型（按名称/描述匹配） | 标签 |
| --- | --- |
| Loopback / Npcap Loopback Adapter | 回环接口 |
| Hyper-V / VMware / VirtualBox / Virtual / VPN / Tap / Tunnel | 虚拟/VPN 接口 |
| Wi-Fi / Wireless / WLAN / 802.11 | 无线网卡 |
| Ethernet / Gigabit / Realtek / Intel(R) Ethernet / LAN | 有线网卡 |
| 其他 | 可用抓包接口 |

注意：虚拟/VPN 判断优先于有线判断，避免 “VMware Virtual Ethernet Adapter” 被误判为有线网卡。

界面显示示例：

```text
Wi-Fi 6 Adapter
Intel(R) Ethernet Connection I219-V
VMware Virtual Ethernet Adapter
Npcap Loopback Adapter
```

### 5.3 自动推荐网卡

界面提供 `自动推断` 能力，点击后按打分规则选择推荐网卡（`recommend_device_display`）：

- 无线 / 有线网卡加分，物理接口命名（`enX`/`ethX`/`wlanX`）加分
- 虚拟网卡、VPN/隧道、蓝牙、回环接口依次扣分

推荐结果附带原因说明（`device_recommendation_reason`），例如“无线网卡，通常连接实验网段”。

整个映射只影响界面显示与推荐，真正开始抓包时程序仍使用 Npcap 返回的真实设备名
传给 `pcap_open_live()`，保证底层兼容性。

## 6. 协议解析与异常处理

协议解析模块直接处理原始字节流，当前支持：

- Ethernet 帧头解析
- IPv4 地址、协议号和长度字段解析
- TCP / UDP 端口解析
- HTTP 简单请求特征识别
- DNS 基础查询信息识别
- 未知 EtherType 和截断包提示

当数据包长度不足、字段异常或协议未知时，解析器不会直接崩溃，而是把问题写入 `PacketInfo.issues`，供 GUI 的协议详情面板展示。

## 7. IDS 规则引擎

项目实现了轻量级 IDS 规则格式，示例：

```text
alert tcp any any -> any 80 (content "GET"; msg "检测到 HTTP GET 请求";)
```

规则引擎支持协议、端口、内容匹配和告警消息，覆盖 IDS 的基础匹配流程；相比完整
的 Snort/Suricata 规则引擎，尚未实现 `offset`/`depth`/`flags`/`threshold`/`sid`
等选项与多包状态机，能力边界见 [roadmap.md](roadmap.md) A 组。

## 8. 图形界面设计

GUI 使用 Tkinter 实现，采用「外壳 + 工作区」两层结构：

**外壳**（始终可见的导航与状态）

- 顶栏：品牌、抓包状态胶囊、主题循环按钮
- 左侧操作轨：开始/停止/暂停/清空、打开/保存 pcap、导出告警、发包、扫描、规则
- 捕获工具条：网卡选择、BPF 表达式与模板，右侧常驻丢弃 / 解析异常计数
- KPI 指标条：五张指标卡（数据包、包速率、吞吐量、活动会话、告警），各带迷你走势图
- 显示过滤栏：过滤输入、模板、匹配计数胶囊
- 底栏：一行日志（可展开到 7 行）+ 状态栏

**工作区**

- 数据包列表（Treeview）：时间、源地址、目的地址、协议、长度、摘要；按协议着色，
  解析异常的包整行标红底
- 数据包检视：与列表并排，内含「解析树 / 原始字节」两个标签页
- 底部标签页：告警、解析问题、流量统计、IDS 规则，标题带实时计数

分栏是可拖动的 `ttk.PanedWindow`（工作区纵向、主区横向），分隔条位置随窗口状态一起持久化。

### 8.1 设计令牌与自绘控件

`gui/theme.py` 的颜色分三层，避免各处硬编码十六进制：

1. **原始令牌** —— `canvas` / `surface` / `surface_2` / `surface_3` / `border` /
   `border_strong` / `text` / `text_dim` / `text_faint` / `accent` / `success` /
   `warning` / `danger` / `info`，明暗各一套；
2. **派生语义色** —— 由原始令牌经 `mix()` 混合得到：`hover`、`row_alt`、`row_issue`、
   `tint_*`、`select`，以及协议配色 `proto_tcp` / `proto_udp` / `proto_http` /
   `proto_dns` / `proto_icmp`；
3. **兼容别名** —— 早期版本的键名（`bg` / `toolbar` / `panel` / `field` / `muted` …），
   指向对应的新令牌，保证历史对话框代码不改也能正常取色。

`gui/widgets.py` 提供自绘控件：`Sparkline`（Canvas 柱状走势图）、`StatCard`
（指标卡：小标题 + 等宽大数字 + 走势图，告警卡带红色竖条）、`StatusPill`（顶栏状态胶囊）、
`PanelHeader`（面板标题栏，右侧 `actions` 帧承载操作控件）、`Tooltip`（悬停提示）
以及 `hline` / `vline` 两个分隔线工具。原生 `tk` 控件不参与 ttk 样式表，
由 `NetGuardApp._paint()` 登记「控件 + 选项 → 颜色令牌名」，主题切换时统一重刷。

严重度不再靠消息关键字猜：`theme.severity_key()` 直接采信 `Alert.severity`
（规则引擎与检测器都填了该字段），只有对象缺字段时才回退到 `severity_color()`
的关键字匹配。

### 8.2 布局尺寸的几个约束

Tkinter 的「请求尺寸」是显式的，控件默认值往往比预期大得多，这几处踩过坑：

- `tk.Text` 默认 `width=80` 字符、`tk.Canvas` 默认宽 10 厘米（约 378px）。
  填充式文本域与走势图必须显式给 `width=1`，否则五个指标卡会把窗口最小宽度
  推到 2000px 以上，右侧内容被裁掉。
- 恢复分隔条位置必须等窗口完成首次布局：`ttk.PanedWindow.sashpos()` 在布局前
  调用会被钳制到 0，主区域塌成一条线。`_apply_sash_positions()` 先
  `update_idletasks()`，未成形时有限次重试。
- 分隔条默认位置按**窗格自身尺寸**计算，而不是窗口尺寸，并给两侧各留最小尺寸，
  否则底部标签页会被挤成一条缝。
- **分隔条位置是绝对值，窗口变窄时必须重算**：`ttk.PanedWindow` 不会让分隔条随窗口
  回退，在宽窗口上定位后缩窄窗口，右侧窗格会被压成一条缝（实测最小尺寸下检视面板只剩
  272px，而它要显示「字段 + 值」两列需要 344px）。窗格自身的 `<Configure>` 事件里重新钳制一次，
  尾部下限取「尾部窗格的请求尺寸」——用户把检视列拖宽后也不会被裁。
- **两个面板的默认列宽之和必须落在最小窗口之内**：数据包列表与检视面板并排，
  两组默认列宽（700 + 332px）加上滚动条、分隔条与内边距就是窗口的实际需求宽度。
  预算写在 `_DEFAULT_PACKET_COLUMNS` / `_DEFAULT_DETAIL_COLUMNS`，由
  `tests/test_gui_layout.py` 守住；`MIN_WINDOW_SIZE` 是这条预算的上界。
- **grid 同格会互相遮挡**：操作轨与内容区之间的 1px 竖线若与内容帧放在同一个
  `grid` 单元格，`sticky="ns"` 只纵向拉伸、横向停在格子中间，后创建的内容帧把它
  整块盖住——分隔线不会显示，也不会报错。各占一列才有效。
- 30px 高的紧凑栏（日志条）放不下常规按钮（需要 34px，会被压扁截字），
  这类位置使用 `Tiny.TButton`。
- 恢复窗口几何时**位置与尺寸都要钳制**：早期只夹位置，在 2560 宽屏上保存的
  `2228x1147` 搬到 2048 宽的屏幕上会把窗口右半边（含操作按钮）推到屏幕外。

为了避免 Windows 设备名过长且难以识别，网卡下拉框优先显示友好描述和 Mac 对应提示。

主题由 `gui/theme.py` 的 `ThemeManager` 统一管理，模式状态存在 `NetGuardApp.theme_mode`（取值 `light` / `dark` / `system`），由 `gui/config.py` 的 `resolve_theme_mode()` 归一化读写，并保留旧版 `dark_mode`（布尔）配置的迁移。`system` 模式下由 `detect_system_dark()` 定期检测系统深浅色并自动切换。

切换实现时固定使用同一个 ttk 主题（`clam`），只替换颜色令牌，不在明暗模式之间切换 ttk 主题结构，避免按钮 padding、边框和控件尺寸被重新计算，从而保证切换主题时控件位置不跳动。`Text` 等传统 Tk 控件会被登记到 `_classic_widgets`，统一应用背景色、前景色、选中色和光标色；Treeview 的行着色改用 tag（`tag_tree()`），换肤时按 tag 重新着色即可；打开中的对话框通过 `wire_dialog_theme()` 监听 `<<ThemeChanged>>` 一并重刷，不会出现"花脸"。

## 9. 测试与验证

项目使用 `pytest` 作为测试框架，配置位于 `pyproject.toml`：

```toml
[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
```

当前测试覆盖包括：

- 应用入口基础行为
- 协议解析
- IDS 规则、会话和统计逻辑
- Windows/Mac 接口映射规则
- GUI 的导入、布局稳定性与最小尺寸下的不变量烟测（最右侧控件不出窗口、分隔条随窗口回收）

推荐验证命令：

```bash
python -m pytest
```

如果当前环境没有安装 `pytest`，应先在项目内 `.venv` 中安装依赖。

## 10. 安全与使用边界

NetGuard 只应在授权网络、实验室环境或自有设备上使用。抓包可能涉及敏感数据，例如账号、Token、内网地址和业务内容。项目不应被用于未授权监听，也不应把真实抓包文件、密钥或敏感日志提交到仓库。

建议使用边界：

- 只监听授权网卡和授权网段
- 演示时优先使用测试流量
- 导出的告警日志提交前应人工检查
- 不在代码中硬编码凭据或真实网络信息

## 11. 后续改进方向

已完成（原文列为待办，现已实现）：

- ~~主题配置持久化~~：`theme_mode` 已随窗口状态写入 `~/.netguard_config.json`，并支持跟随系统
- ~~ICMP 解析~~：已解析 ICMP Echo / Echo Reply，并新增 ICMP flood 检测器
- ~~跨平台 CI~~：GitHub Actions 覆盖 Ubuntu / Windows / macOS × Python 3.11 / 3.12
- ~~网卡推荐标记~~：`interface_mapping.py` 提供推荐网卡与推荐理由

后续可以继续增强：

- Windows 默认网卡识别：结合 `Get-NetIPConfiguration` 找出有默认网关的接口
- 协议支持扩展：增加 IPv6、ARP、TLS SNI
- 规则语法扩展：`offset` / `depth` / `flags` / `threshold` / `sid`（见 `docs/roadmap.md` A 组）
- IPv4 分片重组：当前对非首片仅标记 `fragment_offset`，不重组
- UI 可用性优化：网卡搜索、实时抓包速率图、大结果集虚拟滚动
- 工程化：覆盖率门槛提升、Windows 打包链路（PyInstaller）

完整的优先级清单见 [`docs/roadmap.md`](roadmap.md)。

## 12. 结论

NetGuard 通过原生 pcap/Npcap 接口实现了跨平台抓包基础能力，并在解析、统计、IDS 告警和 GUI 展示上形成了完整的数据流。针对 Windows 与 macOS 网卡命名差异，项目新增接口兼容性提示功能，在不改变底层真实设备名的前提下，为 Windows 用户提供接近 Mac `en0` 使用习惯的操作体验。GUI 提供浅色 / 深色 / 跟随系统三种主题模式，并通过固定 ttk 主题、仅切换颜色令牌的方式保证明暗模式切换时布局稳定。
