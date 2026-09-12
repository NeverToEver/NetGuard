# NetGuard 实验室演示细则

## 1. 演示定位

本文件用于课堂展示、实验验收和答辩说明。它比 `experiment-workflow.md` 更偏“讲解稿”，不仅说明怎么操作，还说明每一步背后的模块、文件和实现逻辑。

演示目标：

- 展示 NetGuard 如何枚举网卡、选择接口并设置 BPF。
- 展示 macOS `en0` 与 Windows Npcap 接口的兼容提示。
- 展示抓包、解析、统计、IDS 告警和导出流程。
- 展示夜间模式切换，并说明切换时布局不发生跳动。
- 能把界面上的现象对应到具体源码模块。

仅在授权实验室网段、授权设备和自有测试环境中运行。

## 2. 演示前准备

### 2.1 环境检查

在项目根目录执行：

```bash
python main.py --list-devices
```

预期效果：

- macOS 可能看到 `en0`、`en1`、`lo0`。
- Windows 可能看到 `\Device\NPF_{GUID}`、`Wi-Fi`、`Ethernet`、`Npcap Loopback Adapter` 等。
- Windows 下列表或 GUI 会出现类似“Windows Wi-Fi 对应 Mac en0”的提示。

对应实现：

| 功能 | 文件 | 说明 |
| --- | --- | --- |
| 程序入口 | `main.py` | 将 `src/` 加入 `sys.path` 后调用 `netguard.app.main()` |
| CLI 参数 | `src/netguard/app.py` | 处理 `--list-devices`、`--no-gui`、`--interface`、`--bpf` |
| 网卡枚举 | `src/netguard/capture/pcap.py` | 调用 `pcap_findalldevs()` 获取系统抓包设备 |
| 接口提示 | `src/netguard/capture/interface_mapping.py` | 生成 Windows 与 Mac 接口习惯名的对应提示 |

### 2.2 启动 GUI

macOS / Linux：

```bash
sudo python main.py
```

Windows：

```powershell
python main.py
```

如果 Windows 无法打开网卡，用管理员身份重新运行。

对应实现：

| 功能 | 文件 | 说明 |
| --- | --- | --- |
| GUI 启动 | `src/netguard/app.py` | 未指定 `--no-gui` 时导入并运行 `run_gui()` |
| 主窗口 | `src/netguard/gui/main_ui.py` | `NetGuardApp` 创建顶部工具栏、包列表、详情区、告警区、统计区 |

## 3. 演示主线

### 3.1 选择网卡

演示操作：

1. 打开顶部“网卡”下拉框。
2. macOS 上选择 `en0`。
3. Windows 上选择提示为“对应 Mac en0”的主联网网卡，通常是 Wi-Fi；如果机器使用网线，则选择 Ethernet。
4. 如果自动提示不符合实验机器，修改 `Mac映射` 输入框，例如填写 `en0`，点击 `应用映射`。
5. 点击 `自动推断`，展示可恢复默认映射。

实现逻辑：

| 文件 | 关键逻辑 |
| --- | --- |
| `src/netguard/capture/pcap.py` | `PcapBackend.list_devices()` 使用 libpcap/Npcap 原生接口枚举设备，Windows 返回真实 `\Device\NPF_{GUID}` |
| `src/netguard/capture/interface_mapping.py` | `build_device_displays()` 为每个 `CaptureDevice` 生成 `DeviceDisplay` |
| `src/netguard/capture/interface_mapping.py` | Wi-Fi / Wireless / WLAN 优先映射为 `en0`，Ethernet 映射为后续 `enX`，Loopback 映射为 `lo0` |
| `src/netguard/gui/main_ui.py` | `_set_devices()` 把真实设备名映射成带提示的下拉显示文本 |
| `src/netguard/gui/main_ui.py` | `_selected_device_name()` 在点击“开始”时把显示文本还原为真实设备名 |

需要强调：

Windows 并不会真的拥有 `en0`。NetGuard 的 `en0` 是界面提示和操作习惯别名，底层抓包仍然使用 Npcap 的真实设备名。

### 3.2 设置 BPF

演示操作：

在 BPF 输入框填写：

```text
tcp or udp
```

如果需要限制实验室网段：

```text
net 192.168.1.0/24
```

将网段替换为实际授权网段。

实现逻辑：

| 文件 | 关键逻辑 |
| --- | --- |
| `src/netguard/gui/main_ui.py` | `self.bpf_var` 保存界面中的 BPF 字符串 |
| `src/netguard/pipeline.py` | `PacketPipeline.start(device, bpf_filter)` 将过滤器传给后端 |
| `src/netguard/capture/pcap.py` | `PcapBackend.set_filter()` 调用 `pcap_compile()` 和 `pcap_setfilter()` |

讲解点：

BPF 是抓包层过滤，影响后台实际捕获到的数据；界面里的“显示过滤”只影响表格展示，不影响后台抓包。

### 3.3 加载 IDS 规则

演示操作：

在底部 `IDS 规则` 输入：

```text
alert tcp any any -> any 80 (content "GET"; msg "检测到 HTTP GET 请求";)
alert udp any any -> any 53 (content "example"; msg "检测到 DNS 查询关键字";)
```

点击 `加载规则`。

实现逻辑：

| 文件 | 关键逻辑 |
| --- | --- |
| `src/netguard/gui/main_ui.py` | `_load_rules()` 从文本框读取规则 |
| `src/netguard/pipeline.py` | `PacketPipeline.load_rules()` 将规则文本交给规则引擎 |
| `src/netguard/rules/engine.py` | 解析 `alert` 规则，按协议、端口、content 和 msg 进行匹配 |

讲解点：

当前规则引擎是轻量教学版，用于展示 IDS 的基本工作流，不等同于完整 Snort/Suricata。

### 3.4 开始抓包

演示操作：

1. 点击 `开始`。
2. 打开网页或执行 DNS 查询。
3. 观察包列表、协议详情、十六进制视图、告警和统计面板。

可以生成 DNS 流量：

```bash
nslookup example.com
```

可以生成 HTTP 流量：

```bash
curl http://example.com
```

实现逻辑：

| 文件 | 关键逻辑 |
| --- | --- |
| `src/netguard/gui/main_ui.py` | `_start()` 加载规则并调用 `pipeline.start()` |
| `src/netguard/pipeline.py` | 创建抓包线程 `netguard-capture` 和解析线程 `netguard-parse` |
| `src/netguard/capture/pcap.py` | `capture_loop()` 调用 `pcap_next_ex()` 持续读取原始数据包 |
| `src/netguard/pipeline.py` | `_capture_worker()` 将 `RawPacket` 放入原始队列 |
| `src/netguard/pipeline.py` | `_parse_worker()` 调用 `parse_packet()`，更新会话、统计并匹配 IDS 规则 |
| `src/netguard/gui/main_ui.py` | `_tick()` 定时从事件队列取出解析结果并刷新界面 |

数据流可以这样讲：

```text
Npcap/libpcap
  -> RawPacket
  -> raw_queue
  -> parse_packet()
  -> SessionTracker / TrafficStats / RuleEngine
  -> event_queue
  -> Tkinter GUI
```

### 3.5 协议解析展示

演示操作：

点击包列表中的某一条 TCP、UDP、DNS 或 HTTP 流量，观察右侧协议详情和十六进制视图。

实现逻辑：

| 文件 | 关键逻辑 |
| --- | --- |
| `src/netguard/parser/packet.py` | 解析 Ethernet、IPv4、TCP、UDP、HTTP、DNS |
| `src/netguard/gui/main_ui.py` | `_show_selected()` 根据选中的表格行展示详情和原始十六进制内容 |
| `src/netguard/gui/main_ui.py` | `_format_packet()` 将解析结果格式化为可读文本 |

讲解点：

协议详情来自原始字节流解析，不是调用 Wireshark。未知 EtherType、截断包或异常字段会被标注为问题信息。

### 3.6 会话与统计展示

演示操作：

观察统计区域中的总数据包数、总字节数、活跃会话、每秒包数、每秒字节数和协议分布。

实现逻辑：

| 文件 | 关键逻辑 |
| --- | --- |
| `src/netguard/session/tracker.py` | 跟踪 TCP 会话、连接关闭和超时清理 |
| `src/netguard/statistics/traffic_stats.py` | 维护包数、字节数、协议计数和速率 |
| `src/netguard/gui/main_ui.py` | `_refresh_stats()` 定时读取 `stats.snapshot()` 并刷新统计文本 |

### 3.7 夜间模式展示

演示操作：

1. 点击顶部 `夜间模式`。
2. 观察窗口、按钮、输入框、下拉框、表格、文本区、告警列表和统计区域都切换为深色。
3. 再次点击，恢复浅色。
4. 重点说明：按钮位置不会变化，布局不会跳动。

实现逻辑：

| 文件 | 关键逻辑 |
| --- | --- |
| `src/netguard/gui/main_ui.py` | `self.dark_mode` 保存夜间模式开关状态 |
| `src/netguard/gui/main_ui.py` | `_apply_theme()` 只切换颜色，不在明暗模式之间切换 ttk 主题 |
| `src/netguard/gui/main_ui.py` | 启动时固定使用同一个 ttk 主题，避免按钮 padding 和边框重新计算 |
| `src/netguard/gui/main_ui.py` | `_classic_widgets` 保存 Text、Listbox 等非 ttk 控件，统一应用深色配置 |

讲解点：

早期实现中，如果切换夜间模式时在 ttk 主题之间来回切换，按钮尺寸和位置可能会变化。当前实现固定主题，只改颜色，因此布局稳定。

### 3.8 暂停、清空和导出

演示操作：

1. 点击 `暂停刷新`，观察界面停止追加新行。
2. 点击某条包继续查看详情。
3. 点击 `清空`，清除当前界面数据。
4. 触发 IDS 告警后点击 `导出告警`，保存 `.log` 或 `.txt` 文件。

实现逻辑：

| 文件 | 关键逻辑 |
| --- | --- |
| `src/netguard/gui/main_ui.py` | `_toggle_pause()` 控制界面是否继续追加新事件 |
| `src/netguard/gui/main_ui.py` | `_clear()` 清空事件、表格、告警、详情和十六进制视图 |
| `src/netguard/gui/main_ui.py` | `_export_alerts()` 将告警列表写入文本文件 |

## 4. 建议演示顺序

推荐按以下顺序讲：

1. 项目目标：跨平台抓包和轻量 IDS。
2. 文件结构：从 `main.py` 到 `src/netguard/` 分层模块。
3. 网卡枚举：展示 macOS `en0` 和 Windows Npcap 差异。
4. 接口映射：说明 `interface_mapping.py` 如何给 Windows 网卡生成 Mac 风格提示。
5. BPF：说明抓包层过滤。
6. 开始抓包：展示实时包列表。
7. 协议解析：点击数据包展示详情和十六进制。
8. IDS 告警：加载规则并触发 HTTP/DNS 告警。
9. 统计：展示 TrafficStats 和 SessionTracker。
10. 夜间模式：展示明暗切换和布局稳定。
11. 导出告警：保存实验结果。

## 5. 验收点

演示完成后应能证明：

- 能枚举系统网卡。
- 能在 Windows 下看到对应 Mac `en0` / `en1` / `lo0` 的提示。
- 能选择主联网网卡完成抓包。
- 能通过 BPF 控制捕获范围。
- 能解析 TCP、UDP、DNS、HTTP 等常见流量。
- 能触发 IDS 规则告警。
- 能展示会话和统计信息。
- 能切换夜间模式且按钮布局不跳动。
- 能导出告警日志。

## 6. 与其他文档的关系

- `docs/experiment-workflow.md`：面向实验操作者，按步骤说明如何完成实验。
- `docs/technical-report.md`：面向报告/答辩，说明架构、模块、实现设计和后续改进。
- `docs/lab-demo.md`：本文件，面向课堂演示，重点把“操作现象”对应到“源码模块和实现逻辑”。
