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

Windows 与 macOS 的接口命名机制不同。macOS 使用 BSD 风格接口名，例如 `en0` 通常代表默认无线或主要物理网卡；Windows Npcap 返回的是设备路径和 GUID，例如 `\Device\NPF_{...}`。因此 Windows 不会原生出现 `en0`，项目通过界面提示提供 Mac 风格的对应关系。

## 3. 系统架构

项目采用分层结构，主要模块如下：

| 模块 | 路径 | 职责 |
| --- | --- | --- |
| 启动入口 | `main.py`, `src/netguard/app.py` | 命令行参数处理、GUI/控制台模式启动 |
| 抓包后端 | `src/netguard/capture/pcap.py` | 加载 pcap 库、枚举设备、打开网卡、设置 BPF、读取原始包 |
| 接口映射 | `src/netguard/capture/interface_mapping.py` | 生成 Windows 与 Mac 接口习惯名的提示和别名 |
| 数据管线 | `src/netguard/pipeline.py` | 捕获线程、解析线程、事件队列、统计与告警分发 |
| 协议解析 | `src/netguard/parser/packet.py` | Ethernet、IPv4、TCP、UDP、HTTP、DNS 解析 |
| IDS 规则 | `src/netguard/rules/engine.py` | 简化规则加载与匹配 |
| 会话跟踪 | `src/netguard/session/tracker.py` | TCP 会话记录、重组与超时清理 |
| 流量统计 | `src/netguard/statistics/traffic_stats.py` | 包数、字节数、协议分布、速率统计 |
| 图形界面 | `src/netguard/gui/main_ui.py` | 网卡选择、BPF 输入、包列表、详情、十六进制视图、告警、统计和夜间模式 |

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

## 5. Windows 与 Mac 接口兼容性提示

### 5.1 问题背景

用户在 macOS 上通常选择 `en0` 完成抓包，但在 Windows 上只能看到 Npcap 设备路径，例如：

```text
\Device\NPF_{0AFD3ED9-02C8-0811-124D-1682118B6574}
```

这不是程序错误，而是平台接口命名方式不同。为了保持接近 Wireshark 的操作体验，NetGuard 在界面中为 Windows 网卡附加 Mac 风格提示。

### 5.2 自动推断规则

当前推断规则如下：

| Windows 网卡类型 | Mac 提示 |
| --- | --- |
| Wi-Fi / Wireless / WLAN / 802.11 | 优先映射为 `en0` |
| Ethernet / LAN / 有线网卡 | 依次映射为 `en1`, `en2` |
| Loopback / Npcap Loopback Adapter | 映射为 `lo0` |
| Hyper-V / VMware / VirtualBox / VPN / Tunnel | 标注为虚拟/VPN，并分配 `enX` |
| 未知类型 | 标注为自动推断，并分配 `enX` |

界面显示示例：

```text
Wi-Fi 6 Adapter - Windows Wi-Fi 6 Adapter 对应 Mac en0（无线）
Intel Ethernet - Windows Intel Ethernet 对应 Mac en1（有线）
Npcap Loopback Adapter - Windows Npcap Loopback Adapter 对应 Mac lo0（回环）
```

### 5.3 手动映射

自动推断无法覆盖所有机器环境，因此 GUI 提供 `Mac映射` 输入框。用户可以手动输入 `en0`、`en1` 等别名并点击 `应用映射`，也可以点击 `自动推断` 恢复默认规则。

该映射只影响界面提示和用户操作习惯。真正开始抓包时，程序仍然使用 Npcap 返回的真实设备名传给 `pcap_open_live()`，保证底层兼容性。

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

规则引擎支持协议、端口、内容匹配和告警消息。其定位是教学和实验室演示，适合展示 IDS 的基础匹配流程，不等同于完整 Snort/Suricata 规则引擎。

## 8. 图形界面设计

GUI 使用 Tkinter 实现，主要区域包括：

- 顶部工具栏：网卡选择、Mac 映射、BPF 输入、开始/停止、暂停刷新、清空、导出告警
- 包列表：展示时间、源地址、目的地址、协议、长度和摘要
- 协议详情：展示解析后的分层字段
- 十六进制视图：展示原始包内容
- 告警面板：展示 IDS 规则命中的结果
- 统计面板：展示包数量、字节数、活跃会话、速率和协议分布
- 夜间模式：切换窗口、按钮、输入框、表格和文本区域的深色配色

为了避免 Windows 设备名过长且难以识别，网卡下拉框优先显示友好描述和 Mac 对应提示。

夜间模式由 `NetGuardApp.dark_mode` 和 `_apply_theme()` 实现。实现时固定使用同一个 ttk 主题，只切换颜色配置，不在明暗模式之间切换 ttk 主题结构，避免按钮 padding、边框和控件尺寸被重新计算，从而保证切换夜间模式时顶部按钮位置不跳动。`Text`、`Listbox` 等传统 Tk 控件会被登记到 `_classic_widgets`，统一应用背景色、前景色、选中色和光标色。

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
- GUI 夜间模式的导入和布局稳定性烟测

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

后续可以继续增强：

- Windows 默认网卡识别：结合 `Get-NetIPConfiguration` 找出有默认网关的接口
- 接口映射持久化：把手动 `en0` / `en1` 映射保存到用户配置文件
- 协议支持扩展：增加 IPv6、ARP、TLS SNI、ICMP 等解析
- 规则引擎增强：支持更多条件、方向、大小写匹配和规则分组
- UI 可用性优化：增加网卡搜索、推荐标记和实时抓包速率图
- 主题配置持久化：保存用户选择的夜间模式状态
- 测试环境完善：提供 Windows Npcap mock 和跨平台 CI

## 12. 结论

NetGuard 通过原生 pcap/Npcap 接口实现了跨平台抓包基础能力，并在解析、统计、IDS 告警和 GUI 展示上形成了完整的数据流。针对 Windows 与 macOS 网卡命名差异，项目新增接口兼容性提示功能，在不改变底层真实设备名的前提下，为 Windows 用户提供接近 Mac `en0` 使用习惯的操作体验。GUI 还提供夜间模式，并通过固定 ttk 主题、仅切换颜色的方式保证明暗模式切换时布局稳定。
