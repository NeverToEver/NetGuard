# NetGuard

跨平台网络数据包监控与轻量 IDS 工具，参考 Wireshark 工作方式设计。

支持 Linux、macOS、Windows（Npcap/WinPcap），纯 Python 标准库实现（零运行时依赖）。

## 功能概览

- **抓包引擎** — `ctypes` 调用原生 libpcap / Npcap / WinPcap，枚举网卡、混杂模式、BPF 过滤
- **离线 pcap** — 纯标准库读写 `.pcap` 文件，可回放实验、保存结果、与 Wireshark/tcpdump 交叉验证
- **协议解析** — 自解析 Ethernet → IPv4 → TCP/UDP → HTTP/DNS/ICMP，结构化错误处理
- **IDS 规则** — 类 Snort 语法，协议/端口/content 匹配，实时告警
- **攻击检测** — 跨包时间窗口检测 SYN flood、端口扫描、DNS 隧道（补充单包规则）
- **会话重组** — TCP 乱序片段重组、流追踪、超时清理；内容规则可在重组流中匹配，防御拆包绕过
- **图形界面** — Tkinter：包列表、协议详情、十六进制视图、告警日志、统计面板、列排序、BPF/显示过滤
- **桌面交互惯例** — 菜单栏与快捷键、表格右键菜单与复制、窗口/布局记忆、悬停提示、跟随系统深浅色主题
- **结构化告警** — 告警可导出为 JSON（每行一条），便于对接 SIEM 或后续分析

## 架构

```
main.py                     入口点
src/netguard/
├── app.py                  参数解析，路由到 GUI 或 CLI 预览，处理 --read/--write/--alerts-json
├── pipeline.py             PacketPipeline 编排门面（start/stop/pump/status）
├── processing.py           PacketProcessor：解析→会话→统计→规则/检测（可独立测试）
├── clock.py                时钟抽象（支持注入 mock）
├── capture/
│   ├── pcap.py             ctypes 调用原生 libpcap/Npcap 后端
│   ├── source.py           CaptureSource：抓包/回放线程、原始包队列、丢包统计
│   ├── pcap_file.py        纯标准库 pcap 文件读写
│   └── interface_mapping.py 跨平台网卡显示与推荐
├── parser/
│   └── packet.py           Ethernet→IPv4→TCP/UDP→HTTP/DNS/ICMP 解码
├── rules/
│   ├── engine.py           IDS 规则引擎：解析、索引、匹配、流匹配
│   └── suggestions.py      规则建议
├── detection/
│   ├── base.py             Detector 协议
│   └── detectors.py        SYN flood / 端口扫描 / DNS 隧道检测器
├── session/
│   └── tracker.py          TCP 会话重组与流管理
├── statistics/
│   └── traffic_stats.py    滚动窗口速率统计
├── discovery/
│   └── subnet.py           网段扫描与主机解析
├── trafficgen.py           合成数据包模板（演示/测试/基准）
└── gui/
    ├── main_ui.py          Tkinter 主窗口（菜单、状态栏、右键菜单、快捷键）
    ├── config.py           应用配置读写与旧版迁移（~/.netguard_config.json）
    ├── theme.py            跨平台字体 + 明暗主题 + 跟随系统检测
    ├── widgets.py          悬停提示等通用控件
    └── view_models.py      显示格式化工具
```

数据流：`capture/source → processing → pipeline(事件队列) → gui`。

## 界面与快捷键

主窗口包含菜单栏、工具栏、显示过滤栏、数据包列表、协议详情/十六进制视图、
告警与解析问题面板、统计与 IDS 规则面板，以及底部状态栏。

| 快捷键 | 功能 |
| --- | --- |
| `F5` | 开始抓包 |
| `Shift+F5` | 停止抓包 |
| `Ctrl+P` | 暂停 / 恢复刷新 |
| `Ctrl+L` | 清空数据 |
| `Ctrl+O` | 打开 pcap |
| `Ctrl+S` | 保存 pcap |
| `Ctrl+E` | 导出告警 |
| `Ctrl+F` | 聚焦显示过滤框 |
| `Ctrl+C` | 复制选中数据包整行 |
| `Ctrl+Q` | 退出 |
| `F1` | 快捷键说明 |

其它交互惯例：

- **表格**：点击表头按列排序，再次点击切换升/降序（表头显示 ▲/▼）；右键菜单可复制摘要、整行、
  源→目的、十六进制，或用摘要快速筛选；双击告警/异常可定位到对应数据包。
- **主题**：视图 → 主题，可选浅色/深色/跟随系统；选择"跟随系统"时会定期检测系统深浅色并自动切换。
- **状态记忆**：窗口位置与大小、分隔条位置、列宽、排序状态、上次网卡与 BPF/显示过滤条件都会保存到
  `~/.netguard_config.json`，下次启动自动恢复。
- **对话框**：相对主窗口居中，`Esc` 取消；模板/规则建议对话框支持回车确认。
- **后台执行**：保存 pcap、导出告警、加载规则在后台线程完成，界面不会被大文件阻塞。

## 安装

```bash
# 创建虚拟环境（Python 3.11+）
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows

pip install -e .
```

Linux 额外依赖：
```bash
sudo apt-get install -y libpcap0.8 fonts-noto-cjk
```

macOS：系统自带 libpcap，无需额外安装。

Windows 额外依赖：
- 安装 [Npcap](https://npcap.com/#download)，勾选 "WinPcap API-compatible Mode"
- Python 自带 tkinter，无需额外安装

## 快速开始

```bash
# 列出可用网卡
python main.py --list-devices

# 启动 GUI
python main.py

# 命令行抓包预览（需管理员/sudo 权限）
sudo python main.py --no-gui --interface eth0 --bpf "tcp or udp"

# 离线回放 pcap（无需 libpcap，无需权限）
python main.py --read capture.pcap

# 抓包并保存 + 导出告警为 JSON
python main.py --no-gui --interface eth0 --write out.pcap --alerts-json alerts.json

# 从文件加载 IDS 规则（默认使用内置示例规则）
python main.py --read capture.pcap --rules my.rules --alerts-json alerts.json

# 性能与检测能力基准
python scripts/benchmark.py --markdown
```

启动脚本（自动检测解释器）：

```bash
./scripts/run_netguard.sh            # Linux / macOS
.\scripts\run_netguard.ps1           # Windows PowerShell
.\scripts\run_netguard.bat --list-devices
```

## IDS 规则

```
alert tcp any any -> any 80 (content "GET"; msg "检测到 HTTP GET 请求";)
alert udp any any -> any 53 (content "example.com"; msg "检测到 DNS 查询";)
```

语法：`alert <proto> <src> <src_port> <-> <dst> <dst_port> (content "X"; msg "Y";)`

内容规则除单包匹配外，还会在 TCP 会话重组流中查找，因此把关键词拆分到多个
TCP 段（拆包绕过）仍会命中；同一会话内同一规则只告警一次。

## 攻击检测（跨包时间窗口）

除静态规则外，内置检测器用于发现单包无法判断的行为（阈值均可在构造时配置）：

| 检测器 | 判据 | 默认阈值 |
| --- | --- | --- |
| SYN flood | 窗口内同一 (目的IP, 端口) 的 SYN 数 | 5s / 100 |
| 端口扫描 | 窗口内同一源访问的不同目的端口数 | 10s / 20 |
| DNS 隧道 | 超长域名/标签，或同一后缀高频查询 | 10s / 50 |

## 性能

合成流量下的基准数据（Windows 10 / Python 3.11，20 万包）：

| 项目 | 结果 |
| --- | --- |
| 协议解析吞吐 | 约 12.7 万 包/秒（约 8.3 MB/s） |
| 端到端流水线 | 约 5.1 万 包/秒 |
| 单包解析耗时 | 约 7.9 µs |
| 规则匹配（500 条） | 中位约 247 µs，P99 约 589 µs |
| 内存增量（5 万包） | 约 8.9 MB |
| 合成攻击场景检出 | 3 / 3 |
| 正常流量误报率 | 0.100% |

复现：`python scripts/benchmark.py --packets 200000 --rules 500 --markdown`
（详见 [docs/benchmark.md](docs/benchmark.md)）

## 开发

```bash
# 运行全部测试
python -m pytest tests/ -v

# 运行单个测试文件
python -m pytest tests/test_parser.py -v

# 语法检查
python -m compileall -q src tests scripts
```

CI 在 GitHub Actions 上对 Ubuntu / Windows × Python 3.11 / 3.12 运行测试。

## 打包

```bash
python3 scripts/build_unix_app.py --python-env .venv
```

生成 `dist/NetGuard-portable/`（Unix）或 `dist/NetGuard.app`（macOS）。

## 文档

- [Linux 安装](docs/install-linux.md)
- [macOS 安装](docs/install-macos.md)
- [Windows 安装](docs/install-windows.md)
- [使用说明](docs/usage.md)
- [实验室演示](docs/lab-demo.md)
- [技术报告](docs/technical-report.md)
- [性能基准](docs/benchmark.md)
- [后续工作路线图](docs/roadmap.md)
- [Linux 可执行文件分发指南](docs/distribute-linux.md)

## License

[MIT](LICENSE)
