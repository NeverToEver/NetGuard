# NetGuard

跨平台网络数据包监控与轻量 IDS 工具，参考 Wireshark 工作方式设计。

支持 Linux、macOS、Windows（Npcap/WinPcap），纯 Python 标准库实现。

## 功能概览

- **抓包引擎** — `ctypes` 调用原生 libpcap / Npcap / WinPcap，枚举网卡、混杂模式、BPF 过滤
- **协议解析** — 自解析 Ethernet → IPv4 → TCP/UDP → HTTP/DNS，结构化错误处理
- **IDS 规则** — 类 Snort 语法，协议/端口/content 匹配，实时告警
- **会话重组** — TCP 乱序片段重组、流追踪、超时清理
- **图形界面** — Tkinter 实现：包列表、协议详情、十六进制视图、告警日志、统计面板、列排序、BPF 过滤

## 架构

```
main.py                     入口点
src/netguard/
├── app.py                  参数解析，路由到 GUI 或 CLI 预览
├── pipeline.py             数据管道：双线程 capture→parse→事件队列
├── clock.py                时钟抽象（支持注入 mock）
├── capture/
│   ├── pcap.py             PcapBackend + Protocol 接口
│   └── interface_mapping.py 跨平台网卡名映射（Windows Npcap ↔ en0）
├── parser/
│   └── packet.py           Ethernet→IPv4→TCP/UDP→HTTP/DNS 递归解码
├── rules/
│   └── engine.py           IDS 规则引擎：解析、索引、匹配
├── session/
│   └── tracker.py          TCP 会话重组与流管理
├── statistics/
│   └── traffic_stats.py    滚动窗口速率统计
└── gui/
    ├── main_ui.py          Tkinter 主窗口
    ├── theme.py            跨平台字体 + 明暗主题
    └── view_models.py      显示格式化工具
```

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

# 命令行抓包预览
sudo python main.py --no-gui --interface eth0 --bpf "tcp or udp"
```

或使用启动脚本（自动检测解释器）：
```bash
./scripts/run_netguard.sh
```

## IDS 规则

```
alert tcp any any -> any 80 (content "GET"; msg "检测到 HTTP GET 请求";)
alert udp any any -> any 53 (content "example.com"; msg "检测到 DNS 查询";)
```

语法：`alert <proto> <src> <src_port> <-> <dst> <dst_port> (content "X"; msg "Y";)`

## 开发

```bash
# 运行全部测试
python -m pytest tests/ -v

# 运行单个测试文件
python -m pytest tests/test_parser.py -v
```

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
- [Linux 可执行文件分发指南](docs/distribute-linux.md)
