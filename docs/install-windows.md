# Windows 安装与配置

Windows 平台使用 Npcap / WinPcap 原生 `wpcap.dll` 接口。

## 安装 Npcap

1. 从 Npcap 官方网站安装 Npcap。
2. 安装时勾选 `Install Npcap in WinPcap API-compatible Mode`。
3. 如需普通用户抓包，可按实验室要求配置 Npcap 权限；否则以管理员身份运行。

## 安装项目

```powershell
cd C:\path\to\NetGuard
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

## 运行

一键启动（推荐；双击 `NetGuard.bat` 或在命令行运行，会自动定位 Python 并转交
`scripts/launch.py`，参数原样透传）：

```powershell
.\NetGuard.bat                 # 启动 GUI
.\NetGuard.bat --list-devices  # 列出网卡
.\NetGuard.bat --check         # 环境自检（Python/源码/抓包后端/界面/规则）
.\NetGuard.bat --read capture.pcap
```

若本机尚未准备解释器，可让启动器自动建虚拟环境并安装：

```powershell
py scripts\launch.py --setup --no-run   # 创建 .venv + pip install -e .
```

直接使用 python 或已有启动脚本：

```powershell
# 直接使用 python
py main.py --list-devices
py main.py

# 或使用启动脚本（自动检测解释器，最终转交 scripts\launch.py）
.\scripts\run_netguard.ps1
.\scripts\run_netguard.bat --list-devices

# 离线回放 pcap / 保存抓包 / 导出告警
py main.py --read capture.pcap
py main.py --no-gui --interface "Wi-Fi" --write out.pcap
```

## Windows 网卡显示与推荐

Windows 上 Npcap 返回的真实抓包接口通常是 `\Device\NPF_{GUID}`，不会原生提供
macOS 的 `en0`、`en1` 名称。NetGuard 会在界面中为每个 Windows 网卡显示可读
名称与类型标签，例如：

```text
Wi-Fi 6 Adapter（无线网卡）
Intel(R) Ethernet Connection I219-V（有线网卡）
Npcap Loopback Adapter（回环接口）
```

界面的 `自动推断` 按钮会按打分规则推荐最可能联网的网卡（无线/有线加分，
虚拟/VPN/回环减分），并在日志区说明推荐原因。显示名与推荐只影响界面提示，
开始抓包时程序仍使用 Npcap 的真实接口名。

如果无法打开网卡，请使用管理员 PowerShell 运行。
