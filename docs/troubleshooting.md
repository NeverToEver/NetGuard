# 排障指南

本文汇总常见问题与定位方法。换机、演示或首次部署时建议先跑一遍环境自检：

```bash
python scripts/launch.py --check
```

自检会逐项报告 Python 版本、源码结构、包导入、抓包后端、图形界面与 IDS 规则
的可用状态，能直接区分"环境问题"与"用法问题"。

## 抓包相关

### 看不到任何网卡 / 网卡列表为空

- **Linux**：确认已安装 `libpcap`（`sudo apt-get install -y libpcap0.8`），并检查当前用户是否有抓包权限。
- **Windows**：确认已安装 [Npcap](https://npcap.com/#download)，且安装时勾选了
  `Install Npcap in WinPcap API-compatible Mode`。若仍无法打开网卡，用管理员身份运行终端。
- **macOS**：系统自带 libpcap，通常无需额外安装；`/dev/bpf*` 权限由启动器在需要时申请。

用 `python main.py --list-devices` 可以脱离 GUI 单独验证设备枚举。

### 只有某一张网卡能抓到包

通常正常。只有当前真正承载流量的网卡会持续出现数据包。虚拟网卡、蓝牙、
回环接口、VPN 或未联网接口可能长期没有流量。

### 设置了 BPF 却没有包

按可能性依次排查：

- BPF 写得过窄；
- 选错网卡；
- 当前确实没有对应流量；
- 权限不足（Windows 尤其常见）。

建议先用最宽的条件确认链路通：

```text
tcp or udp
```

确认能抓到包后再逐步收窄。注意空 BPF 表示抓全部流量，不会回退到默认值。

### Windows 看不到 `en0`

`en0` 是 macOS/BSD 风格接口名，Windows Npcap 使用 `\Device\NPF_{GUID}` 形式。
界面上的 macOS 映射只是可读性提示，底层始终使用真实设备名。

### 抓包时丢失数据包

界面状态栏与统计面板会显示丢包计数，来源有两处：

- 内核/BPF 缓冲区丢弃（libpcap `pcap_stats` 采样）；
- 用户态队列满（`raw_queue` 或事件队列溢出）。

用户态队列上限默认 10000，溢出会计入丢包并限速告警。若持续丢包，先收窄 BPF
减少无关流量；提高队列上限会同步增加内存占用，需结合部署环境权衡。

## 显示与界面

### 出现 `OTHER` 协议

`OTHER` 表示解析器未识别该协议，或该包不是常见 IPv4/TCP/UDP 流量。可检查 BPF、
网卡选择，以及协议详情中的 EtherType。本工具当前只解析 IPv4（不支持 IPv6）。

### 协议详情里有"解析问题"

这是预期行为。"解析问题"面板列出截断包、无效长度/偏移等畸形包，异常包不会被丢弃，
而是标记问题后继续流转。双击条目可定位到对应数据包。

### 主题切换后按钮位置跳动

当前版本已修复：实现上固定 ttk 主题（`clam`），只切换颜色配置，不在明暗模式之间
切换主题结构，因此不会重新计算按钮 padding 与边框。若仍看到跳动，请确认运行的是
最新代码。

### 窗口位置或布局异常

窗口位置、大小、分隔条位置、列宽、排序状态、上次网卡与过滤条件都保存在
`~/.netguard_config.json`。若接外接显示器后窗口跑到屏外，恢复时会被钳制回可见区域；
仍异常时可直接删除该文件，下次启动会重建默认布局。

## 检测与告警

### 有流量但没有告警

依次确认：

1. 是否加载了规则——点击"加载规则"，或启动时用 `--rules` 指定文件；
2. 规则内容是否匹配当前流量（协议、端口、`content` 都要对上）；
3. 检测器是否达到阈值——默认阈值面向演示，见 [usage.md](usage.md) 的检测器表。

从零开始验证时，可用示例样本直接复现告警：

```bash
python scripts/build_sample_pcap.py
python main.py --read docs/samples/sample.pcap --alerts-json alerts.json
```

样本固定包含端口扫描与 SYN flood，应当产出对应告警。

### 告警数量异常多

同源同类攻击在短窗口内会持续告警。检测器内部有去重（同一 (规则, 流) 在抑制窗口内
只告警一次），但不同源或不同规则的攻击会分别告警。可结合 BPF 或显示过滤缩小范围。

## 运行环境

### 提示 Python 版本过低

需要 Python 3.11+。`scripts/launch.py` 统一负责解释器选择与版本校验，优先级为
`NETGUARD_PYTHON` → 项目内 `.venv` → `PATH`。用 `--setup` 可自动建环境：

```bash
python scripts/launch.py --setup --no-run   # 只建 .venv 并安装
```

### 无图形界面环境

`--no-gui` 走控制台预览，`--read` 走离线回放，两者都不需要显示环境。
GUI 相关测试在无显示器时自动跳过。

### 中文显示为方块

Linux 需要中文字体，例如 `sudo apt-get install -y fonts-noto-cjk`。
