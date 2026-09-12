# NetGuard 实验使用流程

## 1. 实验目标

通过 NetGuard 完成一次授权网络环境下的抓包、协议识别、流量统计和 IDS 告警演示。实验重点包括：

- 正确选择当前平台的抓包网卡
- 使用 BPF 控制抓包范围
- 观察 TCP、UDP、DNS、HTTP 等常见流量
- 加载 IDS 规则并触发告警
- 查看协议详情、十六进制数据和统计信息
- 切换夜间模式并确认按钮布局稳定
- 导出告警结果作为实验记录

## 2. 实验前准备

### 2.1 确认授权范围

只在自己拥有权限的设备、实验室网络或指定测试网段中使用 NetGuard。不要抓取无授权网络、公共网络或他人设备流量。

### 2.2 安装运行依赖

macOS / Linux 通常需要系统提供 `libpcap`。Windows 需要安装 Npcap，并建议安装时勾选：

```text
Install Npcap in WinPcap API-compatible Mode
```

如果 Windows 无法打开网卡，请使用管理员身份运行 PowerShell 或终端。

### 2.3 安装项目依赖

在项目根目录执行：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## 3. 启动方式

### 3.1 查看网卡列表

先列出当前系统可用抓包接口：

```bash
python main.py --list-devices
```

macOS 常见接口：

```text
en0
en1
lo0
```

Windows 常见接口：

```text
\Device\NPF_{GUID}
Npcap Loopback Adapter
Wi-Fi
Ethernet
```

NetGuard 会在 Windows 界面中显示 Mac 风格提示，例如：

```text
Wi-Fi 6 Adapter - Windows Wi-Fi 6 Adapter 对应 Mac en0（无线）
Intel Ethernet - Windows Intel Ethernet 对应 Mac en1（有线）
Npcap Loopback Adapter - Windows Npcap Loopback Adapter 对应 Mac lo0（回环）
```

### 3.2 启动图形界面

macOS / Linux：

```bash
sudo python main.py
```

Windows：

```powershell
python main.py
```

如果 Windows 报权限错误，请使用管理员身份重新运行。

## 4. 网卡选择流程

### 4.1 macOS

一般选择 `en0`。如果当前机器使用外接网卡或有线网络，也可能是 `en1` 或其他 `enX`。

推荐判断方式：

- Wi-Fi 上网：通常选择 `en0`
- 有线或 USB 网卡：可能选择 `en1` 或更高编号
- 本机回环测试：选择 `lo0`

### 4.2 Windows

Windows 不会原生提供 `en0` 名称。NetGuard 会自动推断对应关系：

- Wi-Fi / Wireless / WLAN：对应 Mac `en0`
- Ethernet / LAN：对应 Mac `en1` 或后续编号
- Npcap Loopback Adapter：对应 Mac `lo0`
- Hyper-V / VMware / VPN / Tunnel：标注为虚拟或 VPN 接口

如果实验要求“达到 Mac 上选择 en0 的效果”，Windows 上通常选择当前正在联网的 Wi-Fi 网卡；如果机器通过网线联网，则选择 Ethernet 网卡。

### 4.3 手动修改映射

如果自动推断不符合实验机器环境：

1. 在网卡下拉框中选择目标 Windows 网卡
2. 在 `Mac映射` 输入框中填写 `en0`、`en1` 或 `lo0`
3. 点击 `应用映射`
4. 如需恢复默认规则，点击 `自动推断`

注意：该映射只影响界面提示。真正抓包仍使用系统返回的真实接口名。

## 5. 设置 BPF 抓包过滤

BPF 会影响实际抓包范围。实验中建议从宽到窄逐步设置。

常用过滤示例：

```text
tcp or udp
port 53
port 80
tcp port 80
udp port 53
net 192.168.1.0/24
host 192.168.1.10
```

推荐实验设置：

```text
tcp or udp
```

如果需要观察实验室指定网段：

```text
net 192.168.1.0/24
```

将其中的网段替换为实际授权实验网段。

## 6. 加载 IDS 规则

在底部 `IDS 规则` 区域输入规则，然后点击 `加载规则`。

HTTP GET 检测示例：

```text
alert tcp any any -> any 80 (content "GET"; msg "检测到 HTTP GET 请求";)
```

DNS 域名关键字检测示例：

```text
alert udp any any -> any 53 (content "example"; msg "检测到 DNS 查询关键字";)
```

可以同时加载多条规则，每行一条。

## 7. 开始抓包

按以下顺序操作：

1. 选择网卡
2. 确认 Windows/Mac 接口提示是否符合预期
3. 填写 BPF
4. 填写或确认 IDS 规则
5. 点击 `加载规则`
6. 点击 `开始`

启动后观察主界面：

- 左侧包列表出现实时数据包
- 协议列显示 TCP、UDP、DNS、HTTP 或 OTHER
- 右侧协议详情显示分层解析结果
- 十六进制视图显示原始数据
- 统计面板显示包数、字节数、每秒速率和协议分布
- 告警面板显示 IDS 命中结果

## 8. 夜间模式验证

点击顶部 `夜间模式` 开关，可以在浅色和深色界面之间切换。

验证重点：

- 窗口背景、按钮、输入框、下拉框、表格、文本区、告警列表和统计区域都会切换配色。
- 切换前后顶部工具栏按钮位置应保持不变。
- 夜间模式只影响显示效果，不影响抓包、BPF、IDS 规则、统计或导出功能。

对应实现：

| 文件 | 说明 |
| --- | --- |
| `src/netguard/gui/main_ui.py` | `dark_mode` 保存开关状态 |
| `src/netguard/gui/main_ui.py` | `_apply_theme()` 统一应用浅色/深色颜色配置 |
| `src/netguard/gui/main_ui.py` | 固定 ttk 主题，只改颜色，避免切换时按钮尺寸和位置变化 |

## 9. 生成实验流量

### 9.1 DNS 流量

打开浏览器访问网站，或执行：

```bash
nslookup example.com
```

预期效果：

- 包列表出现 UDP/53 或 DNS 相关流量
- 如果加载了 DNS 规则，告警区域出现对应提示

### 9.2 HTTP 流量

访问 HTTP 测试站点，或在实验服务中发起 HTTP 请求。

示例：

```bash
curl http://example.com
```

预期效果：

- 包列表出现 TCP/80 流量
- 协议详情中可看到 HTTP 相关信息
- 如果加载了 HTTP GET 规则，告警区域出现“检测到 HTTP GET 请求”

### 9.3 TCP / UDP 基础流量

可以使用浏览器、ping、DNS 查询或实验室提供的测试服务产生基础流量。注意：`ping` 通常是 ICMP，如果 BPF 设置为 `tcp or udp`，不会显示 ICMP 包。

## 10. 查看与分析结果

### 10.1 包列表

重点观察：

- 时间：数据包捕获时间
- 源地址：发送方 IP 和端口
- 目的地址：接收方 IP 和端口
- 协议：TCP、UDP、DNS、HTTP 或 OTHER
- 长度：数据包长度
- 摘要：协议摘要或异常提示

### 10.2 协议详情

点击某个数据包后，右侧展示解析结果。可用于说明：

- Ethernet 层字段
- IP 源地址和目的地址
- TCP/UDP 端口
- HTTP 或 DNS 识别结果
- 异常包或未知协议说明

### 10.3 十六进制视图

十六进制视图展示原始包内容，适合在实验报告中说明“协议解析来自原始字节流”。

### 10.4 统计面板

统计面板用于观察：

- 总数据包数
- 总字节数
- 活跃会话数
- 每秒数据包
- 每秒字节
- 协议分布
- 丢弃数据包数量

## 11. 暂停、清空和导出

### 11.1 暂停刷新

点击 `暂停刷新` 可以暂停界面追加新数据，后台抓包仍可继续。适合在高流量场景中查看某个包的详情。

### 11.2 清空视图

点击 `清空` 会清空当前界面中的包列表、告警、详情和十六进制视图。适合重新开始一轮实验。

### 11.3 导出告警

点击 `导出告警`，选择 `.log` 或 `.txt` 文件保存告警记录。导出前应确认不包含敏感信息。

## 12. 停止实验

实验结束后：

1. 点击 `停止`
2. 确认统计结果和告警结果
3. 导出需要保留的告警日志
4. 关闭 NetGuard

如果使用命令行模式或终端运行，可以按 `Ctrl+C` 停止。

## 13. 验收效果

实验完成后应能证明以下效果：

- 能正确枚举当前平台网卡
- Windows 下能看到对应 Mac 接口类型提示
- 能选择等价于 Mac `en0` 的 Windows 主联网网卡
- 能通过 BPF 控制抓包范围
- 能捕获 TCP/UDP/DNS/HTTP 等实验流量
- 能查看协议详情和原始十六进制数据
- 能触发至少一条 IDS 告警
- 能查看统计信息并导出告警记录
- 能切换夜间模式，且按钮位置不发生跳动

## 14. 常见问题

### 14.1 Windows 看不到 en0

这是正常现象。`en0` 是 macOS/BSD 风格接口名，Windows Npcap 使用 `\Device\NPF_{GUID}`。NetGuard 的 Mac 映射只是界面提示，底层仍使用真实 Windows 设备名。

### 14.2 只能某一张网卡抓到包

通常正常。只有当前真正承载网络流量的网卡会持续出现数据包。虚拟网卡、蓝牙、回环、VPN 或未联网接口可能没有实验流量。

### 14.3 BPF 设置后没有包

可能原因：

- BPF 写得过窄
- 选错网卡
- 当前没有对应流量
- Windows 权限不足

建议先使用：

```text
tcp or udp
```

确认能抓到包后再缩小范围。

### 14.4 出现 OTHER 协议

`OTHER` 表示当前解析器未识别该协议，或数据包不是常见 IPv4/TCP/UDP 流量。可以检查 BPF、网卡选择和协议详情中的 EtherType。

### 14.5 夜间模式切换时按钮移动

当前版本已经修复该问题。实现方式是固定 ttk 主题，只切换颜色，不在浅色/深色之间切换 ttk 主题结构。如果仍看到按钮移动，请确认运行的是最新代码。
