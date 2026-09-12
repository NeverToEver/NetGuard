# Windows 安装与配置

Windows 平台使用 Npcap / WinPcap 原生 `wpcap.dll` 接口。

## 安装 Npcap

1. 从 Npcap 官方网站安装 Npcap。
2. 安装时勾选 `Install Npcap in WinPcap API-compatible Mode`。
3. 如需普通用户抓包，可按实验室要求配置 Npcap 权限；否则以管理员身份运行。

## 安装项目

```powershell
cd C:\path\to\NetGuard
py -m pip install -e .
```

## 运行

```powershell
py main.py --list-devices
py main.py
```

## Windows 与 Mac 接口提示

Windows 上 Npcap 返回的真实抓包接口通常是 `\Device\NPF_{GUID}`，不会原生提供 macOS 的 `en0`、`en1` 名称。NetGuard 会在界面中为每个 Windows 网卡附加 Mac 对应提示，例如：

```text
Wi-Fi 6 Adapter - Windows Wi-Fi 6 Adapter 对应 Mac en0（无线）
Intel Ethernet - Windows Intel Ethernet 对应 Mac en1（有线）
Npcap Loopback Adapter - Windows Npcap Loopback Adapter 对应 Mac lo0（回环）
```

自动推断规则优先把 Wi-Fi 映射为 `en0`，其次映射有线 Ethernet，再处理其他虚拟/VPN/未知接口。这个映射只是界面提示和操作习惯别名；开始抓包时程序仍会使用 Npcap 的真实接口名。

如果自动推断不符合当前机器环境，可以在界面的 `Mac映射` 输入框中填写 `en0`、`en1` 等名称并点击 `应用映射`；点击 `自动推断` 可恢复默认规则。

如果无法打开网卡，请使用管理员 PowerShell 运行。
