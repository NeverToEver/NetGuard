# 使用说明

## 启动

```bash
./scripts/run_netguard.sh
```

启动脚本会自动检测可用的 Python 3.11+ 解释器，优先使用 `NETGUARD_PYTHON`、项目内 `.venv/bin/python`、常见 Homebrew/Python 路径。如果没有找到合适解释器，会提示创建项目内环境。

打包后可运行：

```bash
sudo ./dist/NetGuard
```

## 图形界面

- 顶部工具栏：选择网卡、填写 BPF、开始/停止监听、暂停刷新、清空、导出告警。
- 包列表：显示时间、源地址、目的地址、协议、长度和摘要。
- 右侧详情：显示协议解析结果和原始数据十六进制内容。
- 底部区域：显示 IDS 告警、实时统计和规则编辑框。

## 常用过滤

BPF 过滤会影响实际抓包范围：

```text
tcp
udp
port 53
port 80
tcp or udp
net 192.168.1.0/24
```

界面内“显示过滤”只过滤当前列表，不影响后台抓包。可输入协议、IP、端口、HTTP Host 或 DNS 域名关键字。

## IDS 规则

```text
alert tcp any any -> any 80 (content "GET"; msg "检测到 HTTP GET 请求";)
```

当前支持协议、源/目的端口、`content` 和 `msg`。规则修改后点击“加载规则”或重新开始监听。
