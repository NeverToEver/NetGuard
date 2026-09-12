# Linux 安装与配置

## 依赖

Debian / Ubuntu：

```bash
sudo apt update
sudo apt install python3 python3-tk libpcap0.8 libpcap-dev
```

Fedora：

```bash
sudo dnf install python3 python3-tkinter libpcap libpcap-devel
```

## 安装项目

```bash
cd /path/to/NetGuard
python3.12 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -e .
```

如果系统命令名不是 `python3.12`，也可以使用任意 Python 3.11+ 解释器创建项目内虚拟环境：

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -e .
```

VS Code 调试和 `scripts/run_netguard.sh` 会自动检测可用的 Python 3.11+ 解释器，优先使用 `NETGUARD_PYTHON`、项目内 `.venv/bin/python` 和系统常见 Python 路径。缺失时会提示创建项目内环境。

## 运行

列出网卡：

```bash
./scripts/run_netguard.sh --list-devices
```

启动图形界面：

```bash
sudo ./scripts/run_netguard.sh
```

命令行预览：

```bash
sudo ./scripts/run_netguard.sh --no-gui --interface eth0 --bpf "tcp or udp"
```

抓包通常需要 `sudo`。也可以为 Python 解释器配置 `CAP_NET_RAW` 和 `CAP_NET_ADMIN`，但这会影响该解释器运行的所有程序，实验环境中需谨慎使用。
