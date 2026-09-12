# Linux 可执行文件分发指南

本指南用于把 NetGuard 的 Linux 可执行文件分发到其他 Linux 机器上运行。

重要：Linux 可执行文件必须在 Linux 上构建，不能直接使用 macOS 或 Windows 上生成的产物。构建机和目标机架构应一致，例如都为 `x86_64 Linux`。

## 目标机器系统依赖

NetGuard 抓包依赖 `libpcap`，图形界面依赖 Tk/桌面显示环境。

Debian / Ubuntu：

```bash
sudo apt update
sudo apt install libpcap0.8 tk
```

Fedora：

```bash
sudo dnf install libpcap tk
```

如果目标机器没有桌面环境，只能使用命令行预览模式；图形界面需要 X11 或 Wayland 会话。

## 推荐构建方式

在 Linux 构建机上安装构建依赖：

```bash
sudo apt update
sudo apt install python3 python3-venv python3-tk libpcap0.8 libpcap-dev
```

创建构建环境并安装 PyInstaller：

```bash
cd /path/to/NetGuard
python3 -m venv .venv-build
. .venv-build/bin/activate
python -m pip install -U pip pyinstaller
python -m pip install -e .
```

生成可执行文件：

```bash
pyinstaller --name NetGuard --onefile --windowed main.py
```

产物位于：

```text
dist/NetGuard
```

如果希望保留终端输出和错误信息，可去掉 `--windowed`：

```bash
pyinstaller --name NetGuard --onefile main.py
```

## 分发内容

至少分发：

```text
dist/NetGuard
```

建议同时附带：

```text
README.md
docs/distribute-linux.md
```

如果你使用目录模式打包，而不是 `--onefile`，需要分发整个 `dist/NetGuard/` 目录，不要只复制其中某一个文件。

## 目标机器运行

赋予执行权限：

```bash
chmod +x NetGuard
```

列出接口：

```bash
./NetGuard --list-devices
```

启动图形界面：

```bash
sudo ./NetGuard
```

命令行抓包预览：

```bash
sudo ./NetGuard --no-gui --interface eth0 --bpf "tcp or udp"
```

## 抓包权限

抓包通常需要 root 权限，因此推荐：

```bash
sudo ./NetGuard
```

如果不想每次使用 `sudo`，可以在受控实验环境中给可执行文件加能力：

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./NetGuard
```

如果加能力后仍无法打开接口，说明该打包方式或系统策略不支持此路径，请改用 `sudo ./NetGuard`。

## 常见问题

- `libpcap.so` 找不到：安装 `libpcap0.8` / `libpcap`。
- 图形界面打不开：安装 `tk`，并确认处于可用的 X11/Wayland 桌面会话。
- 无法打开网卡：使用 `sudo`，或检查系统抓包权限策略。
- 文件无法执行：确认目标机 CPU 架构和构建机一致，并执行 `chmod +x NetGuard`。
- 在较旧系统上无法运行：请在和目标系统版本接近的 Linux 环境中重新构建。
