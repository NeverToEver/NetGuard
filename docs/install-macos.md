# macOS 安装与配置

macOS 通常自带 `libpcap.dylib`，NetGuard 会自动查找。

## 依赖

需要 Python 3.11+，并确保 Tk 可用。使用 python.org 安装包通常自带 Tk 支持。

```bash
cd /path/to/NetGuard
/opt/homebrew/bin/python3.12 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -e .
```

如果使用 python.org 或其他 Python 3.11+ 解释器，也可以替换为对应解释器路径：

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -e .
```

VS Code 调试和 `scripts/run_netguard.sh` 会自动检测可用的 Python 3.11+ 解释器，优先使用 `NETGUARD_PYTHON`、项目内 `.venv/bin/python`、常见 Homebrew/Python 路径。缺失时会提示创建项目内环境。

## 运行

列出接口：

```bash
./scripts/run_netguard.sh --list-devices
```

启动图形界面：

```bash
sudo ./scripts/run_netguard.sh
```

常见接口包括 `en0`、`en1`、`lo0`。如果出现 `/dev/bpf* Permission denied`，请使用 `sudo` 启动。

## 打包

先激活或准备一个包含 Python 和 Tk 的运行环境，然后指定该环境路径：

```bash
python3 scripts/build_unix_app.py --python-env /path/to/python-env
```

生成产物包括 `dist/NetGuard`、`dist/NetGuard-portable/NetGuard` 和 `dist/NetGuard.app`。

双击 `dist/NetGuard.app` 启动时，系统会弹出管理员密码窗口；授权后 NetGuard 会调整 `/dev/bpf*` 抓包设备权限，然后以当前用户身份启动图形界面。
