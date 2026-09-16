"""NetGuard 一键启动器。

统一的跨平台入口：先做环境自检，再调用 ``main.py``。所有启动方式
（``NetGuard.bat`` / ``NetGuard.sh`` / ``scripts/run_netguard.*``）最终都收敛到这里，
保证行为一致。

用法：
    python scripts/launch.py                 # 启动 GUI（默认）
    python scripts/launch.py --list-devices  # 透传给 main.py 的任意参数
    python scripts/launch.py --check         # 仅做环境自检并退出
    python scripts/launch.py --setup         # 创建 .venv 并安装，然后启动
    python scripts/launch.py --setup --no-run

除 ``--check`` / ``--setup`` / ``--no-run`` 外，其余参数原样转发给 ``main.py``。
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

MIN_PYTHON = (3, 11)
MIN_PYTHON_TEXT = ".".join(str(part) for part in MIN_PYTHON)

PROJECT_DIR = Path(__file__).resolve().parents[1]
MAIN_PY = PROJECT_DIR / "main.py"
SRC_DIR = PROJECT_DIR / "src"
VENV_DIR = PROJECT_DIR / ".venv"


def _version_tuple(info) -> tuple[int, int, int]:
    return (info.major, info.minor, info.micro)


def python_supported(version: tuple[int, int, int], minimum: tuple[int, int] = MIN_PYTHON) -> bool:
    """版本是否满足最低要求（只比较 major/minor，便于测试注入）。"""
    return version[:2] >= minimum


def _reconfigure_streams() -> None:
    """Windows 控制台重定向到管道时是 ANSI 代码页，放宽编码避免中文报错中断。"""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def venv_python(venv_dir: Path | None = None) -> Path:
    """返回虚拟环境内的解释器路径（不判断是否存在）。"""
    base = venv_dir if venv_dir is not None else VENV_DIR
    if os.name == "nt":
        return base / "Scripts" / "python.exe"
    return base / "bin" / "python"


def _check_display() -> tuple[bool, str]:
    try:
        import tkinter
    except ImportError as exc:  # pragma: no cover - 取决于本机是否装了 tk
        return False, f"未安装 tkinter（{exc}）"
    try:
        root = tkinter.Tk()
        root.withdraw()
        size = f"{root.winfo_screenwidth()}x{root.winfo_screenheight()}"
        root.destroy()
    except tkinter.TclError as exc:
        return False, f"无可用显示（{exc}）"
    return True, f"可用，屏幕 {size}"


def _check_capture() -> tuple[bool, str]:
    from netguard.capture.pcap import PcapError, create_backend

    try:
        backend = create_backend()
    except PcapError as exc:
        return False, str(exc)
    try:
        devices = backend.list_devices()
    finally:
        backend.close()
    if not devices:
        return False, "pcap 后端已加载，但未发现抓包设备"
    return True, f"pcap 后端正常，发现 {len(devices)} 个抓包设备"


def _check_rules() -> tuple[bool, str]:
    from netguard.rules.engine import DEFAULT_RULES, RuleEngine

    engine = RuleEngine()
    failed = engine.load([line for line in DEFAULT_RULES.splitlines() if line.strip()])
    loaded = len(engine.rules)
    return loaded > 0, f"内置规则加载 {loaded} 条（失败 {failed} 条）"


def run_check() -> int:
    """环境自检：打印各项能力状态，返回进程退出码。"""
    if str(SRC_DIR) not in sys.path:
        sys.path.insert(0, str(SRC_DIR))

    print("NetGuard 环境自检")
    print(f"  项目目录   {PROJECT_DIR}")
    print(f"  解释器     {sys.executable}")
    print(f"  Python     {sys.version.split()[0]} ({sys.platform})")

    version = _version_tuple(sys.version_info)
    checks: list[tuple[str, bool, str]] = []
    if python_supported(version):
        checks.append(("Python 版本", True, f"{'.'.join(map(str, version))} ≥ {MIN_PYTHON_TEXT}"))
    else:
        checks.append(("Python 版本", False, f"{'.'.join(map(str, version))} < {MIN_PYTHON_TEXT}"))

    if MAIN_PY.exists() and (SRC_DIR / "netguard").is_dir():
        checks.append(("源码结构", True, "main.py 与 src/netguard 均存在"))
    else:
        checks.append(("源码结构", False, "缺少 main.py 或 src/netguard，请检查是否在仓库根目录"))

    try:
        import netguard  # noqa: F401

        checks.append(("包导入", True, "import netguard 成功"))
    except Exception as exc:
        checks.append(("包导入", False, str(exc)))

    try:
        ok, detail = _check_capture()
    except Exception as exc:
        ok, detail = False, str(exc)
    checks.append(("抓包后端", ok, detail))

    try:
        ok, detail = _check_display()
    except Exception as exc:
        ok, detail = False, str(exc)
    checks.append(("图形界面", ok, detail))

    try:
        ok, detail = _check_rules()
    except Exception as exc:
        ok, detail = False, str(exc)
    checks.append(("IDS 规则", ok, detail))

    print("  检查项")
    fatal = False
    for name, ok, detail in checks:
        mark = "OK  " if ok else "FAIL"
        print(f"    [{mark}] {name:<10} {detail}")
        # 抓包后端缺失只影响实时抓包，离线回放与 GUI 仍可用，不算致命。
        if not ok and name in {"Python 版本", "源码结构", "包导入"}:
            fatal = True

    if fatal:
        print("自检未通过：请先解决上述 FAIL 项。")
        return 1
    print("自检通过：可运行 GUI 或离线回放。")
    return 0


def run_setup() -> int:
    """创建 .venv 并安装项目（零运行时依赖，安装只是为了注册包与入口）。"""
    target = venv_python()
    if not target.exists():
        print(f"创建虚拟环境：{VENV_DIR}")
        result = subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)])
        if result.returncode != 0:
            print("创建虚拟环境失败，请检查 Python 安装是否完整。", file=sys.stderr)
            return result.returncode
    else:
        print(f"虚拟环境已存在：{VENV_DIR}")

    print("安装项目到虚拟环境（pip install -e .）...")
    result = subprocess.run([str(target), "-m", "pip", "install", "-e", str(PROJECT_DIR)])
    if result.returncode != 0:
        print("安装失败；可直接用系统 Python 运行，无需安装。", file=sys.stderr)
        return result.returncode
    print(f"完成。启动请用：{target} main.py")
    return 0


def select_interpreter() -> Path:
    """选择运行 main.py 的解释器：优先仓库内 .venv，否则用当前解释器。"""
    current = Path(sys.executable)
    candidate = venv_python()
    if candidate.exists():
        try:
            if candidate.resolve() != current.resolve():
                return candidate
        except OSError:
            return candidate
    return current


def run_app(args: list[str]) -> int:
    """执行 main.py，原样转发参数并返回退出码（优先使用 .venv 解释器）。"""
    if not python_supported(_version_tuple(sys.version_info)):
        print(
            f"当前 Python {'.'.join(map(str, _version_tuple(sys.version_info)))} 低于要求 "
            f"{MIN_PYTHON_TEXT}，请先安装较新版本，或运行：python scripts/launch.py --setup",
            file=sys.stderr,
        )
        return 1
    if not MAIN_PY.exists() or not (SRC_DIR / "netguard").is_dir():
        print(f"未找到 main.py 或 src/netguard，请从仓库根目录运行（当前 {PROJECT_DIR}）。", file=sys.stderr)
        return 1
    interpreter = select_interpreter()
    try:
        return subprocess.call([str(interpreter), str(MAIN_PY), *args])
    except KeyboardInterrupt:
        return 130


def main(argv: list[str] | None = None) -> int:
    _reconfigure_streams()
    args = list(sys.argv[1:] if argv is None else argv)

    if "--check" in args:
        args.remove("--check")
        return run_check()

    if "--setup" in args:
        args.remove("--setup")
        code = run_setup()
        if code != 0:
            return code
        if "--no-run" in args:
            args.remove("--no-run")
            return 0

    return run_app(args)


if __name__ == "__main__":
    raise SystemExit(main())
