from __future__ import annotations

import argparse
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
ASSETS = SRC / "netguard" / "assets"
DIST = ROOT / "dist"
BUILD = ROOT / "build" / "unix-app"
APP_NAME = "NetGuard"
APP_BUNDLE = DIST / f"{APP_NAME}.app"
PORTABLE_DIR = DIST / f"{APP_NAME}-portable"
DEFAULT_PYTHON_ENV = os.environ.get("VIRTUAL_ENV", "")


def _read_version() -> str:
    """从 netguard._version 读取版本号，避免与 pyproject 出现第二份拷贝。

    不 import netguard：打包脚本运行时 sys.path 上未必有 src/，且此处只需一个常量。
    """
    source = (SRC / "netguard" / "_version.py").read_text(encoding="utf-8")
    for line in source.splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit(f"无法从 {SRC / 'netguard' / '_version.py'} 解析版本号")


def main() -> None:
    parser = argparse.ArgumentParser(description="构建内置 Python 运行环境的 NetGuard Unix/macOS 应用")
    parser.add_argument(
        "--python-env",
        default=os.environ.get("NETGUARD_PYTHON_ENV", DEFAULT_PYTHON_ENV),
        help="要打包的 Python 环境路径",
    )
    args = parser.parse_args()

    if not args.python_env:
        raise SystemExit("请通过 --python-env 指定 Python 环境路径，或先激活虚拟环境后再运行脚本。")
    env_path = Path(args.python_env).expanduser().resolve()
    _validate_env(env_path)

    import platform as _platform

    if _platform.system() != "Darwin":
        raise SystemExit("此脚本用于构建 macOS .app / Unix 便携包，当前平台不是 macOS。")

    with _StagedEnv(env_path) as build_env:
        DIST.mkdir(parents=True, exist_ok=True)
        BUILD.mkdir(parents=True, exist_ok=True)
        _ensure_icons()
        _build_portable_dir(build_env)
        try:
            _build_app_bundle(build_env)
        except BaseException:
            # 构建中途失败必须回收半成品 bundle，否则 dist 里留下
            # "便携目录 OK、.app 半残" 的混态且无任何提示
            if APP_BUNDLE.exists():
                shutil.rmtree(APP_BUNDLE, ignore_errors=True)
            raise

    print(f"已打包 Python 运行环境：{env_path}")
    print(f"已生成便携 Unix 应用目录：{PORTABLE_DIR}")
    print(f"已生成 macOS 应用包：{APP_BUNDLE}")


def _validate_env(env_path: Path) -> None:
    python = env_path / "bin" / "python"
    if not python.exists():
        raise SystemExit(f"找不到 Python 解释器：{python}")
    try:
        _python_tk_support(env_path)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"当前环境无法导入 Tkinter：{python}") from exc


class _StagedEnv:
    def __init__(self, env_path: Path) -> None:
        self.env_path = env_path
        self.temp_dir: tempfile.TemporaryDirectory[str] | None = None
        self.staged_path = env_path

    def __enter__(self) -> Path:
        try:
            self.env_path.relative_to(DIST.resolve())
        except ValueError:
            return self.env_path

        self.temp_dir = tempfile.TemporaryDirectory(prefix="netguard-python-env-")
        self.staged_path = Path(self.temp_dir.name) / "python-env"
        shutil.copytree(self.env_path, self.staged_path, symlinks=True, ignore=_ignore_env_noise)
        return self.staged_path

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.temp_dir is not None:
            self.temp_dir.cleanup()


def _ensure_icons() -> None:
    png_path = ASSETS / "netguard-icon.png"
    icns_path = ASSETS / "netguard-icon.icns"
    if png_path.exists() and icns_path.exists():
        return
    try:
        from PIL import Image, ImageDraw, ImageFilter
    except ModuleNotFoundError as exc:
        raise SystemExit("缺少图标文件，且当前 Python 没有 Pillow，无法重新生成图标。") from exc

    ASSETS.mkdir(parents=True, exist_ok=True)
    size = 1024
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    for y in range(size):
        t = y / (size - 1)
        draw.line([(0, y), (size, y)], fill=(int(15 + 2 * t), int(118 - 94 * t), int(110 - 71 * t), 255))
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size, size), radius=220, fill=255)
    image.putalpha(mask)
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse((170, 140, 854, 850), fill=(45, 212, 191, 48))
    image.alpha_composite(glow.filter(ImageFilter.GaussianBlur(30)))
    shield = [
        (512, 142),
        (780, 252),
        (780, 470),
        (764, 586),
        (714, 694),
        (628, 788),
        (512, 882),
        (396, 788),
        (310, 694),
        (260, 586),
        (244, 470),
        (244, 252),
    ]
    inner = [
        (512, 205),
        (716, 288),
        (716, 462),
        (704, 548),
        (666, 630),
        (602, 708),
        (512, 784),
        (422, 708),
        (358, 630),
        (320, 548),
        (308, 462),
        (308, 288),
    ]
    draw.polygon(shield, fill=(241, 245, 249, 255))
    draw.polygon(inner, fill=(15, 23, 42, 255))
    draw.line([(338, 486), (686, 486)], fill=(56, 189, 248, 255), width=42)
    draw.line([(512, 326), (512, 646)], fill=(45, 212, 191, 255), width=42)
    for x, y, color in [
        (338, 486, (34, 211, 238, 255)),
        (512, 326, (45, 212, 191, 255)),
        (686, 486, (34, 211, 238, 255)),
        (512, 646, (45, 212, 191, 255)),
    ]:
        draw.ellipse((x - 58, y - 58, x + 58, y + 58), fill=color)
        draw.ellipse((x - 28, y - 28, x + 28, y + 28), fill=(240, 253, 250, 255))
    image.save(png_path)
    image.save(icns_path, format="ICNS")


def _build_portable_dir(env_path: Path) -> None:
    if PORTABLE_DIR.exists():
        shutil.rmtree(PORTABLE_DIR)
    PORTABLE_DIR.mkdir(parents=True)
    _copy_app(PORTABLE_DIR / "app")
    _copy_env(env_path, PORTABLE_DIR / "python-env")
    _write_launcher(
        PORTABLE_DIR / APP_NAME,
        """#!/bin/sh
BASE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export TK_SILENCE_DEPRECATION=1
export PYTHONDONTWRITEBYTECODE=1
[ -d "$BASE_DIR/python-env/lib/tcl9.0" ] && export TCL_LIBRARY="$BASE_DIR/python-env/lib/tcl9.0"
[ -d "$BASE_DIR/python-env/lib/tk9.0" ] && export TK_LIBRARY="$BASE_DIR/python-env/lib/tk9.0"
[ -d "$BASE_DIR/python-env/lib/tcl8.6" ] && export TCL_LIBRARY="$BASE_DIR/python-env/lib/tcl8.6"
[ -d "$BASE_DIR/python-env/lib/tk8.6" ] && export TK_LIBRARY="$BASE_DIR/python-env/lib/tk8.6"
exec "$BASE_DIR/python-env/bin/python" "$BASE_DIR/app/main.py" "$@"
""",
    )

    legacy = DIST / APP_NAME
    if legacy.is_symlink() or (legacy.exists() and legacy.is_file()):
        legacy.unlink()
    elif legacy.is_dir():
        # 历史版本产物可能是目录，Path.unlink 会抛 IsADirectoryError
        shutil.rmtree(legacy)
    _write_launcher(
        legacy,
        f"""#!/bin/sh
DIST_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "$DIST_DIR/{APP_NAME}-portable/{APP_NAME}" "$@"
""",
    )


def _build_app_bundle(env_path: Path) -> None:
    if APP_BUNDLE.exists():
        shutil.rmtree(APP_BUNDLE)
    macos_dir = APP_BUNDLE / "Contents" / "MacOS"
    resources_dir = APP_BUNDLE / "Contents" / "Resources"
    macos_dir.mkdir(parents=True)
    resources_dir.mkdir(parents=True)

    _copy_app(resources_dir / "app")
    _copy_env(env_path, resources_dir / "python-env")
    shutil.copy2(ASSETS / "netguard-icon.icns", resources_dir / "netguard-icon.icns")
    _write_launcher(
        resources_dir / "prepare_bpf.sh",
        """#!/bin/sh
set -eu

TARGET_USER="${1:-}"
if [ -z "$TARGET_USER" ]; then
    exit 2
fi

for dev in /dev/bpf*; do
    [ -e "$dev" ] || continue
    /usr/sbin/chown "$TARGET_USER":admin "$dev"
    /bin/chmod u+rw,g+rw "$dev"
done
""",
    )
    _write_macos_launcher(macos_dir / APP_NAME)

    version = _read_version()
    plist = {
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleIdentifier": "local.netguard.app",
        "CFBundleVersion": version,
        "CFBundleShortVersionString": version,
        "CFBundleExecutable": APP_NAME,
        "CFBundlePackageType": "APPL",
        "CFBundleIconFile": "netguard-icon.icns",
        "LSMinimumSystemVersion": "10.13",
        "NSHighResolutionCapable": True,
        "LSEnvironment": {"TK_SILENCE_DEPRECATION": "1"},
    }
    with (APP_BUNDLE / "Contents" / "Info.plist").open("wb") as handle:
        plistlib.dump(plist, handle)
    (APP_BUNDLE / "Contents" / "PkgInfo").write_text("APPL????", encoding="ascii")
    _sign_app_bundle(APP_BUNDLE)


def _write_macos_launcher(path: Path) -> None:
    source = BUILD / "NetGuardLauncher.c"
    source.write_text(
        r"""#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <pwd.h>
#include <Security/Authorization.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef kAuthorizationRightExecute
#define kAuthorizationRightExecute "system.privilege.admin"
#endif

static void dirname_in_place(char *path) {
    char *slash = strrchr(path, '/');
    if (slash == NULL) {
        strcpy(path, ".");
    } else if (slash == path) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
}

static void join_path(char *out, size_t out_size, const char *left, const char *right) {
    snprintf(out, out_size, "%s/%s", left, right);
}

static int run_admin_prepare(const char *resources_dir) {
    if (getuid() == 0) {
        return 0;
    }

    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_name == NULL) {
        return 1;
    }

    char helper_path[PATH_MAX];
    join_path(helper_path, sizeof(helper_path), resources_dir, "prepare_bpf.sh");

    AuthorizationRef auth = NULL;
    OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &auth);
    if (status != errAuthorizationSuccess) {
        return (int)status;
    }

    AuthorizationItem right = {kAuthorizationRightExecute, 0, NULL, 0};
    AuthorizationRights rights = {1, &right};
    AuthorizationFlags flags = kAuthorizationFlagInteractionAllowed | kAuthorizationFlagPreAuthorize
        | kAuthorizationFlagExtendRights;
    status = AuthorizationCopyRights(auth, &rights, NULL, flags, NULL);
    if (status != errAuthorizationSuccess) {
        AuthorizationFree(auth, kAuthorizationFlagDefaults);
        return (int)status;
    }

    char *args[] = {
        pw->pw_name,
        NULL,
    };
    FILE *pipe = NULL;
    /* NOTE: AuthorizationExecuteWithPrivileges is deprecated since macOS 10.7.
 * Consider migrating to SMJobBless + XPC for a modern privilege-separated helper.
 * This is acceptable for a developer tool but unsuitable for distribution. */
    status = AuthorizationExecuteWithPrivileges(auth, helper_path, kAuthorizationFlagDefaults, args, &pipe);
    if (status != errAuthorizationSuccess) {
        AuthorizationFree(auth, kAuthorizationFlagDefaults);
        return (int)status;
    }

    if (pipe != NULL) {
        char buffer[256];
        while (fread(buffer, 1, sizeof(buffer), pipe) > 0) {
        }
        fclose(pipe);
    }
    AuthorizationFree(auth, kAuthorizationFlagDestroyRights);
    return 0;
}

int main(void) {
    char executable[PATH_MAX];
    uint32_t size = sizeof(executable);
    if (_NSGetExecutablePath(executable, &size) != 0) {
        return 1;
    }

    char macos_dir[PATH_MAX];
    char contents_dir[PATH_MAX];
    char resources_dir[PATH_MAX];
    strncpy(macos_dir, executable, sizeof(macos_dir));
    macos_dir[sizeof(macos_dir) - 1] = '\0';
    dirname_in_place(macos_dir);
    strncpy(contents_dir, macos_dir, sizeof(contents_dir));
    contents_dir[sizeof(contents_dir) - 1] = '\0';
    dirname_in_place(contents_dir);
    join_path(resources_dir, sizeof(resources_dir), contents_dir, "Resources");

    int prep_rc = run_admin_prepare(resources_dir);
    if (prep_rc != 0) {
        return prep_rc;
    }

    char python_path[PATH_MAX];
    char main_path[PATH_MAX];
    char tcl_path[PATH_MAX];
    char tk_path[PATH_MAX];
    join_path(python_path, sizeof(python_path), resources_dir, "python-env/bin/python");
    join_path(main_path, sizeof(main_path), resources_dir, "app/main.py");
    join_path(tcl_path, sizeof(tcl_path), resources_dir, "python-env/lib/tcl9.0");
    join_path(tk_path, sizeof(tk_path), resources_dir, "python-env/lib/tk9.0");

    setenv("TK_SILENCE_DEPRECATION", "1", 1);
    setenv("PYTHONDONTWRITEBYTECODE", "1", 1);
    if (access(tcl_path, F_OK) == 0) {
        setenv("TCL_LIBRARY", tcl_path, 1);
    } else {
        join_path(tcl_path, sizeof(tcl_path), resources_dir, "python-env/lib/tcl8.6");
        if (access(tcl_path, F_OK) == 0) {
            setenv("TCL_LIBRARY", tcl_path, 1);
        }
    }
    if (access(tk_path, F_OK) == 0) {
        setenv("TK_LIBRARY", tk_path, 1);
    } else {
        join_path(tk_path, sizeof(tk_path), resources_dir, "python-env/lib/tk8.6");
        if (access(tk_path, F_OK) == 0) {
            setenv("TK_LIBRARY", tk_path, 1);
        }
    }

    execl(python_path, python_path, main_path, (char *)NULL);
    return 1;
}
""",
        encoding="utf-8",
    )
    clang = shutil.which("clang") or "/usr/bin/clang"
    if not Path(clang).exists():
        raise SystemExit("构建 macOS .app 需要 clang。请先安装 Xcode Command Line Tools。")
    subprocess.run(
        [
            clang,
            "-O2",
            "-Wall",
            "-Wextra",
            "-Wno-deprecated-declarations",
            str(source),
            "-framework",
            "Security",
            "-o",
            str(path),
        ],
        check=True,
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _sign_app_bundle(path: Path) -> None:
    codesign = Path("/usr/bin/codesign")
    if not codesign.exists():
        return
    result = subprocess.run(
        [str(codesign), "--force", "--deep", "--sign", "-", str(path)], check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Warning: codesign failed: {result.stderr.strip()}", file=sys.stderr)


def _copy_app(target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    shutil.copy2(ROOT / "main.py", target / "main.py")
    shutil.copytree(SRC, target / "src", ignore=_ignore_generated)


def _copy_env(source: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target, symlinks=True, ignore=_ignore_env_noise)
    _copy_tk_support(source, target)


def _python_tk_support(env_path: Path) -> dict[str, str]:
    python = env_path / "bin" / "python"
    probe = r"""
import json
import pathlib
import sysconfig
import tkinter
import _tkinter

tcl = tkinter.Tcl()
tcl_library = tcl.eval("info library")
tk_library = tcl.eval("set tk_library") if "tk_library" in tcl.eval("info globals") else ""
if not tk_library:
    version_parts = tcl.eval("info patchlevel").split(".")
    candidate = pathlib.Path(tcl_library).parent / f"tk{version_parts[0]}.{version_parts[1]}"
    if candidate.exists():
        tk_library = str(candidate)
print(json.dumps({
    "stdlib": sysconfig.get_path("stdlib"),
    "version": sysconfig.get_python_version(),
    "tkinter": tkinter.__file__,
    "_tkinter": _tkinter.__file__,
    "tcl_library": tcl_library,
    "tk_library": tk_library,
}))
"""
    result = subprocess.run([str(python), "-c", probe], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def _copy_tk_support(source_env: Path, target_env: Path) -> None:
    support = _python_tk_support(source_env)
    python_lib = target_env / "lib" / f"python{support['version']}"
    python_lib.mkdir(parents=True, exist_ok=True)

    tkinter_source = Path(support["tkinter"]).parent
    tkinter_target = python_lib / "tkinter"
    if tkinter_source.exists() and not tkinter_target.exists():
        shutil.copytree(tkinter_source, tkinter_target, ignore=_ignore_generated)

    tkinter_ext = Path(support["_tkinter"])
    dynload_target = python_lib / "lib-dynload"
    dynload_target.mkdir(parents=True, exist_ok=True)
    if tkinter_ext.exists():
        shutil.copy2(tkinter_ext, dynload_target / tkinter_ext.name)

    for key in ("tcl_library", "tk_library"):
        library = support.get(key)
        if not library:
            continue
        source = Path(library)
        target = target_env / "lib" / source.name
        if source.exists() and not target.exists():
            shutil.copytree(source, target, symlinks=True, ignore=_ignore_env_noise)


def _ignore_generated(_: str, names: list[str]) -> set[str]:
    return {name for name in names if name == "__pycache__" or name.endswith((".pyc", ".pyo"))}


def _ignore_env_noise(_: str, names: list[str]) -> set[str]:
    ignored = set()
    for name in names:
        if name in {"__pycache__", "share"} or name.endswith((".pyc", ".pyo", ".a")):
            ignored.add(name)
    return ignored


def _write_launcher(path: Path, content: str) -> None:
    # 固定 LF：Windows 宿主上文本模式默认换行翻译会写出 CRLF，Unix 下报 bad interpreter
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


if __name__ == "__main__":
    main()
