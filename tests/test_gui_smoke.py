"""GUI 冒烟测试：真实构造 Tk 窗口并演练关键交互，无显示环境自动跳过。

一个进程内反复创建/销毁 Tk 根窗口会让 Tcl 解释器失效，因此这里用模块级
单例窗口，每个用例只重置状态、不重建窗口。

显示探测放在子进程里并带超时，而不是在当前进程 `try: tk.Tk() except TclError`：

- 需要超时兜底。CI 上曾出现测试步骤长时间 in_progress 直至被取消；在那次
  现象中，同进程探测等不到任何异常，于是无从判定"无显示"也无法脱身。
  确切触发条件未能单独复现（同一轮还改了其他因素），因此这里按"防御"处理：
  无论 `tk.Tk()` 是抛错、返回还是卡住，探测都会在超时后给出"无显示"的结论，
  测试会话不会被拖死。配合 pyproject 的 pytest timeout 形成双重保险。
- 顺带避免把半初始化的 Tcl 状态留在测试进程里。

注意 macOS runner 实测是**能**创建 Tk 窗口的（GUI 用例全部执行，与
Windows/Linux 同为 264 passed），所以这些用例并非"在 macOS 上总是跳过"。
Linux CI 另经 Xvfb 提供虚拟显示。
"""

from __future__ import annotations

import queue
import subprocess
import sys
import time

import pytest

tk = pytest.importorskip("tkinter")

_app = None
_skip_reason = ""

#: 子进程探测 Tk 的超时（秒）。正常环境下一瞬间即可完成；超时即视为无显示。
_DISPLAY_PROBE_TIMEOUT = 30.0
_display_probe: tuple[bool, str] | None = None


def _probe_display() -> tuple[bool, str]:
    """在子进程中探测能否创建 Tk 窗口，结果缓存。

    用子进程而非当前进程：既能在挂起时靠超时脱身，又能避免把探测过程中可能
    产生的半初始化 Tcl 状态留在测试进程里。
    """
    global _display_probe
    if _display_probe is not None:
        return _display_probe

    code = "import tkinter; r = tkinter.Tk(); r.withdraw(); r.destroy()"
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=_DISPLAY_PROBE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        _display_probe = (False, f"创建 Tk 窗口超过 {_DISPLAY_PROBE_TIMEOUT:.0f}s，视为无可用显示")
    except OSError as exc:  # pragma: no cover - 取决于环境
        _display_probe = (False, f"无法启动探测子进程：{exc}")
    else:
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            _display_probe = (False, f"无可用显示：{detail[-1] if detail else '未知错误'}")
        else:
            _display_probe = (True, "")
    return _display_probe


def _get_app():
    global _app, _skip_reason
    if _app is not None:
        return _app

    available, reason = _probe_display()
    if not available:
        _skip_reason = reason
        return None

    from netguard.gui.main_ui import NetGuardApp

    _app = NetGuardApp()
    _app.withdraw()
    _app.update_idletasks()
    _app.update()
    _settle_background(_app)
    return _app


def _settle_background(application, settle: float = 0.35, timeout: float = 3.0) -> None:
    """排空构造期遗留的后台任务（如 _load_devices），建立干净的忙碌基线。

    单例窗口在启动时用 after(100, _load_devices) 排定了设备加载任务；它会在
    后续任意一次 update() 里触发，其后台线程与 busy 计数跨用例残留，令后续
    用例的 busy 断言读到别的任务的文本。这里先跑满一个覆盖该定时器的时长让
    它触发，再等到忙碌计数归零。只在首次建窗后调用一次即可。
    """
    deadline = time.monotonic() + timeout
    settle_until = time.monotonic() + settle
    while time.monotonic() < deadline:
        application._pump_background()
        try:
            application.update_idletasks()
            application.update()
        except tk.TclError:
            break
        if time.monotonic() >= settle_until and application._busy_count <= 0:
            break
        time.sleep(0.01)
    _reset_background(application)


def _reset_background(application) -> None:
    """把忙碌状态清回干净基线。"""
    application._busy_count = 0
    application._background_queue = queue.Queue()
    application.busy_text_var.set("")


def _settle(application, rounds: int = 12) -> None:
    """跑若干轮事件循环，让 after_idle 排定的布局回调真正执行完。"""
    for _ in range(rounds):
        try:
            application.update_idletasks()
            application.update()
        except tk.TclError:
            return
        time.sleep(0.01)


@pytest.fixture(autouse=True)
def _silence_dialogs(monkeypatch):
    """把 messagebox 换成非阻塞空实现。

    无 Npcap 的 CI runner 上，启动时的网卡枚举会抛 PcapError，后台任务把它
    作为错误回传，`_pump_background` 随即调用 `messagebox.showerror`。那是个
    模态框，无人值守时永久阻塞，测试进程挂死。这里统一替换掉，避免触碰任何
    真实对话框。
    """
    from netguard.gui import main_ui

    def _noop(*_args, **_kwargs):
        return None

    for name in ("showerror", "showwarning", "showinfo"):
        monkeypatch.setattr(main_ui.messagebox, name, _noop)
    for name in ("askyesno", "askokcancel", "askquestion"):
        monkeypatch.setattr(main_ui.messagebox, name, lambda *a, **k: False)
    yield


@pytest.fixture()
def app():
    application = _get_app()
    if application is None:
        pytest.skip(_skip_reason)
    _reset_background(application)
    # 每测重置可变状态，避免用例间互相污染
    application.events = []
    application.filtered = []
    application.event_offset = 0
    application._sort_column = ""
    application._sort_descending = False
    application._set_theme_mode("system")
    application.update_idletasks()
    application.update()
    yield application


def test_main_window_builds_with_menu_and_status_bar(app) -> None:
    assert app.cget("menu")
    assert app.status_text_var.get()
    assert app.theme_mode.get() in {"light", "dark", "system"}


def test_theme_switching_updates_dark_flag(app) -> None:
    app._set_theme_mode("dark")
    assert app.dark_mode.get() is True
    app._set_theme_mode("light")
    assert app.dark_mode.get() is False
    app._set_theme_mode("system")


def test_theme_switch_with_existing_alert_rows(app) -> None:
    """告警表非空时切换主题不得抛错，且每行按严重度重新打标签。

    回归用例：告警区曾是 Listbox，用 per-item 前景色着色，而
    ``Listbox.get(index, index)`` 返回的是元组，会把元组喂给 severity_color
    触发 AttributeError——异常类型不在 except tk.TclError 覆盖范围内，
    直接冒泡中断主题切换。改成 Treeview + tag 之后走的是另一条路径，
    这里守住「换肤后标签仍与严重度一致」这个不变量。
    """
    from netguard.rules.engine import Alert

    def make_alert(severity: str, kind: str, rule_id: str | None, msg: str) -> Alert:
        return Alert(
            timestamp=1.0,
            msg=msg,
            protocol="TCP",
            src="10.0.0.1",
            dst="10.0.0.2",
            src_port=12345,
            dst_port=80,
            summary=msg,
            kind=kind,
            severity=severity,
            rule_id=rule_id,
        )

    app.alerts.delete(*app.alerts.get_children())
    app._insert_alert_rows(
        [
            (0, make_alert("high", "anomaly", "syn-flood", "疑似 SYN Flood")),
            (1, make_alert("medium", "rule", None, "检测到 HTTP GET 请求")),
        ]
    )
    assert app._real_alert_count() == 2

    app._set_theme_mode("dark")
    assert len(app.alerts.get_children()) == 2
    app._set_theme_mode("light")

    # 两行严重度不同 → 标签不同，且与结构化 severity 对应
    rows = app.alerts.get_children()
    assert app.alerts.item(rows[0], "tags")[0] == "high"
    assert app.alerts.item(rows[1], "tags")[0] == "medium"

    app.alerts.delete(*app.alerts.get_children())
    app._update_alert_tab_label()
    app._set_theme_mode("system")


def test_detail_and_hex_views_populate_on_selection(app) -> None:
    """选中数据包后，解析树与十六进制视图都应写入内容。"""
    from netguard.parser.packet import PacketInfo
    from netguard.pipeline import PacketEvent

    app.events = [
        PacketEvent(
            PacketInfo(
                timestamp=1.0,
                length=60,
                raw=b"GET / HTTP/1.1\r\n\r\n",
                protocol="HTTP",
                src="10.0.0.1",
                dst="10.0.0.2",
                src_port=12345,
                dst_port=80,
                summary="GET / HTTP/1.1",
                payload=b"GET / HTTP/1.1\r\n\r\n",
            ),
            (),
        )
    ]
    app.event_offset = 0
    app._fill_detail_tree(app.events[0].packet)
    app._fill_hex_view(app.events[0].packet)

    top = app.detail.get_children()
    assert top, "解析树应有帧信息分组"
    # 帧信息 → 摘要 一行应带上原摘要（值列用 Treeview.set 读取）
    frame_children = app.detail.get_children(top[0])
    rendered = [app.detail.item(iid, "text") for iid in frame_children]
    rendered += [app.detail.set(iid, "value") for iid in frame_children]
    assert any("GET / HTTP/1.1" in str(item) for item in rendered)
    assert "47 45 54" in app.hex_view.get("1.0", "end")


def test_theme_button_cycles_through_all_modes(app) -> None:
    """顶栏主题按钮在「跟随系统 → 浅色 → 深色」之间循环。

    这是替代早期工具栏「夜间模式」复选框的入口：当时开关失效是因为复选框状态
    被 _apply_theme 按 theme_mode 还原，所以这里守住「循环真的改变了 dark_mode」。
    """
    app._set_theme_mode("system")
    app._cycle_theme_mode()
    assert app.theme_mode.get() == "light"
    assert app.dark_mode.get() is False

    app._cycle_theme_mode()
    assert app.theme_mode.get() == "dark"
    assert app.dark_mode.get() is True

    app._cycle_theme_mode()
    assert app.theme_mode.get() == "system"


def test_ctrl_o_in_text_widgets_opens_pcap(app, monkeypatch) -> None:
    """回归：Text 控件里的 Ctrl+O 既要打开文件，又不能插入换行。

    Tk 的 Text 类绑定把 Ctrl+O 绑成"插入换行"，控件级绑定先于类绑定执行。
    此前只在控件级返回 "break"，结果连主窗口的打开动作一起被吃掉——按 Ctrl+O
    什么都不发生；正确做法是先执行打开动作、再返回 "break"。
    """
    calls: list[int] = []
    monkeypatch.setattr(app, "_open_pcap", lambda: calls.append(1))

    for name, widget in (("规则编辑框", app.rules_text), ("十六进制视图", app.hex_view), ("日志条", app._log_text)):
        assert widget.bind("<Control-o>"), f"{name}缺少 Ctrl+O 的控件级绑定，会与 Text 默认换行冲突"

    assert app._open_pcap_from_text(None) == "break"
    assert calls == [1]


def _right_edge(widget, root) -> int:
    """控件右边界相对主窗口左沿的像素位置。

    窗口在测试里是 withdraw 的，winfo_rootx/ismapped 都不可靠，因此按父子链
    累加 winfo_x（布局本身照常计算，只是不映射到屏幕）。
    """
    x = 0
    node = widget
    while node is not None and node is not root:
        x += node.winfo_x()
        node = node.master
    return x + widget.winfo_width()


def test_rail_separator_has_its_own_grid_column(app) -> None:
    """操作轨、分隔线、内容区必须各占一个 grid 单元格。

    回归：那条 1px 竖线曾与内容帧放在同一个单元格里，`sticky="ns"` 让它停在格子
    中间，后创建的内容帧把它整块盖住，分隔线在界面上从未真正出现过。
    断言全部基于结构与请求尺寸，不读 winfo_x/winfo_width：窗口是 withdraw 的，
    Linux/Xvfb 上 grid 子控件根本不会被摆放（实测 x=0、width=1），
    只有 Windows/macOS 会给真实坐标。
    """
    shell = app._rail.master
    children = shell.grid_slaves()
    cells = [(child.grid_info().get("row"), child.grid_info().get("column")) for child in children]
    assert len(cells) == len(set(cells)), f"有控件共用了同一个 grid 单元格（会互相遮挡）：{cells}"
    assert {column for _row, column in cells} == {0, 1, 2}, "操作轨 / 分隔线 / 内容区应当各占一列"

    separator = next(child for child in children if child.grid_info().get("column") == 1)
    rail = next(child for child in children if child.grid_info().get("column") == 0)
    assert rail.winfo_reqwidth() > separator.winfo_reqwidth(), "第 0 列应是操作轨，第 1 列是 1px 分隔线"
    assert separator.winfo_reqwidth() == 1


def test_minimum_window_size_keeps_every_control_inside(app) -> None:
    """不变量：窗口缩到最小尺寸时，最右侧的控件仍要留在窗口内。

    这是防回归的护栏而非既有缺陷的复现——把默认列宽或工具条控件加宽时，只要
    请求宽度超过 min_width，grid/pack 就会把放不下的控件摆到窗口外（第 5 张
    KPI 卡、工具条右侧的丢弃计数、显示过滤栏的模板按钮与匹配胶囊）。
    """
    original = app.geometry()
    min_width, min_height = app.minsize()
    try:
        app.geometry(f"{min_width}x{min_height}")
        _settle(app)
        if app.winfo_width() != min_width:
            # 没有窗口管理器时（Xvfb）可能不接受尺寸请求，此时量到的位置没有意义
            pytest.skip(f"平台未按请求调整窗口尺寸（{app.winfo_width()} != {min_width}）")

        for name, widget in (
            ("第 5 张 KPI 卡（IDS 告警）", app._stat_cards["alerts"]),
            ("丢弃/解析异常计数", app._drop_hint),
            ("显示过滤模板按钮", app._match_chip),
            ("检视面板", app.detail),
        ):
            assert widget is not None, name
            overflow = _right_edge(widget, app) - min_width
            assert overflow <= 0, f"{name} 超出窗口右边界 {overflow}px"
    finally:
        app.geometry(original)
        _settle(app)


def test_shrinking_window_keeps_inspector_usable(app) -> None:
    """窗口变窄后分隔条要重新钳制，检视面板仍放得下「字段 + 值」两列。

    回归：分隔条位置是绝对值（ttk.PanedWindow 不会随窗口变窄自动回退），
    在宽窗口上定位后缩窄窗口，右侧窗格会被压成一条缝——实测最小尺寸下检视面板
    只剩 272px，而「字段 + 值」两列需要 320px，值列整列被裁掉。
    """
    original = app.geometry()
    min_width, min_height = app.minsize()
    try:
        app.geometry(f"{min_width + 480}x{min_height + 160}")
        _settle(app)
        app.geometry(f"{min_width}x{min_height}")
        _settle(app)

        span = app._main_panes.winfo_width()
        sash = app._main_panes.sashpos(0)
        if span <= 1:
            # 同上：Xvfb 下 grid 子控件不会被摆放，像素断言在这里无意义
            pytest.skip("该平台在 withdraw 状态下不计算窗格几何，跳过像素断言")
        tail_min = max(340, app._tail_pane_min(app._main_panes, horizontal=True))
        assert sash <= span - tail_min, f"分隔条未随窗口回收：sash={sash} span={span}"
        columns = int(app.detail.column("#0", "width")) + int(app.detail.column("value", "width"))
        assert app.detail.winfo_width() >= columns, (
            f"检视面板被压扁到 {app.detail.winfo_width()}px，两列需要 {columns}px"
        )
    finally:
        app.geometry(original)
        _settle(app)


def test_empty_state_text_fits_detail_columns(app) -> None:
    """空状态文字要放得进解析树的两列。

    Treeview 单元格不换行，文字比列宽长就被截成半句（空状态是新用户看到的第一屏，
    "尚未选中数据[包]" 这种断句很显眼）。这里用真实字体度量 + 默认列宽校验。
    """
    from netguard.gui.main_ui import _DEFAULT_DETAIL_COLUMNS

    app.detail.column("#0", width=_DEFAULT_DETAIL_COLUMNS["#0"])
    app.detail.column("value", width=_DEFAULT_DETAIL_COLUMNS["value"])
    app._set_initial_empty_state()

    font = app._theme.font_body
    title = str(app.detail.item("__empty__", "text")).strip()
    hint = str(app.detail.set("__empty_hint__", "value"))
    assert title and hint
    # #0 列要给层级缩进留位置
    assert font.measure(title) + 24 <= int(app.detail.column("#0", "width")), title
    assert font.measure(hint) <= int(app.detail.column("value", "width")), hint


def test_log_strip_keeps_last_message_fully_visible(app) -> None:
    """单行日志必须完整显示最新一条。

    回归：日志以换行结尾时 Text 会多出一条空显示行，滚到底部看到的是那条空行，
    最后一条日志被挤出可视区——表现为整条看不见，或只露出上半截（与上一条叠在一起）。
    """
    if app._log_expanded:  # 其他用例可能把日志条展开过
        app._toggle_log()
    app._log("第一条日志")
    app._log("第二条日志：这是最后一条")
    _settle(app)

    # 末尾不能多出空行（空列表项），否则最后一条日志会被挤出可视区
    lines = app._log_text.get("1.0", "end-1c").split("\n")
    assert lines[-2:] == ["第一条日志", "第二条日志：这是最后一条"], lines[-3:]
    info = app._log_text.dlineinfo("end-1c")
    assert info is not None, "最后一条日志不在可视区内"
    _x, y, width, height = info[0], info[1], info[2], info[3]
    assert width > 0, "最后一条日志落在空行上（末尾多了换行）"
    assert y >= 0 and y + height <= app._log_text.winfo_height(), f"最后一条日志被裁切：y={y} h={height}"
    # 单行模式下文本域只能占一行的高度（容差留给各平台字体度量的差异；
    # 修复前这里是 29px vs 行高 20px，多出的半行会露出上一条的下半截）
    linespace = app._theme.font_mono.metrics("linespace")
    assert app._log_text.winfo_height() <= linespace + 4, f"单行日志条被拉伸到 {app._log_text.winfo_height()}px"


def test_sort_toggles_direction(app) -> None:
    app._sort("time")
    assert app._sort_column == "time"
    assert app._sort_descending is False
    app._sort("time")
    assert app._sort_descending is True


def test_refilter_batches_without_blocking(app) -> None:
    from netguard.parser.packet import PacketInfo
    from netguard.pipeline import PacketEvent

    app.events = [
        PacketEvent(
            PacketInfo(
                timestamp=float(i),
                length=60,
                raw=b"GET / HTTP/1.1\r\n\r\n",
                protocol="HTTP",
                src="10.0.0.1",
                dst="10.0.0.2",
                src_port=1,
                dst_port=80,
                summary="GET",
            ),
            (),
        )
        for i in range(1200)
    ]
    app._refilter()
    for _ in range(400):
        app.update()
        if app._refilter_after_id is None:
            break
        time.sleep(0.005)
    assert len(app.filtered) == 1200


def test_background_helper_marshals_result(app) -> None:
    result: dict[str, object] = {}
    app._run_in_background(lambda: 7, lambda value: result.setdefault("value", value), "busy", "错误")
    for _ in range(200):
        app._pump_background()
        if "value" in result:
            break
        time.sleep(0.005)
    assert result.get("value") == 7
    assert app.busy_text_var.get() == ""


def test_background_helper_reports_failure(app, monkeypatch) -> None:
    from netguard.gui import main_ui

    captured = {}
    monkeypatch.setattr(
        main_ui.messagebox, "showerror", lambda title, message, **kw: captured.update(title=title, message=message)
    )

    def boom():
        raise ValueError("nope")

    app._run_in_background(boom, lambda _r: None, "busy", "错误")
    for _ in range(200):
        app._pump_background()
        if app._busy_count == 0:
            break
        time.sleep(0.005)
    assert app._busy_count == 0
    assert app.busy_text_var.get() == ""
    assert captured.get("title") == "错误"
    assert "nope" in str(captured.get("message"))
