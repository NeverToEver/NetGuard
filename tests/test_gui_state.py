"""无显示环境下的 GUI 状态测试。

用 ``object.__new__(NetGuardApp)`` + 手写替身构造一个「只有状态机、没有窗口」的
应用实例，从而在 CI 上不依赖 libpcap / root / X11 也能验证事件裁剪、告警补录、
详情渲染这些纯逻辑。

替身只实现被测代码真正会调用的方法：**故意不补全** —— 一旦某条路径开始依赖
新控件能力，这里会以 AttributeError 立刻暴露，而不是静默通过。
"""

from __future__ import annotations

import tkinter as tk

from netguard.gui.main_ui import NetGuardApp
from netguard.parser.packet import PacketInfo
from netguard.pipeline import PacketEvent
from netguard.rules.engine import Alert


class FakeVar:
    def __init__(self, value: str = "") -> None:
        self.value = value

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value


class FakeButton:
    def __init__(self) -> None:
        self.options: dict[str, str] = {}

    def configure(self, **kwargs: str) -> None:
        self.options.update(kwargs)


class FakeTree:
    """ttk.Treeview 的最小替身（数据包表 / 告警表 / 解析树共用）。"""

    def __init__(self, selection: tuple[str, ...] = ()) -> None:
        self.rows: list[str] = []
        self.values: dict[str, tuple[object, ...]] = {}
        self.tags: dict[str, tuple[str, ...]] = {}
        self.text: dict[str, str] = {}
        self.seen: list[str] = []
        self.focused = ""
        self._selection = selection
        self._auto_iid = 0

    def insert(
        self,
        parent: str,
        index: int | str,
        iid: str | None = None,
        text: str = "",
        values: tuple[object, ...] = (),
        tags: tuple[str, ...] = (),
        **_options: object,
    ) -> str:
        if iid is None:
            self._auto_iid += 1
            iid = f"auto{self._auto_iid}"
        self.rows.append(iid)
        self.values[iid] = tuple(values)
        self.tags[iid] = tuple(tags)
        self.text[iid] = text
        return iid

    def delete(self, *items: str) -> None:
        removed = set(items)
        self.rows = [row for row in self.rows if row not in removed]
        for iid in removed:
            self.values.pop(iid, None)
            self.tags.pop(iid, None)
            self.text.pop(iid, None)

    def get_children(self, item: str | None = None) -> tuple[str, ...]:
        return tuple(self.rows)

    def selection(self) -> tuple[str, ...]:
        return self._selection

    def selection_set(self, *items: str) -> None:
        self._selection = tuple(items)

    def focus(self, item: str) -> None:
        self.focused = item

    def see(self, item: str) -> None:
        self.seen.append(item)

    def yview(self) -> tuple[float, float]:
        return (0.0, 1.0)

    def item(self, iid: str, option: str | None = None, **kwargs: object) -> object:
        if kwargs:
            if "tags" in kwargs:
                self.tags[iid] = tuple(kwargs["tags"])  # type: ignore[arg-type]
            return None
        if option == "tags":
            return self.tags.get(iid, ())
        if option == "text":
            return self.text.get(iid, "")
        return None


class FakeText:
    def __init__(self, **_options: object) -> None:
        self.value = ""
        self.state = tk.NORMAL
        self.tags: dict[str, dict[str, object]] = {}

    def delete(self, start: str, end: str) -> None:
        self.value = ""

    def insert(self, index: str, value: str, *tags: str) -> None:
        self.value += value

    def configure(self, **kwargs: object) -> None:
        if "state" in kwargs:
            self.state = kwargs["state"]  # type: ignore[assignment]

    def tag_configure(self, tag: str, **options: object) -> None:
        self.tags.setdefault(tag, {}).update(options)


class FakeNotebook:
    def __init__(self) -> None:
        self.labels: dict[int, str] = {}

    def tab(self, index: int, text: str) -> None:
        self.labels[index] = text


class FakePipeline:
    def __init__(self, events: list[PacketEvent]) -> None:
        self.events = events
        self.capture_error: str | None = None
        self.replay_finished = False

    def pump(self, max_events: int) -> list[PacketEvent]:
        events = self.events
        self.events = []
        return events


def packet_event(summary: str = "GET / HTTP/1.1") -> PacketEvent:
    packet = PacketInfo(
        timestamp=1.0,
        length=60,
        raw=b"GET / HTTP/1.1\r\n\r\n",
        protocol="HTTP",
        src="10.0.0.1",
        dst="10.0.0.2",
        src_port=12345,
        dst_port=80,
        summary=summary,
        payload=b"GET / HTTP/1.1\r\n\r\n",
    )
    alert = Alert(
        timestamp=1.0,
        msg="检测到 HTTP GET 请求",
        protocol="HTTP",
        src=packet.src,
        dst=packet.dst,
        src_port=packet.src_port,
        dst_port=packet.dst_port,
        summary=packet.summary,
    )
    return PacketEvent(packet, (alert,))


def fake_app(events: list[PacketEvent], *, paused: bool = False, display_filter: str = "") -> NetGuardApp:
    app = object.__new__(NetGuardApp)
    app.pipeline = FakePipeline(events)
    app.events = []
    app.filtered = []
    app.event_offset = 0
    app.alert_packet_indices = []
    app.alerts = FakeTree()
    app.alerts_placeholder = True
    app.table = FakeTree()
    app.detail = FakeTree()
    app.hex_view = FakeText()
    app.error_list = FakeTree()
    app.error_summary_var = FakeVar("解析问题 0 · 致命异常 0")
    app.display_filter = FakeVar(display_filter)
    app.packet_count_var = FakeVar()
    app.device_var = FakeVar("dev")
    app.display_to_device = {"dev": "dev"}
    app.capturing = True
    app.paused = paused
    app._pause_event_total = 0
    app._active_bpf_filter = ""
    app.dark_mode = FakeVar(False)
    app.status_text_var = FakeVar()
    app.busy_text_var = FakeVar()
    app._status_bar = None
    app._busy_label = None
    app._status_detail = None
    app._tooltips = []
    app._sort_column = ""
    app._sort_descending = False
    app._alert_sort_column = ""
    app._alert_sort_descending = False
    app._alert_tab_index = 0
    app._issue_tab_index = 1
    app._bottom_tabs = FakeNotebook()
    app._busy_count = 0
    app._background_queue = __import__("queue").Queue()
    app._themed = []
    app._panels = []
    app._panel_headers = []
    app._stat_cards = {}
    app._stats_cells = {}
    app._proto_bars = {}
    app._detail_nodes = {}
    app._alert_by_row = {}
    app._alert_seq = 0
    app._pill = None
    app._match_chip = None
    app._table_hint = None
    app._error_badge = None
    app._drop_hint = None
    app._rule_count_label = None
    app._rail_buttons = {key: FakeButton() for key in ("start", "stop", "pause", "clear", "open", "save", "export")}
    app._rail_glyphs = dict.fromkeys(app._rail_buttons, "?")
    app._rail_labels = dict.fromkeys(app._rail_buttons, "")
    app._refresh_stats = lambda: None
    app.after = lambda *args: None
    return app


def test_alerts_are_recorded_when_display_filter_hides_packet() -> None:
    app = fake_app([packet_event()], display_filter="DNS")

    app._tick()

    assert len(app.alerts.get_children()) == 1
    assert app.alerts_placeholder is False
    assert app.alert_packet_indices == [0]
    assert app.table.get_children() == ()


def test_alerts_are_recorded_while_table_refresh_is_paused() -> None:
    app = fake_app([packet_event()], paused=True)

    app._tick()

    # 暂停期间事件仍被累积，但不刷新界面、不写告警
    assert len(app.events) == 1
    assert app.alerts_placeholder is True
    assert app.alerts.get_children() == ()
    assert app.alert_packet_indices == []
    assert app.table.get_children() == ()

    # 恢复刷新时通过 _catch_up_paused_alerts 补录暂停期间的告警
    app.paused = False
    app._catch_up_paused_alerts()

    assert app.alerts_placeholder is False
    assert len(app.alerts.get_children()) == 1
    assert app.alert_packet_indices == [0]


def test_alert_row_is_tagged_with_structured_severity() -> None:
    """告警行按结构化 severity 上标签，而不是靠消息关键字猜。"""
    app = fake_app([packet_event()])
    app._tick()

    (iid,) = app.alerts.get_children()
    # packet_event 里的 Alert 用默认 severity="medium"
    assert "medium" in app.alerts.tags[iid]
    assert app._alert_by_row[iid].msg == "检测到 HTTP GET 请求"
    # 告警选项卡标题应带计数
    assert app._bottom_tabs.labels[0] == "告警（1）"


def test_alert_row_iid_encodes_packet_index_for_jump() -> None:
    """行 iid 形如 "{包索引}:{序号}"，双击定位时无需额外映射表。"""
    app = fake_app([packet_event(), packet_event()])
    app._tick()

    iids = app.alerts.get_children()
    assert [int(iid.split(":", 1)[0]) for iid in iids] == [0, 1]
    assert len(set(iids)) == 2  # 同一包多条告警也不会撞 iid


def test_control_states_disable_stop_until_capturing() -> None:
    app = fake_app([])
    app.capturing = False
    app._update_control_states()

    assert app._rail_buttons["stop"].options["state"] == tk.DISABLED
    assert app._rail_buttons["start"].options["state"] == tk.NORMAL

    app.capturing = True
    app._update_control_states()
    assert app._rail_buttons["stop"].options["state"] == tk.NORMAL


def test_selected_packet_uses_event_offset_after_event_trim() -> None:
    app = object.__new__(NetGuardApp)
    app.event_offset = 5
    app.events = [packet_event("trim-safe")]
    app.table = FakeTree(selection=("5",))
    app.detail = FakeTree()
    app.hex_view = FakeText()
    app._detail_nodes = {}
    app._register_hex_tags = lambda: None

    app._show_selected()

    # 摘要既出现在解析树的「帧信息」里，也出现在十六进制视图里
    assert any("trim-safe" in str(value) for value in app.detail.values.values())
    assert "47 45 54" in app.hex_view.value
    # 解析树按分组/字段打标签，供主题着色
    assert any("group" in tags for tags in app.detail.tags.values())
    assert any("key" in tags for tags in app.detail.tags.values())


def test_detail_tree_starts_collapsed_below_two_levels() -> None:
    """深层协议字段默认收起，避免选中一个 HTTP 包就铺满整个面板。"""
    app = object.__new__(NetGuardApp)
    app.event_offset = 0
    app.events = [packet_event()]
    app.table = FakeTree(selection=("0",))
    app.detail = FakeTree()
    app.hex_view = FakeText()
    app._detail_nodes = {}
    app._register_hex_tags = lambda: None

    app._show_selected()

    assert app.detail.rows, "解析树应至少渲染帧信息"
    # 空状态占位不应残留
    assert "__empty__" not in app.detail.rows


def test_jump_to_error_packet_selects_the_right_row() -> None:
    """回归：改写跳转逻辑时曾残留旧实现的三行，iid 未定义，
    每次双击解析问题都会 NameError。这里守住「双击能定位到对应行」。"""
    app = object.__new__(NetGuardApp)
    app.event_offset = 0
    app.events = [packet_event(), packet_event("second")]
    app.table = FakeTree()
    app.table.rows = ["0", "1"]
    app.detail = FakeTree()
    app.hex_view = FakeText()
    app._detail_nodes = {}
    app._register_hex_tags = lambda: None
    app.error_list = FakeTree(selection=("1:0",))

    app._jump_to_error_packet()

    assert app.table.selection() == ("1",)
    assert "1" in app.table.seen


def test_jump_to_alert_packet_parses_packet_index_from_iid() -> None:
    app = object.__new__(NetGuardApp)
    app.event_offset = 0
    app.events = [packet_event(), packet_event("second")]
    app.table = FakeTree()
    app.table.rows = ["0", "1"]
    app.detail = FakeTree()
    app.hex_view = FakeText()
    app._detail_nodes = {}
    app._register_hex_tags = lambda: None
    app.alerts = FakeTree(selection=("0:7",))

    app._jump_to_alert_packet()

    assert app.table.selection() == ("0",)


def test_jump_is_a_noop_for_unknown_or_malformed_rows() -> None:
    # 行已被裁剪掉：iid 不在表里，不应抛错
    app = object.__new__(NetGuardApp)
    app.event_offset = 0
    app.events = []
    app.table = FakeTree()
    app.detail = FakeTree()
    app.hex_view = FakeText()
    app._detail_nodes = {}
    app._register_hex_tags = lambda: None
    app.error_list = FakeTree(selection=("99:0",))
    app._jump_to_error_packet()
    assert app.table.selection() == ()

    # 非数字 iid 同样安静返回
    app.error_list = FakeTree(selection=("bogus",))
    app._jump_to_error_packet()
    assert app.table.selection() == ()
