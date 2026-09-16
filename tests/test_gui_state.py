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


class FakeListbox:
    def __init__(self, items: list[str] | None = None) -> None:
        self.items = items or []
        self.colors: list[tuple[int | str, str]] = []

    def insert(self, index: int | str, value: str) -> None:
        if index == tk.END:
            self.items.append(value)
        else:
            self.items.insert(int(index), value)

    def delete(self, start: int, end: int | str | None = None) -> None:
        if end == tk.END:
            del self.items[start:]
            return
        if end is None:
            del self.items[start]
            return
        del self.items[start : int(end) + 1]

    def size(self) -> int:
        return len(self.items)

    def itemconfigure(self, index: int | str, **kwargs: str) -> None:
        self.colors.append((index, kwargs.get("fg", "")))


class FakeTable:
    def __init__(self, selection: tuple[str, ...] = ()) -> None:
        self.rows: list[str] = []
        self._selection = selection

    def insert(
        self, parent: str, index: int | str, iid: str, tags: tuple[str, ...], values: tuple[object, ...]
    ) -> None:
        self.rows.append(iid)

    def delete(self, *items: str) -> None:
        if not items:
            return
        item_set = set(items)
        self.rows = [row for row in self.rows if row not in item_set]

    def get_children(self, item: str | None = None) -> tuple[str, ...]:
        return tuple(self.rows)

    def selection(self) -> tuple[str, ...]:
        return self._selection


class FakeText:
    def __init__(self) -> None:
        self.value = ""

    def delete(self, start: str, end: str) -> None:
        self.value = ""

    def insert(self, index: str, value: str) -> None:
        self.value += value


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
    app.alerts = FakeListbox(["placeholder"])
    app.alerts_placeholder = True
    app.table = FakeTable()
    app.display_filter = FakeVar(display_filter)
    app.packet_count_var = FakeVar()
    app.status_var = FakeVar()
    app.device_var = FakeVar("dev")
    app.display_to_device = {"dev": "dev"}
    app.capturing = True
    app.paused = paused
    app._pause_event_total = 0
    app.dark_mode = FakeVar(False)
    app.status_text_var = FakeVar()
    app.busy_text_var = FakeVar()
    app._status_bar = None
    app._busy_label = None
    app._tooltips = []
    app._sort_column = ""
    app._sort_descending = False
    app._busy_count = 0
    app._background_queue = __import__("queue").Queue()
    app._capture_indicator = None
    app.start_btn = FakeButton()
    app.stop_btn = FakeButton()
    app.pause_btn = FakeButton()
    app.export_alerts_btn = FakeButton()
    app.save_pcap_btn = FakeButton()
    app._refresh_stats = lambda: None
    app.after = lambda *args: None
    return app


def test_alerts_are_recorded_when_display_filter_hides_packet() -> None:
    app = fake_app([packet_event()], display_filter="DNS")

    app._tick()

    assert app.alerts.size() == 1
    assert app.alerts_placeholder is False
    assert app.alert_packet_indices == [0]
    assert app.table.get_children() == ()


def test_alerts_are_recorded_while_table_refresh_is_paused() -> None:
    app = fake_app([packet_event()], paused=True)

    app._tick()

    # 暂停期间事件仍被累积，但不刷新界面、不写告警
    assert len(app.events) == 1
    assert app.alerts_placeholder is True
    assert app.alerts.size() == 1  # 仅占位符
    assert app.alert_packet_indices == []
    assert app.table.get_children() == ()

    # 恢复刷新时通过 _catch_up_paused_alerts 补录暂停期间的告警
    app.paused = False
    app._catch_up_paused_alerts()

    assert app.alerts_placeholder is False
    assert app.alerts.size() == 1
    assert app.alert_packet_indices == [0]


def test_selected_packet_uses_event_offset_after_event_trim() -> None:
    app = object.__new__(NetGuardApp)
    app.event_offset = 5
    app.events = [packet_event("trim-safe")]
    app.table = FakeTable(selection=("5",))
    app.detail = FakeText()
    app.hex_view = FakeText()

    app._show_selected()

    assert "trim-safe" in app.detail.value
    assert "47 45 54" in app.hex_view.value
