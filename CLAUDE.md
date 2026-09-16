# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

No `.venv` is present in this workspace. `python` on PATH is 3.11+ with a working
`tkinter`, so use it directly; create a venv only if you need isolation.

```bash
# Optional: first-time setup (or let the launcher do it: python scripts/launch.py --setup --no-run)
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Unix: source .venv/bin/activate
python -m pip install -e ".[dev]"

# One-click launch + environment self-check (Windows: NetGuard.bat)
./NetGuard.sh
./NetGuard.sh --check

# Run the app (GUI mode by default)
python main.py

# CLI capture preview (needs elevation: sudo on Unix, Administrator on Windows)
sudo python main.py --no-gui --interface en0 --bpf "tcp or udp"

# List capture devices
python main.py --list-devices

# Offline replay (no libpcap / no root needed)
python main.py --read capture.pcap

# Run all tests
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_parser.py -v

# Quality gates (see CONTRIBUTING.md)
python -m ruff check src tests scripts main.py
python -m ruff format --check src tests scripts main.py
python -m mypy
python -m pytest tests/ --cov=netguard

# Package as standalone macOS .app / Unix portable directory (macOS only)
python scripts/build_unix_app.py --python-env .venv
```

Requirements: Python 3.11+. `scripts/launch.py` is the single entry point and owns
interpreter selection (`NETGUARD_PYTHON` > repo `.venv` > current) plus the version
check; the shell/batch wrappers only find a Python to run it.
`scripts/run_netguard.sh` is POSIX only — on Windows use `NetGuard.bat` or
`scripts/run_netguard.ps1`.

## Architecture

**Data flow:** `capture source → processing → pipeline event queue → GUI`

```
main.py                          # Entry point: CLI args → console or GUI
└── src/netguard/
    ├── app.py                   # Argument parsing; CLI preview, --read/--write/--alerts-json
    ├── pipeline.py              # PacketPipeline orchestrator: start/stop/pump/status + PipelineStatus
    ├── processing.py            # PacketProcessor: parse → session → stats → rules/detectors (thread-free)
    ├── clock.py                 # Clock Protocol + system_clock (injectable)
    ├── capture/
    │   ├── pcap.py              # ctypes bindings to libpcap/WinPcap/Npcap
    │   ├── source.py            # CaptureSource: capture/replay thread, raw queue, drop stats
    │   ├── pcap_file.py         # pure-stdlib pcap read/write (offline replay)
    │   └── interface_mapping.py # Windows/Nix device display names + recommendation
    ├── parser/
    │   └── packet.py            # Ethernet→IPv4→TCP/UDP→HTTP/DNS/ICMP recursive decoder
    ├── rules/
    │   ├── engine.py            # IDS rule engine: protocol+port+content, stream matching
    │   └── suggestions.py       # rule suggestions from observed traffic
    ├── detection/
    │   ├── base.py              # Detector protocol + BaseDetector
    │   └── detectors.py         # SynFlood / PortScan / DnsTunnel / IcmpFlood / BruteForce detectors
    ├── session/
    │   └── tracker.py           # TCP session reassembly (out-of-order, fragment stitching)
    ├── statistics/
    │   └── traffic_stats.py     # Rolling-window counters with pkt/s and B/s rates
    ├── discovery/
    │   └── subnet.py            # subnet sweep + host resolution
    ├── trafficgen.py            # synthetic packet templates (demo/bench/test)
    └── gui/
        ├── main_ui.py           # Tkinter shell: title bar, action rail, KPI strip,
        │                        #   packet table, detail/hex inspector, bottom tabs
        ├── config.py            # AppConfig: ~/.netguard_config.json + legacy dark_mode migration
        ├── theme.py             # ThemeManager + design tokens + severity/protocol colors
        ├── widgets.py           # Tooltip, StatCard, Sparkline, StatusPill, PanelHeader
        └── view_models.py       # Display helpers: rows, protocol parse tree, hex rows
```

**GUI conventions** (`gui/`): colors come from `theme.build_colors()` only (never hardcoded) —
prefer raw tokens (`surface_2`, `border`, `text_dim`, `accent`, `proto_*`); legacy keys
(`bg`/`toolbar`/`panel`/`muted`) survive for older dialog code. Native `tk` widgets are
registered via `NetGuardApp._paint(...)` so theme switches re-colour them; Treeview row colors
are tags from `theme.tag_tree()`. Alert severity comes from the structured `Alert.severity`
via `theme.severity_key()`, not message keyword matching. Rail buttons live in
`self._rail_buttons` (update labels with `_set_rail_text`, states with `_update_control_states`).
Persistence goes through `gui.config.AppConfig` (window geometry, sashes, column widths, sort
state, last device, filters); shortcuts bind to the main window, not `bind_all`, so dialogs are
unaffected; dialogs center on the parent, support `Esc`, and re-theme on `<<ThemeChanged>>`;
long file operations run via `NetGuardApp._run_in_background` with status-bar feedback.

Two Tk sizing traps that have bitten this layout: `tk.Text` defaults to `width=80` characters
and `tk.Canvas` to ~378px, so fill-style widgets must pass `width=1`; and
`ttk.PanedWindow.sashpos()` clamps against the current space, so sash restoration has to wait
for the first real layout (see `_apply_sash_positions`) and compute defaults from the pane's
own size, not the window's.

**Pipeline threading model** (`pipeline.py` + `capture/source.py` + `processing.py`):
`CaptureSource` runs the `_capture_worker` (or `_file_worker` for pcap replay) filling
`raw_queue`; `PacketPipeline` runs `_parse_worker`, which calls
`PacketProcessor.process()` (parse → session reassembly → stats → rule/detector match)
and pushes `PacketEvent` into `event_queue`. The GUI polls `pump()` on a 250ms timer and
reads state through `pipeline.status() -> PipelineStatus` instead of reaching into internals.

**Packet parsing** (`parser/packet.py`): `parse_packet()` takes raw bytes, decodes Ethernet →
IPv4 → TCP/UDP/ICMP, then delegates to HTTP or DNS sub-parsers based on port. All parse errors
are collected as `ParseIssue` objects rather than thrown. `PacketInfo.session_key` is the 4-tuple
`(src, src_port, dst, dst_port)`.

**IDS rules** (`rules/engine.py`): Custom Snort-like syntax —
`alert <proto> <src> <src_port> <-> <dst> <dst_port> (content "X"; msg "Y";)`. The engine indexes
rules by protocol for fast lookup. `content` matching checks both `packet.payload` and `packet.raw`,
and falls back to the reassembled session stream (`RuleEngine.match(packet, stream, matched)`) to
catch keywords split across TCP segments; each rule alerts once per session.

**Attack detection** (`detection/`): stateful, time-window detectors (SYN flood, port scan,
DNS tunnel) complementing single-packet rules. Windows and thresholds are configurable and a
`Clock` is injected; `build_default_detectors()` wires the defaults into `PacketProcessor`.
Tracker/detector windows are bounded to avoid O(n²) behaviour under high volume.

**Session reassembly** (`session/tracker.py`): Tracks TCP byte streams buffered by sequence number.
`SessionTracker.update()` accumulates fragments, fills gaps when out-of-order packets arrive, detects
HTTP request/response lines, and cleans up closed or timed-out sessions.

**Offline pcap** (`capture/pcap_file.py`): pure-stdlib read/write supporting both byte orders and
µs/ns magic; `pipeline.start_file()` replays a file with no libpcap or privileges required.

**No external dependencies** — stdlib + `ctypes` for pcap and `tkinter` for the GUI. The
`pyproject.toml` `dependencies` list is intentionally empty. The build script bundles a Python
environment with Tk support; `Pillow` is only needed at build time for icon generation.

