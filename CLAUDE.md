# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

```bash
# First-time setup
/opt/homebrew/bin/python3.12 -m venv .venv
./.venv/bin/python -m pip install -e .

# Run the app (GUI mode by default)
./scripts/run_netguard.sh

# CLI capture preview
sudo ./scripts/run_netguard.sh --no-gui --interface en0 --bpf "tcp or udp"

# List capture devices
./scripts/run_netguard.sh --list-devices

# Run all tests
./.venv/bin/python -m pytest tests/ -v

# Run a single test file
./.venv/bin/python -m pytest tests/test_parser.py -v

# Package as standalone macOS .app / Unix portable directory
python3 scripts/build_unix_app.py --python-env .venv
```

Requirements: Python 3.11+. The start script auto-detects the interpreter from `.venv`, Homebrew paths, or the `NETGUARD_PYTHON` env var.

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
        ├── main_ui.py           # Tkinter UI: menu, toolbar, table, detail/hex, alerts, stats
        ├── config.py            # AppConfig: ~/.netguard_config.json + legacy dark_mode migration
        ├── theme.py             # ThemeManager + colors + system-theme detection + menu styling
        ├── widgets.py           # Tooltip
        └── view_models.py       # Display helpers: packet formatting, search text extraction
```

**GUI conventions** (`gui/`): colors come from `theme.build_colors()` only (never hardcoded);
persistence goes through `gui.config.AppConfig` (window geometry, sashes, column widths, sort
state, last device, filters); shortcuts bind to the main window, not `bind_all`, so dialogs are
unaffected; dialogs center on the parent, support `Esc`, and re-theme on `<<ThemeChanged>>`;
long file operations run via `NetGuardApp._run_in_background` with status-bar feedback.

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

