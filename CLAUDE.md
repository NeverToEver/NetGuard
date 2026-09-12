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

**Data flow:** `capture → parse → pipeline → GUI`

```
main.py                          # Entry point: CLI args → console or GUI
└── src/netguard/
    ├── app.py                   # Argument parsing, routes to CLI preview or GUI
    ├── pipeline.py              # PacketPipeline: threaded capture→parse→event queue
    ├── capture/
    │   ├── pcap.py              # ctypes bindings to libpcap/WinPcap/Npcap
    │   └── interface_mapping.py # Windows/Nix device name mapping (Npcap → en0 style)
    ├── parser/
    │   └── packet.py            # Ethernet→IPv4→TCP/UDP→HTTP/DNS recursive decoder
    ├── rules/
    │   └── engine.py            # IDS rule engine: protocol+port+content matching
    ├── session/
    │   └── tracker.py           # TCP session reassembly (out-of-order, fragment stitching)
    ├── statistics/
    │   └── traffic_stats.py     # Rolling-window counters with pkt/s and B/s rates
    ├── gui/
    │   ├── main_ui.py           # Tkinter UI: packet table, detail/hex views, alerts, stats
    │   └── view_models.py       # Display helpers: packet formatting, search text extraction
    └── assets/                  # App icons (png, svg, icns)
```

**Pipeline threading model** (`pipeline.py`): Two daemon threads — `_capture_worker` reads raw packets from pcap into `raw_queue`, `_parse_worker` decodes them and pushes `PacketEvent` objects into `event_queue`. The GUI polls `pump()` on a 250ms timer.

**Packet parsing** (`parser/packet.py`): `parse_packet()` takes raw bytes, decodes Ethernet → IPv4 → TCP/UDP, then delegates to HTTP or DNS sub-parsers based on port. All parse errors are collected as `ParseIssue` objects rather than thrown. `PacketInfo.session_key` is the 4-tuple `(src, src_port, dst, dst_port)` used for session tracking.

**IDS rules** (`rules/engine.py`): Custom Snort-like syntax — `alert <proto> <src> <src_port> <-> <dst> <dst_port> (content "X"; msg "Y";)`. The engine indexes rules by protocol for fast lookup. `content` matching checks both `packet.payload` and `packet.raw`.

**Session reassembly** (`session/tracker.py`): Tracks TCP byte streams buffered by sequence number. `SessionTracker.update()` accumulates fragments, fills gaps when out-of-order packets arrive, detects HTTP request/response lines from the stream, and cleans up closed or timed-out sessions.

**No external dependencies** — the project uses only stdlib + `ctypes` for pcap and `tkinter` for the GUI. The `pyproject.toml` `dependencies` list is intentionally empty. The build script (`build_unix_app.py`) bundles a Python environment with Tk support for distribution; it only needs `Pillow` at build time for icon generation.
