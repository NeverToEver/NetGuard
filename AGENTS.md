# AGENTS.md

Guidance for ZCode agents working in this repository. See `CLAUDE.md` for a longer
Claude-specific version; this file is the authoritative quick reference.

## What this is

NetGuard — a cross-platform network packet monitor with a lightweight IDS, designed
around a Wireshark-style workflow. Pure Python **3.11+**, run on Linux, macOS, and
Windows (Npcap/WinPcap). Runtime dependencies are intentionally **zero**: stdlib plus
`ctypes` bindings to native libpcap/Npcap and `tkinter` for the GUI. Do not add
third-party runtime dependencies; `Pillow` is used only at build time for icon
generation.

## Layout

```
main.py                     entry point; adds src/ to sys.path, calls netguard.app.main
src/netguard/
  app.py                    CLI arg parsing; GUI or --no-gui/--read console mode
  pipeline.py               PacketPipeline orchestrator + PipelineStatus facade
  processing.py             PacketProcessor: parse→session→stats→rules/detectors
  clock.py                  Clock Protocol + system_clock (injectable for tests)
  capture/pcap.py           ctypes bindings to libpcap/WinPcap/Npcap
  capture/source.py         CaptureSource: capture/replay thread + raw queue + drop stats
  capture/pcap_file.py      pure-stdlib pcap read/write (offline replay)
  capture/interface_mapping.py  device display names + recommendation
  parser/packet.py          Ethernet→IPv4→TCP/UDP→HTTP/DNS/ICMP decoder
  rules/engine.py           Snort-like IDS rule engine (single-packet + stream matching)
  rules/suggestions.py      rule suggestions from observed traffic
  detection/base.py         Detector protocol + BaseDetector
  detection/detectors.py    SynFlood / PortScan / DnsTunnel detectors
  session/tracker.py        TCP stream reassembly and flow cleanup
  statistics/traffic_stats.py  rolling-window counters / rates
  discovery/subnet.py       subnet sweep + host resolution
  trafficgen.py             synthetic packet templates (demo/test/bench)
  gui/main_ui.py            Tkinter main window (menu, status bar, context menu, shortcuts)
  gui/config.py             AppConfig: ~/.netguard_config.json read/write + legacy migration
  gui/theme.py              ThemeManager + build_colors + system-theme detection + menu styling
  gui/widgets.py            Tooltip and other reusable widgets
  gui/view_models.py        display formatting helpers
tests/                      pytest suite (fakes/mocks; no libpcap, root, or display needed)
scripts/                    unix + windows launchers, interpreter detection, app bundler, benchmark.py
docs/                       install/usage/technical/lab docs, benchmark.md (mostly Chinese)
```

Data flow: `capture/source → processing → pipeline(event queue) → gui`. `CaptureSource`
runs the capture (or pcap-replay) thread and fills `raw_queue`; the pipeline's parse
thread calls `PacketProcessor.process()` and pushes `PacketEvent` into `event_queue`;
the GUI polls `pump()` every 250 ms and reads state via `pipeline.status()`.

## Commands

A `.venv` is **not** present in this workspace. Python 3.11.9 with working `tkinter`
is available on PATH, so use `python` directly. To set up a venv:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Unix: source .venv/bin/activate
python -m pip install -e .
```

Run / test / benchmark:

```bash
python main.py                              # GUI (default)
python main.py --list-devices               # enumerate capture devices
python main.py --no-gui --interface eth0 --bpf "tcp or udp"   # console preview
python main.py --read capture.pcap          # offline replay (no libpcap/root needed)
python main.py --write out.pcap --alerts-json alerts.json
python main.py --read capture.pcap --rules my.rules   # CLI loads DEFAULT_RULES unless --rules given
python -m pytest tests/ -v                  # all tests
python -m pytest tests/test_parser.py -v    # one file
python scripts/benchmark.py --markdown      # perf + detection metrics
```

`pyproject.toml` sets `pythonpath = ["src"]` and `testpaths = ["tests"]`, so pytest
finds the package without installing. Tests must not require libpcap, root, or a
display — keep that property when adding tests.

`scripts/run_netguard.sh` and `check_interpreter.sh` are POSIX only. On Windows use
`scripts/run_netguard.ps1` / `.bat`, or invoke `python main.py` directly. Live capture
needs elevation: `sudo` on Unix, an Administrator shell on Windows.

## Conventions and architecture rules

- Use **absolute imports** (`from netguard.parser.packet import ...`); never relative
  imports. Package lives under `src/` (setuptools src-layout).
- Time-dependent code must take a `Clock` from `netguard.clock`. Do not call
  `time.time()` directly in tracker / stats / engine / detectors — tests inject a mock clock.
- Capture backends must conform to `PcapBackendProtocol` in `capture/pcap.py` so tests
  can mock them. `CaptureSource` accepts a `backend_factory`.
- Parsing never raises for malformed packets: errors are collected as `ParseIssue`
  objects. Preserve this contract.
- `PacketInfo.session_key` is the 4-tuple `(src, src_port, dst, dst_port)`.
- The GUI reads pipeline state only through `pipeline.status()` / `rule_count` /
  `capture_error`; do not reach into `pipeline.processor.*` or `pipeline.source.*` from the GUI.
- GUI theme colors live in `gui/theme.py:build_colors()`; never hardcode hex colors in
  `main_ui.py` — use `build_colors` / `severity_color` / `status_color` / `select_text`.
- GUI state persistence goes through `gui/config.py:AppConfig`; add new persisted fields
  to `WindowState` + `to_dict`/`_apply`, and keep legacy `dark_mode` migration intact.
- Dialogs must center with `center_on_parent`, bind `Esc` via `bind_dialog_keys`, and call
  `wire_dialog_theme` so open dialogs re-skin on `<<ThemeChanged>>`.
- Keyboard shortcuts bind to the main window (`self.bind`), never `bind_all` — `bind_all`
  leaks into dialogs (an `Esc` in a dialog would stop capture).
- Long file I/O (save pcap, export alerts, load rules) must go through
  `NetGuardApp._run_in_background`; background threads never touch Tk widgets, and results
  marshal back via `after(0, ...)`.
- Resource bounds are deliberate — do not remove or bypass: `MAX_EVENTS = 50_000`
  (GUI), `max_sessions = 10_000` (tracker), `max_protocols = 64` (stats),
  `_MAX_BPF_LENGTH = 4096`, detector `max_keys` / `max_samples`.
- Detector windows must stay bounded (see `_MAX_SAMPLES_PER_KEY`); unbounded windows
  cause O(n²) distinct-counting under load.
- Content rules match the reassembled session stream as a fallback and dedupe per
  session via `Session.matched_rules`.
- `visualization/` is an empty placeholder — visualization is done in the Tk GUI.

## Gotchas

- `capture/pcap.py` has platform-specific `timeval` layout (macOS `tv_usec` is int32,
  others long). Be careful when touching ctypes structs.
- Windows pcap library is `wpcap.dll` and requires Npcap in "WinPcap API-compatible Mode".
- The pcap file reader (`capture/pcap_file.py`) supports classic pcap only, not pcapng;
  it handles both byte orders and µs/ns magic. `iter_pcap_safe()` tolerates truncation.
- GUI tests build `NetGuardApp` via `object.__new__` and hand-rolled fakes; when you add
  a widget or pipeline attribute the GUI touches, update `tests/test_gui_state.py` fakes too.
- Windows `ipconfig`/`nbtstat` output is not UTF-8 on localized systems (e.g. cp936);
  decode subprocess output via `discovery.subnet._decode_output`, never `text=True`.
- Benchmark rule matching is a per-protocol full scan; 500 same-protocol rules is slow by
  design (see `docs/benchmark.md` → Known limitations).

## Docs to read before sensitive changes

- `docs/technical-report.md` — design details.
- `docs/roadmap.md` — remaining/planned work and explicitly out-of-scope items (TLS, IPv6).
- `docs/benchmark.md` — measured throughput/latency/detection numbers and known limits.
- `docs/experiment-workflow.md`, `docs/lab-demo.md` — expected demo behavior.
- `审查报告/code-review-2026-05-03.md` — historical review; note some P2 items are now
  addressed (pipeline split, GUI facade, stream matching, detectors).
- `CLAUDE.md` — longer English architecture notes.
