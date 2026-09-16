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
  detection/detectors.py    SynFlood / PortScan / DnsTunnel / IcmpFlood / BruteForce detectors
  session/tracker.py        TCP stream reassembly and flow cleanup
  statistics/traffic_stats.py  rolling-window counters / rates
  discovery/subnet.py       subnet sweep + host resolution
  trafficgen.py             synthetic packet templates (demo/test/bench)
  gui/main_ui.py            Tkinter shell (title bar, action rail, KPI strip, panels,
                            dialogs, shortcuts); _build_* methods build each region
  gui/config.py             AppConfig: ~/.netguard_config.json read/write + legacy migration
  gui/theme.py              ThemeManager + build_colors design tokens + ttk styles +
                            severity/protocol colour helpers + system-theme detection
  gui/widgets.py            Tooltip, StatCard, Sparkline, StatusPill, PanelHeader
  gui/view_models.py        display formatting: packet/alert rows, protocol parse tree,
                            hex rows, timestamp formatting
tests/                      pytest suite (fakes/mocks; no libpcap, root, or display needed)
scripts/                    unix + windows launchers, interpreter detection, app bundler, benchmark.py
  launch.py                 cross-platform one-click entry (--check / --setup, forwards to main.py)
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
NetGuard.bat / ./NetGuard.sh                # one-click launcher (auto Python + self-check)
NetGuard.bat --check                        # env self-check only (Python/source/capture/GUI/rules)
python scripts/launch.py --setup --no-run   # create .venv + pip install -e .
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

`scripts/launch.py` is the single cross-platform entry behind `NetGuard.bat` /
`NetGuard.sh` and `scripts/run_netguard.*`: it resolves the interpreter
(`NETGUARD_PYTHON` > repo `.venv` > current), enforces the 3.11 minimum, supports
`--check` (env self-check) and `--setup` (create `.venv` + `pip install -e .`), and
forwards every other arg to `main.py`. The shell/batch wrappers only locate a Python
that can run `launch.py` — do not add version checks to them. `scripts/run_netguard.sh`
is POSIX only. On Windows use `NetGuard.bat` / `scripts/run_netguard.ps1`, or invoke
`python main.py` directly. Live capture needs elevation: `sudo` on Unix, an
Administrator shell on Windows.

`.gitattributes` pins `*.bat`/`*.ps1` to CRLF and `*.sh` to LF — `.bat` files with LF
line endings make cmd mis-parse `if (...)` blocks and hang. Keep batch files ASCII-only
too: UTF-8 Chinese text plus a mid-file `chcp 65001` corrupts command parsing; let
Python emit the localized messages.

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
  `main_ui.py`. Prefer the raw tokens (`surface`, `surface_2`, `border`, `text_dim`,
  `accent`, `proto_*`); `bg` / `toolbar` / `panel` / `muted` are legacy aliases kept for
  older dialog code. Derive tints with `mix()`, not new hex constants.
- Native `tk` widgets do not take part in ttk styling. Register them with
  `NetGuardApp._paint(widget, background="surface_2", foreground="text_dim")` so
  `_apply_theme()` re-colours them on theme switch; do not `configure` colours ad hoc.
- Treeview row colours are tags registered by `theme.tag_tree()`; `_apply_theme()` passes
  the packet / alert / issue / detail trees so tags are refreshed on theme switch.
- Alert severity comes from `theme.severity_key(alert)` (structured `Alert.severity`),
  not from keyword-matching the message. `severity_color()` is only the legacy fallback.
- The rail action buttons live in `self._rail_buttons` keyed by role; update their label
  through `_set_rail_text(key, label)` and their state through `_update_control_states()`
  — `_sync_rail_styles()` picks the style for the current capture state.
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
- `visualization/` is a placeholder for future non-Tk visualizations; today all
  visualization lives in the Tk GUI.

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
- Tk widget defaults inflate the window's requested size: `tk.Text` defaults to
  `width=80` characters and `tk.Canvas` to 10cm (~378px). Fill-style text areas and
  sparklines must pass `width=1`, otherwise the layout demands ~2000px and the right-hand
  content gets clipped on a 1600px window.
- `ttk.PanedWindow.sashpos()` clamps against the *current* space, so restoring saved sash
  positions before the first layout collapses a pane to 1px. `_apply_sash_positions()`
  calls `update_idletasks()` and retries a bounded number of times; sash defaults are
  computed from the pane's own size, not the window's.
- Sash positions are absolute: `ttk.PanedWindow` never pulls them back when the window
  narrows, so the trailing pane collapses (the inspector drops to 272px while its two
  columns need 344px). `_on_pane_configure()` re-clamps on the paned window's *own*
  `<Configure>`, with the trailing pane's requested size as the lower bound
  (`_SASH_MIN_SIZES` is the floor). Do not bind this to a child's `<Configure>` or to the
  toplevel: child events also fire while the user drags a sash and would fight the drag.
- The two side-by-side panels' default column widths (`_DEFAULT_PACKET_COLUMNS` +
  `_DEFAULT_DETAIL_COLUMNS`, 700 + 332px) plus scrollbars and padding must fit
  `MIN_WINDOW_SIZE`: `tests/test_gui_layout.py` asserts the budget, and
  `tests/test_gui_smoke.py` asserts nothing lands outside a minimum-size window.
- Two widgets in the same `grid` cell silently overlap: the rail's 1px separator once
  shared a cell with the content frame and was covered by it (`sticky="ns"` only stretches
  vertically, so the line also sat in the middle of the cell). Give each region its own column.
- Compact 30px chrome rows (the log strip) cannot host a normal `TButton` (it needs 34px
  and gets squashed); use `Tiny.TButton` there.
- `Ctrl+O` is bound on the toplevel, but Tk's `Text` class binding inserts a newline. A
  widget-level binding that merely returns `"break"` swallows the toplevel binding too
  (Tk dispatch order is widget → class → toplevel), so the shortcut dies inside a text box.
  The widget handler must call `_open_pcap()` *and* return `"break"`.
- Benchmark rule matching is a per-protocol full scan; 500 same-protocol rules is slow by
  design (see `docs/benchmark.md` → Known limitations).

## Docs to read before sensitive changes

- `docs/technical-report.md` — design details.
- `docs/roadmap.md` — remaining/planned work and explicitly out-of-scope items (TLS, IPv6).
- `docs/benchmark.md` — measured throughput/latency/detection numbers and known limits.
- `docs/troubleshooting.md` — FAQ for capture/display/detection/environment issues.
- `docs/reviews/` — historical code reviews; note some P2 items are now addressed
  (pipeline split, GUI facade, stream matching, detectors).
- `CONTRIBUTING.md` — dev setup, quality gates (ruff / mypy / coverage), commit rules.
- `CHANGELOG.md` — version history.
- `CLAUDE.md` — longer English architecture notes.
