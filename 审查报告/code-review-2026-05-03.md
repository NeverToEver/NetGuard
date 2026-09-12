# NetGuard 代码审查报告

日期: 2026/05/03  
审查范围: `NetGuard 仓库根目录`  
最终测试: 66 个测试全部通过

---

## 一、已修复问题

### P0 — Bugs & 竞态

| 位置 | 问题 | 修复 |
|------|------|------|
| main_ui:578 | `_trim_alerts` off-by-one | 使用 `extra` 而非 `extra - 1` |
| pcap:179-199 | `capture_loop` 与 `close()` use-after-free | `_handle_lock` 保护句柄访问 |
| pipeline:66 | `stop()` 读 `_backend` 不加锁 | 使用 `_backend_lock` |
| pipeline:96,120 | `dropped_packets` 非原子 `+=` | `_dropped_lock` 保护 |
| main_ui:632 | 表格排序按字符串序 | `_sort_key()` 数值排序 |
| engine:52 | 无效规则静默失败 | `load()` 返回失败计数 |
| main_ui:491-496 | 全无效规则也弹"成功" | 检查失败计数，显示警告 |
| main_ui:664 | `_export_alerts` 目录崩溃 | `try/except (OSError, IsADirectoryError)` |

### P1 — 内存 & 线程

| 位置 | 问题 | 修复 |
|------|------|------|
| main_ui:535 | `self.events` 无限增长 | `MAX_EVENTS = 50_000` 上限 |
| traffic_stats:33 | `protocol_counts` 无限增长 | `max_protocols=64`，保留 top N |
| tracker:61 | 每包 O(n) 扫描清理 | `_cleanup_interval=100`，FIN/RST 立即清理 |
| app:19 | `_list_devices()` backend 不关闭 | `try/finally backend.close()` |
| pipeline:71 | 线程 join 只等 0.5s | 改为 2.0s |
| pipeline:112 | parse_packet 异常崩线程 | `try/except` + `continue` |
| tracker | 无会话数上限 | `max_sessions=10_000` |

### P1 — 资源 & 安全

| 位置 | 问题 | 修复 |
|------|------|------|
| tracker:87 | `del stream[:]` 不释放缓冲区 | 新建 `bytearray(stream[-max:])` |
| pipeline:84 | `on_packet` 异常丢事件 | `try/except` 记录后继续 |
| pcap:156 | BPF 无长度校验 | `_MAX_BPF_LENGTH = 4096` |
| packet:126 | HTTP 端口硬编码 | 提取 `_HTTP_PORTS` 常量 |
| build_unix_app:262 | 废弃 API 无注释 | 添加迁移说明注释 |
| build_unix_app:360 | codesign 失败静默 | 输出 stderr 警告 |
| engine:52 | 无效规则崩溃 | silently skip |
| interface_mapping:125 | `_windows_priority` 名字误导 | 添加 docstring |

### 架构重构

| 位置 | 问题 | 修复 |
|------|------|------|
| ARCH-3 | `DEFAULT_RULES` 在 view 层定义 | 移至 `rules/engine.py`，`view_models` 重导 |
| ARCH-8 | PcapBackend 无抽象接口 | 添加 `PcapBackendProtocol` (Protocol) |
| ARCH-9 | `time.time()` 不可 mock | 添加 `Clock` Protocol + `system_clock()`，注入到 tracker/stats/engine |
| main_ui | 723 行单类，主题代码混在一起 | 提取 `gui/theme.py`（ThemeManager），main_ui → 495 行 |
| main_ui | 写死 macOS 字体 | `resolve_fonts()` 跨平台自动检测（Win/Linux/macOS） |

### 测试（12 项新增，共 66 个）

新增覆盖：
- `engine.load()` 返回失败计数 / 畸形规则跳过
- `session_key` None/元组返回
- `hex_dump` 输出
- 会话上限驱逐最旧 / stream 截断 / max_sessions
- protocol_counts 上限裁剪
- `_native_alias` en/lo/未知
- ICMP 协议 / IPv4 无效总长度 / IPv4 选项截断
- 非 HTTP 端口 TCP / TCP 无效偏移 / TCP 选项截断

---

## 二、尚未处理的架构问题（P2，长期改进）

以下问题涉及较大重构，未在本次修复：

1. **PacketPipeline 上帝类** — 掌管线程、队列、设备、规则、会话、统计、回调。需要拆分为可注入组件
2. **GUI 直接访问 pipeline 内部** — `main_ui.py` 直接引用 `pipeline.stats`、`pipeline.dropped_packets`、`pipeline.backend`
3. **main.py `sys.path` 操作** — 虽然做了 `Path(__file__).resolve()` 加固，但本质仍是路径 hack
4. **协议检测依赖端口号** — HTTP=80/8080/8000, DNS=53，无法识别非标准端口流量
5. **PcapBackend 零测试** — 需要 mock CDLL 或真实 libpcap
6. **GUI 零测试** — 需要 Tkinter 测试框架
7. **`_export_alerts` 导出时未加锁** — 抓包线程可能同时写入 `self.alerts`
8. **`alerts` Listbox 无上限** — 大量告警时 UI 可能卡顿

---

## 三、最终测试结果

```
66 passed in 0.04s — Linux (WSL)
66 passed in 0.80s — D:\NetGuard (NTFS)
```

所有测试在 WSL 和 D 盘 NTFS 文件系统上均通过。
