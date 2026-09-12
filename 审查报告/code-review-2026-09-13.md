# NetGuard 代码审查报告（2026-09-13）

日期: 2026/09/13
审查方式: 7 个并行子代理按模块深度审查（capture / 解析 / 规则与检测 / 核心流水线 / GUI 主窗口 / GUI 配置主题 / 发现与脚本），关键结论经运行时复现验证；随后分 6 个阶段全量修复，测试随修复同阶段提交。
审查范围: 仓库全量（约 7,700 行 Python）
基线测试: 166 个通过 → 最终测试: 221 个通过（新增 55 条回归测试）

---

## 一、修复总览（6 个阶段化提交）

| 提交 | 阶段 | 内容概要 |
|------|------|----------|
| `018ba50` | 低风险快速修复 | 配置原子写与容错、`_refilter_queue` 初始化、`apply_menu` 判空、`import sys`、HTTP 首行截断、解析死代码、trafficgen 校验和 |
| `ffbbfe6` | 流水线与 CLI | parse 线程异常兜底、回放超时语义、stop 尾部事件派发、线程代际隔离、控制台错误可见性、CLI 校验 |
| `010789b` | 规则引擎与告警风暴 | Snort 冒号方言、端口/地址子集、nocase、UDP/DNS 告警抑制、DnsTunnel 抑制、阈值校验 |
| `4fe902c` | capture 层与协议覆盖 | macOS sockaddr、VLAN 802.1Q/QinQ、write_pcap 一致性、linktype 校验、pcap_stats 内核丢包 |
| `4dc06dd` | GUI 健壮性 | 扫描对话框线程模型、退出等待写盘、快捷键冲突、主题刷新、配置恢复防御、parent 补齐 |
| `b689ea3` | 会话/统计/发现/脚本 | 碎片字节预算、批量淘汰、真超时模型、取消撤销、网卡单向匹配、benchmark 单位、build 清理 |

## 二、P1 修复明细（7 项）

| 位置 | 问题 | 修复 | 提交 |
|------|------|------|------|
| engine:253 | Snort 标准冒号语法 `content:"GET"` 被静默丢弃，content 规则退化为全匹配告警风暴 | `_parse_options` 兼容冒号/空格两种方言，无值选项（nocase）可识别 | `010789b` |
| pipeline:189 | `--read` 回放被 5 秒硬超时静默截断，`--write`/`--alerts-json` 输出不完整 | 改为等到回放完成/出错/排空，`timeout` 重定义为无进展看门狗 | `ffbbfe6` |
| pipeline:228 | 解析线程无顶层异常保护，链路任一步抛异常线程静默死亡、统计冻结 | `process()` 加 try/except，单包失败跳过并记日志 | `ffbbfe6` |
| main_ui:1557 | `_refilter_queue` 未初始化，未用过滤时 MAX_EVENTS 裁剪路径 AttributeError，表格孤儿行无界增长 | `__init__` 初始化该属性与游标 | `018ba50` |
| config:129 | 配置保存为非原子覆盖写，崩溃/断电致配置永久丢失；保存失败只记 debug | 临时文件 + `os.replace` 原子替换，失败日志升级 warning | `018ba50` |
| subnet:244 | `resolve_hostname` 超时机制无效（`setdefaulttimeout` 不影响 `gethostbyaddr`，实测 0.5s 设置下阻塞 9.4s） | 共享线程池 + `future.result(timeout)` 真超时模型 | `b689ea3` |
| build_unix_app:365 | codesign 警告路径使用未导入的 `sys`（历史修复项本身引入 NameError） | 补 `import sys` | `018ba50` |

## 三、P2 修复明细（20 项）

### capture / 解析

| 位置 | 问题 | 提交 |
|------|------|------|
| pcap:77 | macOS/BSD sockaddr 布局不兼容，设备 IPv4/掩码解析恒为空 | `4fe902c` |
| pcap_file:131 | write_pcap 只钳头不钳体，公开 API 可产出错位损坏文件 | `4fe902c` |
| packet:57 | 不识别 VLAN（802.1Q/QinQ），tagged 流量解析与检测整体静默失效 | `4fe902c` |

### 规则与检测

| 位置 | 问题 | 提交 |
|------|------|------|
| engine:108 | UDP/DNS 内容规则无会话去重，逐包告警；建议引擎恰好生成此类规则 | `010789b` |
| detectors:352 | DnsTunnel 超长域名分支无告警抑制，隧道场景逐包告警 | `010789b` |
| engine | 高级选项（flags/pcre/dsize）静默忽略致语义漂移（nocase 丢失=漏报） | `010789b` |
| engine | 端口范围/`$变量`/取反产生"解析成功但永不命中"的死规则 | `010789b` |

### 核心流水线

| 位置 | 问题 | 提交 |
|------|------|------|
| pipeline:138 | stop() 清空 event_queue 丢尾部已解析事件（含告警） | `ffbbfe6` |
| app | 控制台不读 capture_error：坏文件 exit 0 静默、设备消失后无限空转 | `ffbbfe6` |
| pipeline:133 | join 超时放弃的僵尸线程被下轮 start 唤醒，与新线程无锁并发 | `ffbbfe6` |
| tracker:99 | 碎片缓冲只限条数不限字节，恶意乱序注入可放大至 200×snaplen/会话 | `b689ea3` |

### GUI

| 位置 | 问题 | 提交 |
|------|------|------|
| main_ui:2409 | SubnetScanDialog 工作线程直接调 Tk（winfo_exists/after），主循环退出后 RuntimeError 卡死按钮 | `4dc06dd` |
| main_ui:1374 | 退出不等待后台写盘，保存 pcap 被硬杀截断 | `4dc06dd` |
| main_ui:2491 | 手动网段无大小校验，`10.0.0.0/8` 在主线程物化 1677 万对象冻结界面 | `4dc06dd` |
| main_ui:2304 | 扫描与解析共享 `_cancel_event`，互相取消/抹掉标志 | `4dc06dd` |

### 配置 / 发现 / 脚本

| 位置 | 问题 | 提交 |
|------|------|------|
| config:84 | `bpf: null` 生成字面量 `"None"` 灌入 BPF 框，抓包无法启动 | `018ba50` |
| subnet:214 | Windows 网卡双向子串匹配，"以太网 2" 误配 "以太网" 取错网段 | `b689ea3` |
| subnet:312 | resolve_hosts 取消不撤销排队任务，停止后线程空跑十几分钟 | `b689ea3` |
| subnet:79 | ping_host 只看退出码，网关回 unreachable 时死主机被判活 | `b689ea3` |
| benchmark:63 | macOS `ru_maxrss` 单位是字节，内存指标虚高 1024 倍 | `b689ea3` |
| build_unix_app | 构建失败不清理半成品 .app；`legacy.unlink()` 遇目录崩溃 | `b689ea3` |

## 四、P3 修复明细（38 项，按模块归纳）

- **capture**：补 `restype=None`；`iter_pcap_safe` 文档与实现对齐、删死分支；`read_pcap` 校验 linktype；`_wait_for_capture_loop` 加 5s 超时；设备地址按项配对（缺掩码占位）；新增 `pcap_stats` 周期采样并入丢包统计。
- **解析/模板**：HTTP 首行与头部值截断 512 字符；`_read_dns_name` 死变量清理；`_parse_http` 不可达 except 清理；trafficgen 按 IPv4 伪首部计算 IP/TCP/UDP/ICMP 校验和；`abn-eth` 模板笔误修复。
- **规则/检测**：`_clean_option_text` 清除反斜杠；所有检测器校验 `threshold <= max_samples`；`_suffix` 对 3 标签域名取末两级聚合。
- **流水线/CLI**：长流截断改批量水位、HTTP 扫描水位与段起点分离；max_sessions 批量逐出 10%；`_recent` 有界（65536）+ 字节增量维护；CLI 参数组合校验与写文件 OSError 友好提示；stdout `errors="replace"` 防 Windows 重定向丢行；main.py 导入失败友好指引。
- **GUI**：Ctrl+O 与 Text 类绑定冲突消除；Esc 输入框聚焦不触发停止且补入帮助；F5 抓包中守卫；主题切换重刷告警行颜色、Tooltip 实时读主题、`apply` 存活检查、`wire_dialog_theme` 补 highlight 样式、删除死代码 `apply_dialog`；messagebox/filedialog 全部补 `parent`；删除 `_show_device_error` 死代码；恢复 `sort_column` 白名单校验；窗口几何按屏幕钳制。
- **配置/主题**：字符串布尔宽松解析；theme_mode 归一化 + 非法回退 legacy dark_mode；UTF-8 BOM 兼容；未知字段保留回写。
- **发现/脚本**：`_detect_unix_subnets` 检查 returncode 并回退 `ip addr`、拒绝 `-` 开头接口名；benchmark 新增 `--fail-on-miss` CI 门禁；launcher 固定 LF；`run_netguard.ps1` 文档与实际顺序对齐。

## 五、验证

- 全量测试 221 passed（无 libpcap/root/显示依赖的项目约定保持不变）。
- 回放冒烟：3000 包 pcap → CLI 回放 → 写 pcap（3000 包往返一致）→ 导出 205 条告警，exit 0。
- 错误路径：不存在的 pcap 报"回放失败"且 exit 1；`--read`+`--interface` 拒绝且 exit 2。
- benchmark（`--fail-on-miss`）：三个攻击场景全部命中，误报率 0.100%，exit 0。

## 六、确认为设计意图、未改动项

| 位置 | 说明 |
|------|------|
| engine:193 | content 回退匹配整帧 `raw`（含头部）为有意行为，有测试背书（`test_rule_engine_content_in_raw_bytes`）；短内容规则的头部碰撞误报风险已知 |
| 资源上限 | `MAX_EVENTS=50_000`、`max_sessions=10_000`、`max_protocols=64`、检测器 `max_keys/max_samples` 均为有意设计，仅补齐缺失的字节预算与校验 |
| theme | Linux 系统主题检测仅支持 GNOME——增强项而非缺陷，保留现状 |
| 基准 | 规则匹配按协议桶全扫描为 docs/benchmark.md 记录的已知取舍 |

## 七、遗留建议（下一轮）

1. macOS 真机回归：sockaddr/`pcap_stats`/`ru_maxrss` 三项平台修复仅经代码与结构验证，建议在 macOS 上跑一次 `--list-devices` 与 benchmark 采数。
2. 为 `rules/engine.py` 的新增语法子集（范围/取反/列表）补充 GUI 加载路径的端到端测试。
3. `discovery/subnet.py` 已有单元测试（本轮新增），可再补 ipconfig 多网卡 fixture 的回归样本。
