# 文档索引

NetGuard 的文档按用途分组。项目总览与架构见仓库根目录的
[README.md](../README.md)；开发约定见 [CONTRIBUTING.md](../CONTRIBUTING.md)。

## 安装

| 文档 | 内容 |
| --- | --- |
| [install-linux.md](install-linux.md) | Linux 依赖（libpcap、中文字体）、虚拟环境、抓包权限 |
| [install-macos.md](install-macos.md) | macOS 依赖、虚拟环境、BPF 设备权限 |
| [install-windows.md](install-windows.md) | Npcap 安装、虚拟环境、网卡显示与推荐 |

## 使用

| 文档 | 内容 |
| --- | --- |
| [usage.md](usage.md) | 界面区域、表格操作、快捷键、过滤、规则与检测器 |
| [lab-demo.md](lab-demo.md) | 课堂演示脚本：每个界面动作对应的源码模块 |
| [experiment-workflow.md](experiment-workflow.md) | 实验流程：从构造流量到验证检出 |

## 技术

| 文档 | 内容 |
| --- | --- |
| [technical-report.md](technical-report.md) | 分层架构、pcap 后端、解析器、规则引擎、GUI、测试、安全边界 |
| [benchmark.md](benchmark.md) | 基准方法、测试环境、吞吐/延迟/检出结果与已知限制 |
| [benchmark-results.json](benchmark-results.json) | `scripts/benchmark.py` 的原始输出（与 README 性能表同源） |

## 规划与评审

| 文档 | 内容 |
| --- | --- |
| [roadmap.md](roadmap.md) | 按 P0/P1/P2 分组的待办，含"明确不做"清单 |
| [reviews/](reviews/) | 历次全量代码审查报告 |
| [distribute-linux.md](distribute-linux.md) | Linux 可执行文件分发指南（PyInstaller） |

## 仓库根目录

| 文档 | 内容 |
| --- | --- |
| [CHANGELOG.md](../CHANGELOG.md) | 版本变更记录 |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | 开发环境、质量门槛、提交规范 |
| [AGENTS.md](../AGENTS.md) | 面向 AI agent 的架构速查与硬性约定 |
| [CLAUDE.md](../CLAUDE.md) | Claude 专用的详细架构说明 |
