# ReconMaster

自动化安全侦察框架 — 子域名收集 → URL 采集 → FUZZ 爆破 → JS 密钥分析。

## 功能模块

| 阶段 | 模块 | 工具 | 说明 |
|---|---|---|---|
| 1 | 子域名收集 | subfinder, OneForAll, FOFA API | 被动 + 主动收集，dnsx 验活 |
| 2 | URL 收集 | gau, katana | 历史 URL + 主动爬取，支持代理 |
| 3 | URL 处理 | URLProcessor | 去重、静态分离、FUZZ 注入 |
| 4 | FUZZ 爆破 | ffuf | 自动校准 (-ac)，并发调度 |
| 5 | JS 分析 | trufflehog | JS 下载 → 密钥检测 → Verified 分级 |

## 环境要求

- Python 3.10+
- 外部工具需放置在 `tools/` 目录

## 快速开始

```bash
# 1. 安装 Python 依赖
pip install -r requirements.txt

# 2. 下载外部工具到 tools/ 目录
# subfinder:   https://github.com/projectdiscovery/subfinder/releases
# dnsx:        https://github.com/projectdiscovery/dnsx/releases
# gau:         https://github.com/lc/gau/releases
# katana:      https://github.com/projectdiscovery/katana/releases
# ffuf:        https://github.com/ffuf/ffuf/releases
# trufflehog:  https://github.com/trufflesecurity/trufflehog/releases

# 3. 配置代理 (如在国内)
# 编辑 reconmaster/config/settings.py
# HTTP_PROXY = "http://127.0.0.1:7890"

# 4. 运行测试
python tests/test_full_pipeline.py visitcloud.com
```

## 外部工具清单

以下工具需手动下载放入 `tools/` 目录：

| 工具 | 用途 | 下载地址 |
|---|---|---|
| subfinder.exe | 被动子域名收集 | [releases](https://github.com/projectdiscovery/subfinder/releases) |
| dnsx.exe | DNS 解析/验活 | [releases](https://github.com/projectdiscovery/dnsx/releases) |
| gau.exe | 历史 URL 收集 (Wayback Machine) | [releases](https://github.com/lc/gau/releases) |
| katana.exe | 主动 URL 爬取 | [releases](https://github.com/projectdiscovery/katana/releases) |
| ffuf.exe | Web Fuzzer | [releases](https://github.com/ffuf/ffuf/releases) |
| **trufflehog.exe** | **JS 密钥检测** | **[releases](https://github.com/trufflesecurity/trufflehog/releases)** |

> **注意**: trufflehog.exe 约 162MB，未包含在仓库中（超过 GitHub 100MB 限制）。
> 下载后解压将 `trufflehog.exe` 放入 `tools/` 目录即可使用 Phase 5 JS 分析功能。
> 如不需要 JS 密钥分析，可以不下载。

## 项目结构

```
.
├── reconmaster/               # 核心框架
│   ├── core/                  # 核心模块
│   │   ├── subdomain_manager.py   # Phase 1: 子域名调度
│   │   ├── url_collector.py       # Phase 2: URL 收集
│   │   ├── url_processor.py       # Phase 3: 去重 + FUZZ 注入
│   │   ├── fuzz_engine.py         # Phase 4: ffuf 调度
│   │   └── js_analyzer.py         # Phase 5: JS 下载 + trufflehog
│   ├── config/settings.py     # 全局配置
│   ├── utils/                 # 工具函数
│   └── wordlists/             # 字典文件
├── oneforall/                 # OneForAll 子域名收集模块
├── tools/                     # 外部工具二进制 + 辅助脚本
│   ├── subfinder.exe
│   ├── dnsx.exe
│   ├── gau.exe
│   ├── katana.exe
│   ├── ffuf.exe
│   ├── trufflehog.exe         # ← 需手动下载
│   ├── fast_scan_js.py        # 快速 JS 扫描脚本
│   └── ultra_fast_scan.py     # 极速 JS 扫描脚本
├── tests/                     # 测试用例
│   ├── test_phase1_subdomain.py   # 阶段 1 单独测试
│   └── test_full_pipeline.py      # 全流程集成测试
├── requirements.txt
└── README.md
```

## 配置

编辑 `reconmaster/config/settings.py`：

- `HTTP_PROXY` — 代理地址（国内访问外网时使用）
- `FOFA_KEY` — FOFA API Key
- `TOOL_PATHS` — 各工具路径（默认从 `tools/` 读取）
- 各阶段超时和并发参数

## 运行测试

```bash
# 测试阶段 1（仅子域名收集）
python tests/test_phase1_subdomain.py example.com

# 测试全流程（5 阶段）
python tests/test_full_pipeline.py example.com
```

## 输出

扫描结果保存在 `results/<target>_<timestamp>/`，包含：
- `summary.json` — 全流程汇总
- `phase2_all_urls.txt` — 收集的 URL
- `phase3_fuzz_tasks.txt` — FUZZ 任务
- `phase5_js_analysis.json` — 密钥分析结果 (CRITICAL + INFO)
