# ReconMaster

自动化安全侦察框架 — 子域名收集、URL 采集、FUZZ 爆破、JS 密钥分析。

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
- Windows / Linux
- 外部工具放在 `tools/` 目录

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 下载外部工具到 tools/ 目录
# - subfinder: https://github.com/projectdiscovery/subfinder
# - dnsx:      https://github.com/projectdiscovery/dnsx
# - gau:       https://github.com/lc/gau
# - katana:    https://github.com/projectdiscovery/katana
# - ffuf:      https://github.com/ffuf/ffuf
# - trufflehog: https://github.com/trufflesecurity/trufflehog (需 Git LFS)

# 配置代理 (settings.py)
# HTTP_PROXY = "http://127.0.0.1:7890"

# 运行全流程测试
python test_url_pipeline.py visitcloud.com

# 批量扫描 (台湾站点示例)
python batch_scan_tw.py
```

## 项目结构

```
.
├── reconmaster/          # 核心框架
│   ├── core/             # 核心模块
│   │   ├── subdomain_manager.py
│   │   ├── url_collector.py
│   │   ├── url_processor.py
│   │   ├── fuzz_engine.py
│   │   └── js_analyzer.py
│   ├── config/           # 配置
│   │   └── settings.py
│   └── utils/            # 工具函数
├── oneforall/            # OneForAll 子域名收集
├── tools/                # 外部工具二进制
├── wordlists/            # 字典文件
├── test_url_pipeline.py  # 全流程集成测试
└── batch_scan_tw.py      # 批量扫描脚本
```

## 配置

编辑 `reconmaster/config/settings.py`：

- `HTTP_PROXY` — 代理地址（用于 gau/katana 访问外网）
- `FOFA_KEY` — FOFA API Key
- 各工具超时和并发参数

## 输出

扫描结果保存在 `results/<target>_<timestamp>/`，包含：
- `summary.json` — 全流程汇总
- `phase2_all_urls.txt` — 收集的 URL
- `phase3_fuzz_tasks.txt` — FUZZ 任务
- `phase5_js_analysis.json` — 密钥分析结果
