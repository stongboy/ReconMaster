#!/usr/bin/env python3
"""ReconMaster 全流程集成测试 — URL收集 → 去重FUZZ注入 → ffuf爆破 → JS下载+trufflehog分析

用法:
    python test_url_pipeline.py visitcloud.com
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from reconmaster import SubdomainManager
from reconmaster.core.url_collector import URLCollector
from reconmaster.core.url_processor import URLProcessor
from reconmaster.core.fuzz_engine import FuzzEngine
from reconmaster.core.js_analyzer import JSAnalyzer


def setup_logging() -> None:
    fmt = "%(asctime)s [%(levelname)-5s] %(name)s | %(message)s"
    logging.basicConfig(level=logging.INFO, format=fmt, datefmt="%H:%M:%S")
    for noisy in ("urllib3", "requests", "httpx", "chardet",
                  "sqlalchemy", "asyncio", "aiohttp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


async def main(target: str) -> None:
    setup_logging()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path("results") / f"{target}_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  ReconMaster 全流程集成测试 — {target}")
    print(f"  输出目录: {out_dir}")
    print(f"{'='*60}")

    # ==================================================================
    #  阶段 1: 子域名收集 + 验活
    # ==================================================================
    print("\n--- 阶段 1: 子域名收集 + 验活 ---")
    mgr = SubdomainManager(target)
    sub_result = await mgr.run()
    verified = sub_result["verified_passive"]
    print(f" 验活子域名: {len(verified)}")

    # ==================================================================
    #  阶段 2: URL 收集 (gau + katana)
    # ==================================================================
    print("\n--- 阶段 2: URL 收集 (gau + katana) ---")
    collector = URLCollector(target)
    subdomains_http = [s for s in verified if not s.startswith("http")]
    url_result = await collector.collect(subdomains_http[:20])
    all_urls = url_result["all"]
    print(f" 收集 URL: gau={len(url_result['gau'])}  katana={len(url_result['katana'])}  unique={len(all_urls)}")

    # 保存阶段 2 结果
    _save(out_dir / "phase2_urls.json", {
        "target": target,
        "gau_count": len(url_result["gau"]),
        "katana_count": len(url_result["katana"]),
        "unique_count": len(all_urls),
        "gau_urls": url_result["gau"],
        "katana_urls": url_result["katana"],
        "all_urls": all_urls,
    })
    _save_text(out_dir / "phase2_all_urls.txt", all_urls)

    # ==================================================================
    #  阶段 3: URL 处理 (URLProcessor)
    # ==================================================================
    print("\n--- 阶段 3: URL 处理 (去重 + FUZZ 注入) ---")
    processor = URLProcessor(target)
    fuzz_tasks, js_pool = processor.process(all_urls)
    stats = processor.stats
    print(f" {stats}")
    print(f" JS pool: {len(js_pool)} | Fuzz tasks: {len(fuzz_tasks)}")

    _save(out_dir / "phase3_processed.json", {
        "stats": stats,
        "js_pool": js_pool,
        "fuzz_tasks": fuzz_tasks,
    })
    _save_text(out_dir / "phase3_fuzz_tasks.txt", fuzz_tasks)
    _save_text(out_dir / "phase3_js_pool.txt", js_pool)

    # ==================================================================
    #  阶段 4: ffuf 爆破
    # ==================================================================
    print("\n--- 阶段 4: ffuf 爆破 ---")
    fuzz_results: list[dict] = []
    if fuzz_tasks:
        engine = FuzzEngine()
        fuzz_results = await engine.run(fuzz_tasks[:15])
        print(f" ffuf matches: {len(fuzz_results)}")
        for m in fuzz_results[:8]:
            print(f"  [{m['status']}] {m['url']}  len={m['length']}")
    else:
        print(" (无 fuzz 任务)")

    _save(out_dir / "phase4_fuzz_results.json", {
        "match_count": len(fuzz_results),
        "matches": fuzz_results,
    })

    # ==================================================================
    #  阶段 5: JS 分析 (下载 + trufflehog)
    # ==================================================================
    print("\n--- 阶段 5: JS 分析 (trufflehog) ---")
    js_result: dict = {}
    if js_pool:
        analyzer = JSAnalyzer(target)
        js_result = await analyzer.run(js_pool[:30])
        print(f" Critical: {js_result['critical_count']}  |  Info: {js_result['info_count']}")
        for v in js_result["critical_vulns"]:
            print(f"  [CRITICAL] {v['detector_type']:25s} | {str(v['raw'])[:55]}")
        for v in js_result["info_findings"][:5]:
            print(f"  [INFO]     {v['detector_type']:25s} | {str(v['raw'])[:45]}")
    else:
        print(" (无 JS URL)")

    _save(out_dir / "phase5_js_analysis.json", {
        "critical_count": js_result.get("critical_count", 0),
        "info_count": js_result.get("info_count", 0),
        "critical_vulns": js_result.get("critical_vulns", []),
        "info_findings": js_result.get("info_findings", []),
    })

    # ==================================================================
    #  汇总
    # ==================================================================
    summary = {
        "target": target,
        "timestamp": ts,
        "phase1_verified_domains": len(verified),
        "phase2_gau": len(url_result["gau"]),
        "phase2_katana": len(url_result["katana"]),
        "phase2_unique_urls": len(all_urls),
        "phase3_dynamic_urls": stats.get("dynamic", 0),
        "phase3_js_pool": len(js_pool),
        "phase3_fuzz_tasks": len(fuzz_tasks),
        "phase4_fuzz_matches": len(fuzz_results),
        "phase5_critical": js_result.get("critical_count", 0),
        "phase5_info": js_result.get("info_count", 0),
    }
    _save(out_dir / "summary.json", summary)

    print(f"\n{'='*60}")
    print(f"  全流程完成 — 结果保存在: {out_dir}")
    print(f"{'='*60}")


def _save(path: Path, data: dict | list) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)


def _save_text(path: Path, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "gdei.edu.cn"
    asyncio.run(main(target))
