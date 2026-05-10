#!/usr/bin/env python3
"""台湾站点批量扫描 — 逐个执行 ReconMaster 全流程，直到发现密钥泄露"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from reconmaster.core.url_collector import URLCollector
from reconmaster.core.url_processor import URLProcessor
from reconmaster.core.fuzz_engine import FuzzEngine
from reconmaster.core.js_analyzer import JSAnalyzer


def setup_logging() -> None:
    fmt = "%(asctime)s [%(levelname)-5s] %(name)s | %(message)s"
    logging.basicConfig(level=logging.INFO, format=fmt, datefmt="%H:%M:%S")
    for noisy in ("urllib3", "requests", "httpx", "chardet", "sqlalchemy", "asyncio", "aiohttp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

logger = logging.getLogger("reconmaster.batch")


async def scan_target(target: str, out_root: Path) -> dict:
    """对单个域名执行 Phase 2-5（跳过 Phase 1 子域名收集，直接用域名）。"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = out_root / f"{target}_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 50)
    logger.info("开始扫描: %s", target)
    logger.info("=" * 50)

    # Phase 2 — URL 收集 (用该域名直属 + www 子域)
    subdomains = [target, f"www.{target}"]
    collector = URLCollector(target)
    url_result = await collector.collect(subdomains)
    all_urls = url_result["all"]
    logger.info("Phase 2: gau=%d katana=%d unique=%d",
                len(url_result["gau"]), len(url_result["katana"]), len(all_urls))

    if not all_urls:
        logger.warning("无 URL，跳过 %s", target)
        return {"target": target, "skipped": True, "reason": "no_urls"}

    # Phase 3 — URL 处理
    processor = URLProcessor(target)
    fuzz_tasks, js_pool = processor.process(all_urls)
    logger.info("Phase 3: dynamic=%d js=%d fuzz_tasks=%d",
                processor.stats.get("dynamic", 0), len(js_pool), len(fuzz_tasks))

    # Phase 4 — ffuf
    fuzz_results = []
    if fuzz_tasks:
        engine = FuzzEngine()
        fuzz_results = await engine.run(fuzz_tasks[:10])
        logger.info("Phase 4: ffuf matches=%d", len(fuzz_results))

    # Phase 5 — JS 分析 (重点)
    js_result = {}
    if js_pool:
        analyzer = JSAnalyzer(target)
        js_result = await analyzer.run(js_pool[:50])
        logger.info("Phase 5: CRITICAL=%d INFO=%d",
                    js_result["critical_count"], js_result["info_count"])

    # 保存结果
    summary = {
        "target": target,
        "timestamp": ts,
        "phase2_unique_urls": len(all_urls),
        "phase3_dynamic": processor.stats.get("dynamic", 0),
        "phase3_js_pool": len(js_pool),
        "phase3_fuzz_tasks": len(fuzz_tasks),
        "phase4_fuzz_matches": len(fuzz_results),
        "phase5_critical": js_result.get("critical_count", 0),
        "phase5_info": js_result.get("info_count", 0),
        "critical_vulns": js_result.get("critical_vulns", []),
        "info_findings": js_result.get("info_findings", []),
    }
    with open(out_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, default=str)

    return summary


async def main() -> None:
    setup_logging()

    # 从文件读取目标列表
    targets_file = Path("tw_targets_v2.txt")
    if not targets_file.exists():
        logger.error("tw_targets.txt 不存在，请先运行 FOFA 查询")
        return

    targets = [line.strip() for line in targets_file.read_text().splitlines() if line.strip()]
    logger.info("加载 %d 个台湾站点目标", len(targets))

    out_root = Path("results") / "tw_batch"
    out_root.mkdir(parents=True, exist_ok=True)

    for i, target in enumerate(targets, 1):
        logger.info("\n[%d/%d] 目标: %s", i, len(targets), target)
        try:
            result = await scan_target(target, out_root)
        except Exception:
            logger.exception("扫描异常: %s", target)
            continue

        if result.get("skipped"):
            continue

        # 判定是否找到密钥
        critical = result.get("phase5_critical", 0)
        info = result.get("phase5_info", 0)

        if critical > 0:
            logger.warning("=" * 60)
            logger.warning("!!! 发现密钥泄露 !!! 目标: %s", target)
            logger.warning("CRITICAL=%d  INFO=%d", critical, info)
            for v in result.get("critical_vulns", []):
                logger.warning("  [%s] %s", v["detector_type"], str(v["raw"])[:80])
            logger.warning("结果保存在: %s", out_root)
            logger.warning("=" * 60)
            break  # 找到密钥就停止

        logger.info("[%d/%d] %s: 无密钥泄露 (critical=%d info=%d)",
                    i, len(targets), target, critical, info)

    else:
        logger.info("全部 %d 个站点扫描完毕，未发现密钥泄露", len(targets))

    logger.info("批量扫描结束，结果目录: %s", out_root)


if __name__ == "__main__":
    asyncio.run(main())
