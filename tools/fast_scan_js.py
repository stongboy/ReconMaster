#!/usr/bin/env python3
"""快速 JS 密钥扫描 — 只下载主页 + JS 文件 → trufflehog，跳过全流程

用法:
    python tools/fast_scan_js.py targets.txt
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from reconmaster.config.settings import HTTP_PROXY
from reconmaster.core.js_analyzer import JSAnalyzer

logger = logging.getLogger("fast_scan")


def setup_logging() -> None:
    fmt = "%(asctime)s [%(levelname)-5s] %(name)s | %(message)s"
    logging.basicConfig(level=logging.INFO, format=fmt, datefmt="%H:%M:%S")
    for noisy in ("urllib3", "requests", "httpx", "chardet", "sqlalchemy", "asyncio", "aiohttp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


async def quick_collect_js(target: str) -> list[str]:
    """用 gau 快速收集 JS URL（不跑 katana，大幅提速）。"""
    from reconmaster.core.url_collector import URLCollector
    collector = URLCollector(target)
    result = await collector.collect([target, f"www.{target}"])
    all_urls = result["all"]

    from reconmaster.core.url_processor import URLProcessor
    processor = URLProcessor(target)
    _, js_pool = processor.process(all_urls)
    return js_pool


async def main() -> None:
    setup_logging()

    targets_file = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tw_targets_v2.txt")
    if not targets_file.exists():
        logger.error("%s 不存在", targets_file)
        return

    targets = [line.strip() for line in targets_file.read_text().splitlines() if line.strip()]
    logger.info("加载 %d 个目标 (快速 JS 扫描模式)", len(targets))

    out_root = Path("results") / "js_scan"
    out_root.mkdir(parents=True, exist_ok=True)

    # 设置代理环境变量
    os.environ.setdefault("HTTP_PROXY", HTTP_PROXY)
    os.environ.setdefault("HTTPS_PROXY", HTTP_PROXY)

    found_any = False

    for i, target in enumerate(targets, 1):
        logger.info("[%d/%d] %s", i, len(targets), target)
        try:
            js_pool = await quick_collect_js(target)
        except Exception:
            logger.exception("URL 收集异常: %s", target)
            continue

        if not js_pool:
            logger.info("  无 JS URL，跳过")
            continue

        logger.info("  JS pool: %d", len(js_pool))

        try:
            analyzer = JSAnalyzer(target)
            js_result = await analyzer.run(js_pool[:100])
        except Exception:
            logger.exception("JS 分析异常: %s", target)
            continue

        critical = js_result["critical_count"]
        info = js_result["info_count"]
        logger.info("  CRITICAL=%d  INFO=%d", critical, info)

        if critical > 0 or info > 0:
            found_any = True
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_dir = out_root / f"{target}_{ts}"
            out_dir.mkdir(parents=True, exist_ok=True)
            with open(out_dir / "findings.json", "w", encoding="utf-8") as f:
                json.dump(js_result, f, ensure_ascii=False, indent=2, default=str)
            logger.warning("!!! 发现 %d CRITICAL, %d INFO → %s", critical, info, out_dir)
            if critical > 0:
                break  # 找到 CRITICAL 就停

    if not found_any:
        logger.info("全部 %d 个目标扫描完毕，未发现密钥", len(targets))
    logger.info("结果目录: %s", out_root)


if __name__ == "__main__":
    asyncio.run(main())
