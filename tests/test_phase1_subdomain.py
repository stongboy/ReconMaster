#!/usr/bin/env python3
"""ReconMaster 集成测试 — 端到端子域名收集+验活流程。

用法:
    python tests/test_phase1_subdomain.py example.com
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

# 将项目根加入 sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from reconmaster import SubdomainManager


def setup_logging() -> None:
    fmt = "%(asctime)s [%(levelname)-5s] %(name)s | %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        datefmt="%H:%M:%S",
    )
    # 降低第三方库噪音
    for noisy in ("urllib3", "requests", "httpx", "chardet"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


async def main(target: str) -> None:
    setup_logging()

    print(f"\n{'='*60}")
    print(f"  ReconMaster — 子域名收集与验活")
    print(f"  Target: {target}")
    print(f"{'='*60}\n")

    mgr = SubdomainManager(target)
    result = await mgr.run()

    print(f"\n{'='*60}")
    print(f"  结果摘要")
    print(f"{'='*60}")
    print(f"  耗时               : {result['elapsed_sec']:.1f}s")
    print(f"  被动收集 (原始)    : {result['passive_raw_count']}")
    print(f"  被动验活通过       : {result['verified_passive_count']}")
    print(f"  主动爆破           : {result['active_count']}")
    print(f"  最终去重总数       : {result['final_count']}")
    print(f"{'='*60}\n")

    if result["subdomains"]:
        print("最终子域名列表 (前50):")
        for sub in result["subdomains"][:50]:
            print(f"  {sub}")
        if result["final_count"] > 50:
            print(f"  ... 还有 {result['final_count'] - 50} 条")
    else:
        print("(无结果 — 可能目标域名无公开子域名)")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    asyncio.run(main(target))
