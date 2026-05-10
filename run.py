#!/usr/bin/env python3
"""ReconMaster — Automated security reconnaissance pipeline.

Phases:
  1. Subdomain enumeration   — subfinder + FOFA + OneForAll → dnsx verification
  2. URL collection          — gau (Wayback) + katana (active crawl)
  3. URL processing          — dedup by parameter fingerprint → FUZZ injection
  4. Web fuzzing             — ffuf with auto-calibration
  5. Secret detection        — homepage JS extraction → trufflehog (fast mode default)

Usage:
    python run.py example.com
    python run.py example.com --deep   (comprehensive JS scan via URL pool)
"""

from __future__ import annotations

import argparse
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

logger = logging.getLogger("reconmaster")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)-5s] %(name)s | %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")
    for noisy in ("urllib3", "requests", "httpx", "chardet",
                  "sqlalchemy", "asyncio", "aiohttp", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


async def run_pipeline(target: str, deep_js: bool = False) -> dict:
    """Execute the full 5-phase reconnaissance pipeline."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path("results") / f"{target}_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 60}")
    print(f"  ReconMaster  —  {target}")
    print(f"  Results: {out_dir}")
    print(f"{'=' * 60}")

    # ==================================================================
    #  Phase 1 — Subdomain enumeration + verification
    # ==================================================================
    print("\n[Phase 1/5] Subdomain enumeration …")
    mgr = SubdomainManager(target)
    sub_result = await mgr.run()
    verified = sub_result["verified_passive"]
    print(f"  Verified: {len(verified)} subdomains")
    print(f"  Active (brute-force): {len(sub_result.get('verified_active', []))}")

    # ==================================================================
    #  Phase 2 — URL collection
    # ==================================================================
    print("\n[Phase 2/5] URL collection (gau + katana) …")
    collector = URLCollector(target)
    subdomains_http = [s for s in verified if not s.startswith("http")]
    url_result = await collector.collect(subdomains_http[:20])
    all_urls = url_result["all"]
    print(f"  gau (Wayback):    {len(url_result['gau'])}")
    print(f"  katana (crawl):   {len(url_result['katana'])}")
    print(f"  Unique total:     {len(all_urls)}")

    _save_json(out_dir / "phase2_urls.json", {
        "gau": url_result["gau"], "katana": url_result["katana"], "all": all_urls,
    })

    if not all_urls:
        print("  No URLs collected — skipping further phases")

    # ==================================================================
    #  Phase 3 — URL processing (dedup + FUZZ injection)
    # ==================================================================
    fuzz_tasks: list[str] = []
    js_pool: list[str] = []
    if all_urls:
        print("\n[Phase 3/5] URL processing (dedup + FUZZ injection) …")
        processor = URLProcessor(target)
        fuzz_tasks, js_pool = processor.process(all_urls)
        stats = processor.stats
        print(f"  Dynamic URLs:  {stats.get('dynamic', 0)}")
        print(f"  JS files:       {len(js_pool)}")
        print(f"  Static skipped: {stats.get('static_skipped', 0)}")
        print(f"  FUZZ tasks:     {len(fuzz_tasks)}")

        _save_json(out_dir / "phase3_processed.json", {
            "stats": stats, "fuzz_tasks": fuzz_tasks, "js_pool": js_pool,
        })

    # ==================================================================
    #  Phase 4 — Web fuzzing
    # ==================================================================
    fuzz_matches: list[dict] = []
    if fuzz_tasks:
        print("\n[Phase 4/5] Web fuzzing (ffuf) …")
        engine = FuzzEngine()
        fuzz_matches = await engine.run(fuzz_tasks[:15])
        print(f"  Matches: {len(fuzz_matches)}")
        for m in fuzz_matches[:5]:
            print(f"    [{m['status']}] {m['url'][:80]}  (len={m['length']})")
        _save_json(out_dir / "phase4_fuzz.json", fuzz_matches)
    else:
        print("\n[Phase 4/5] Web fuzzing — skipped (no tasks)")

    # ==================================================================
    #  Phase 5 — Secret detection (JS analysis)
    # ==================================================================
    print(f"\n[Phase 5/5] Secret detection (JS analysis) …")
    mode = "deep" if deep_js else "fast"
    analyzer = JSAnalyzer(target, mode=mode)

    if mode == "deep" and js_pool:
        js_result = await analyzer.run(js_pool[:50])
    else:
        js_result = await analyzer.run()

    print(f"  Mode:      {js_result.get('mode', mode)}")
    print(f"  CRITICAL:  {js_result['critical_count']}")
    print(f"  INFO:      {js_result['info_count']}")

    if js_result["critical_count"] > 0:
        print("\n  !!! CRITICAL FINDINGS !!!")
        for v in js_result["critical_vulns"]:
            print(f"  [{v['detector_type']:25s}] {str(v['raw'])[:80]}")
    elif js_result["info_count"] > 0:
        for v in js_result["info_findings"][:3]:
            print(f"  [{v['detector_type']:25s}] {str(v['raw'])[:60]}")

    _save_json(out_dir / "phase5_secrets.json", {
        "critical": js_result["critical_vulns"],
        "info": js_result["info_findings"],
        "stats": js_result.get("stats", {}),
    })

    # ==================================================================
    #  Summary
    # ==================================================================
    summary = {
        "target": target,
        "timestamp": ts,
        "phase1_verified": len(verified),
        "phase2_urls": len(all_urls),
        "phase3_dynamic": len(fuzz_tasks),
        "phase3_js_pool": len(js_pool),
        "phase4_fuzz_matches": len(fuzz_matches),
        "phase5_critical": js_result["critical_count"],
        "phase5_info": js_result["info_count"],
    }
    _save_json(out_dir / "summary.json", summary)

    print(f"\n{'=' * 60}")
    print(f"  Pipeline complete  —  {out_dir}")
    print(f"{'=' * 60}\n")

    return summary


def _save_json(path: Path, data: dict | list) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)


# ------------------------------------------------------------------
#  CLI
# ------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ReconMaster — Automated security reconnaissance pipeline",
        epilog="Example: python run.py example.com --deep",
    )
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--deep", action="store_true",
                        help="Deep JS scan: use full URL pool instead of fast homepage extraction")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    setup_logging(verbose=args.verbose)
    asyncio.run(run_pipeline(args.target, deep_js=args.deep))


if __name__ == "__main__":
    main()
