"""ReconMaster — Automated security reconnaissance framework.

Usage:
    import asyncio
    from reconmaster import SubdomainManager

    async def main():
        mgr = SubdomainManager("example.com")
        result = await mgr.run()
        print(f"{result['final_count']} subdomains discovered")

    asyncio.run(main())

Or use the CLI entry point:
    python run.py example.com
    python run.py example.com --deep    (comprehensive JS scan)
"""

from reconmaster.core.subdomain_manager import SubdomainManager
from reconmaster.core.url_collector import URLCollector
from reconmaster.core.url_processor import URLProcessor
from reconmaster.core.fuzz_engine import FuzzEngine
from reconmaster.core.js_analyzer import JSAnalyzer

__all__ = [
    "SubdomainManager",
    "URLCollector",
    "URLProcessor",
    "FuzzEngine",
    "JSAnalyzer",
]
