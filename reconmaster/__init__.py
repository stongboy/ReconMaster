"""ReconMaster — 子域名收集与验活模块。

Usage::

    import asyncio
    from reconmaster import SubdomainManager

    async def main():
        mgr = SubdomainManager("example.com")
        result = await mgr.run()
        print(f"共获取 {result['final_count']} 个子域名")

    asyncio.run(main())
"""

from reconmaster.core.subdomain_manager import SubdomainManager

__all__ = ["SubdomainManager"]
