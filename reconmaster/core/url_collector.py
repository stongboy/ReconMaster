"""
URLCollector — 全量端点收集。

针对验活后的 Web 资产异步并发调用：
- gau:  被动历史 URL 收集
- katana: 主动深度爬取 (-jc -jsonl)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from reconmaster.config.settings import (
    HTTP_PROXY,
    KATANA_CONCURRENCY,
    KATANA_DEPTH,
    TIMEOUT_GAU,
    TIMEOUT_KATANA,
    TOOL_PATHS,
)

logger = logging.getLogger("reconmaster.url_collector")

# katana JSONL 行中提取 URL 的 key 名（v1.6+ 可能为 "URL" 或小写的 "url"）
_KATANA_URL_KEYS = ("URL", "url", "endpoint", "location")


class URLCollector:
    """gau + katana 异步 URL 收集器。"""

    def __init__(self, target_domain: str) -> None:
        self.target = target_domain.lower().rstrip(".")
        self._gau_urls: list[str] = []
        self._katana_urls: list[str] = []

    # ------------------------------------------------------------------
    #  公共入口 — 针对子域名列表收集
    # ------------------------------------------------------------------

    async def collect(
        self,
        subdomains: list[str],
        enabled_sources: set[str] | None = None,
    ) -> dict[str, list[str]]:
        """对每个子域名并发执行 gau + katana，返回合并后的 URL 列表。

        Returns:
            {"all": [...], "gau": [...], "katana": [...]}
        """
        if not subdomains:
            logger.warning("子域名列表为空，跳过 URL 收集")
            return {"all": [], "gau": [], "katana": []}

        logger.info(
            "URL 收集启动: %d 个子域名, gau + katana 并发",
            len(subdomains),
        )

        if enabled_sources is None or "gau" in enabled_sources:
            # gau — 所有子域名并发
            gau_tasks = [self._run_gau(sub) for sub in subdomains]
            gau_results = await asyncio.gather(*gau_tasks, return_exceptions=True)
            for i, res in enumerate(gau_results):
                if isinstance(res, Exception):
                    logger.warning("gau[%s] 异常: %s", subdomains[i], res)
                elif res:
                    self._gau_urls.extend(res)

        if enabled_sources is None or "katana" in enabled_sources:
            # katana — 限制并发数的并发（katana 自身已做爬取限速）
            sem = asyncio.Semaphore(5)
            katana_tasks = [self._run_katana(sub, sem) for sub in subdomains]
            katana_results = await asyncio.gather(*katana_tasks, return_exceptions=True)
            for i, res in enumerate(katana_results):
                if isinstance(res, Exception):
                    logger.warning("katana[%s] 异常: %s", subdomains[i], res)
                elif res:
                    self._katana_urls.extend(res)

        all_urls = sorted(set(self._gau_urls + self._katana_urls))
        logger.info(
            "URL 收集完成: gau=%d  katana=%d  unique=%d",
            len(self._gau_urls), len(self._katana_urls), len(all_urls),
        )
        return {
            "all": all_urls,
            "gau": sorted(set(self._gau_urls)),
            "katana": sorted(set(self._katana_urls)),
        }

    # ------------------------------------------------------------------
    #  工具调用
    # ------------------------------------------------------------------

    async def _run_gau(self, subdomain: str) -> list[str]:
        """调用 gau 获取历史 URL（通过 --proxy 代理访问 Wayback Machine）。"""
        cmd = [
            str(TOOL_PATHS["gau"]),
            "--proxy", HTTP_PROXY,
            subdomain,
        ]
        logger.debug("→ gau: %s (proxy=%s)", subdomain, HTTP_PROXY)
        stdout = await self._exec(*cmd, timeout=TIMEOUT_GAU)
        return [line.strip() for line in stdout.splitlines() if line.strip()]

    async def _run_katana(self, subdomain: str, sem: asyncio.Semaphore) -> list[str]:
        """调用 katana 进行主动爬取。"""
        async with sem:
            url = f"https://{subdomain}" if not subdomain.startswith("http") else subdomain
            cmd = [
                str(TOOL_PATHS["katana"]),
                "-u", url,
                "-jc",
                "-d", str(KATANA_DEPTH),
                "-c", str(KATANA_CONCURRENCY),
                "-jsonl",
                "-proxy", HTTP_PROXY,
            ]
            logger.debug("→ katana: %s", url)
            stdout = await self._exec(*cmd, timeout=TIMEOUT_KATANA)
            return self._parse_katana_jsonl(stdout)

    # ------------------------------------------------------------------
    #  katana JSONL 解析
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_katana_jsonl(raw: str) -> list[str]:
        urls: list[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            # 尝试多种可能的 URL 字段
            for key in _KATANA_URL_KEYS:
                if key in obj:
                    u = obj[key]
                    if isinstance(u, str) and u.startswith("http"):
                        urls.append(u)
                        break
            else:
                # 回退：尝试拼接
                if "request" in obj:
                    req = obj["request"]
                    if isinstance(req, dict):
                        u = req.get("url", "") or req.get("endpoint", "")
                        if u:
                            urls.append(u)
        return urls

    # ------------------------------------------------------------------
    #  子进程执行
    # ------------------------------------------------------------------

    @staticmethod
    async def _exec(*cmd: str, timeout: float, env: dict[str, str] | None = None) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, **(env or {})},
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.warning("超时 (%ds): %s", timeout, cmd[0])
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()
                return ""
            return stdout_bytes.decode("utf-8", errors="replace")
        except FileNotFoundError:
            logger.error("工具未找到: %s", cmd[0])
            return ""
        except Exception:
            logger.exception("命令异常: %s", " ".join(cmd))
            return ""
