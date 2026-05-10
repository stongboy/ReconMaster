#!/usr/bin/env python3
"""极速 JS 密钥扫描 — 纯 aiohttp + trufflehog，跳过所有外部收集工具

流程: 主页 HTML → 提取 <script src> → 并发下载 → trufflehog
每个目标 ~3-8 秒
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reconmaster.config.settings import HTTP_PROXY, JS_ANALYSIS_TIMEOUT, TOOL_PATHS

logger = logging.getLogger("ultra_fast")

# 常见 JS 文件路径
COMMON_JS_PATHS = [
    "/app.js", "/main.js", "/bundle.js", "/index.js",
    "/static/js/app.js", "/static/js/main.js", "/js/app.js", "/js/main.js",
    "/assets/index.js", "/build/bundle.js",
]

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


def setup_logging() -> None:
    fmt = "%(asctime)s [%(levelname)-5s] %(name)s | %(message)s"
    logging.basicConfig(level=logging.INFO, format=fmt, datefmt="%H:%M:%S")
    for noisy in ("urllib3", "requests", "httpx", "chardet", "sqlalchemy", "asyncio", "aiohttp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


class UltraFastScanner:
    """极速扫描器: fetch HTML → extract JS → download → trufflehog"""

    def __init__(self) -> None:
        self._session: aiohttp.ClientSession | None = None
        self._sem = asyncio.Semaphore(15)

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=12)
        os.environ.setdefault("HTTP_PROXY", HTTP_PROXY)
        os.environ.setdefault("HTTPS_PROXY", HTTP_PROXY)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            trust_env=True,
            connector=aiohttp.TCPConnector(ssl=False, limit=20),
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    async def scan(self, target: str) -> dict:
        """扫描单个目标，返回 {critical_count, info_count, findings}"""
        base_domain = target.lower().split("/")[0].split(":")[0]
        js_urls: set[str] = set()

        # Step 1: 下载主页 HTML，提取 <script>
        for scheme in ("https://", "http://"):
            html = await self._fetch(f"{scheme}{base_domain}")
            if html:
                # 提取 <script src>
                for m in SCRIPT_SRC_RE.finditer(html):
                    src = m.group(1)
                    if src:
                        js_urls.add(self._resolve_url(src, f"{scheme}{base_domain}"))
                # 也检查内联脚本中的 import/require
                break

        if not html:
            return {"critical_count": 0, "info_count": 0, "findings": []}

        # Step 2: 追加常见 JS 路径
        for path in COMMON_JS_PATHS:
            js_urls.add(f"https://{base_domain}{path}")

        # Step 3: 保存 HTML + 并发下载 JS → 全部扫 (即使无 JS，HTML 也扫)
        workspace = Path(tempfile.mkdtemp(prefix="ufs_"))
        try:
            # 保存页面 HTML 自身（FOFA 搜到的密钥就在 HTML 里）
            html_file = workspace / f"{base_domain}.html"
            html_file.write_text(html, encoding="utf-8")

            # 并发下载 JS
            downloaded = await self._download_js(js_urls, workspace)

            # Step 4: trufflehog 扫整个 workspace（HTML + JS）
            findings = await self._run_trufflehog(workspace)
            shutil.rmtree(workspace, ignore_errors=True)
        except Exception:
            shutil.rmtree(workspace, ignore_errors=True)
            return {"critical_count": 0, "info_count": 0, "findings": []}

        critical = [f for f in findings if f.get("verified")]
        info = [f for f in findings if not f.get("verified")]
        return {
            "critical_count": len(critical),
            "info_count": len(info),
            "critical_vulns": critical,
            "info_findings": info,
            "js_downloaded": len(downloaded),
        }

    async def _fetch(self, url: str) -> str | None:
        try:
            async with self._sem:
                async with self._session.get(url) as r:
                    if r.status == 200:
                        return await r.text()
        except Exception:
            pass
        return None

    async def _download_js(self, urls: set[str], workspace: Path) -> list[Path]:
        async def dl_one(url: str) -> Path | None:
            try:
                async with self._sem:
                    async with self._session.get(url) as r:
                        if r.status == 200 and int(r.headers.get("content-length", "0")) > 50:
                            content = await r.read()
                        else:
                            return None
            except Exception:
                return None
            if not content or len(content) < 50:
                return None
            h = hashlib.md5(url.encode()).hexdigest()[:12]
            p = workspace / f"{h}.js"
            header = f"// source: {url}\n// downloaded: {datetime.now(timezone.utc).isoformat()}\n\n"
            p.write_bytes(header.encode() + content)
            return p

        tasks = [dl_one(u) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, Path)]

    async def _run_trufflehog(self, workspace: Path) -> list[dict]:
        cmd = [
            str(TOOL_PATHS["trufflehog"]),
            "filesystem", str(workspace),
            "--json", "--no-update",
            "--results", "verified,unverified,unknown",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=JS_ANALYSIS_TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return []
        except Exception:
            return []

        findings = []
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "level" in obj and "DetectorType" not in obj:
                continue
            findings.append({
                "raw": obj.get("RawV2", "") or obj.get("Raw", ""),
                "verified": obj.get("Verified", False),
                "detector_type": str(obj.get("DetectorName", obj.get("DetectorType", "Unknown"))),
                "source_file": obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                "line": obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 0),
            })
        return findings

    @staticmethod
    def _resolve_url(src: str, base_url: str) -> str:
        if src.startswith("http"):
            return src
        if src.startswith("//"):
            return "https:" + src
        if src.startswith("/"):
            # 提取 scheme+host from base_url
            p = base_url.split("/")
            return f"{p[0]}//{p[2]}{src}"
        return f"{base_url.rstrip('/')}/{src}"


async def main() -> None:
    setup_logging()

    tf = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tw_targets_v2.txt")
    targets = [l.strip() for l in tf.read_text().splitlines() if l.strip()]
    logger.info("极速扫描 %d 个目标", len(targets))

    out_root = Path("results") / "ultra_fast"
    out_root.mkdir(parents=True, exist_ok=True)

    async with UltraFastScanner() as scanner:
        for i, target in enumerate(targets, 1):
            logger.info("[%d/%d] %s", i, len(targets), target)
            try:
                result = await scanner.scan(target)
            except Exception as e:
                logger.warning("  异常: %s", e)
                continue

            c = result["critical_count"]
            info = result["info_count"]
            dled = result.get("js_downloaded", 0)
            logger.info("  JS=%d  CRITICAL=%d  INFO=%d", dled, c, info)

            if c > 0 or info > 0:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                od = out_root / f"{target}_{ts}"
                od.mkdir(parents=True, exist_ok=True)
                with open(od / "findings.json", "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=2, default=str)
                if c > 0:
                    logger.warning("!!! 发现密钥: %s → %s", target, od)
                    break
                else:
                    logger.info("  INFO findings 已保存: %s", od)

    logger.info("完成。结果: %s", out_root)


if __name__ == "__main__":
    asyncio.run(main())
