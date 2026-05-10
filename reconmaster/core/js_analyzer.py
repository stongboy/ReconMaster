"""JSAnalyzer — JavaScript secret detection via trufflehog.

Modes (configure in settings.py → JS_ANALYSIS_MODE):
  fast (default): Fetch homepage → extract <script src> → download → trufflehog
                  ~3-8s per target. Recommended for initial reconnaissance.
  deep:           Download all JS URLs from full URL collection → trufflehog.
                  Slower but comprehensive. Requires prior URL collection phase.

Output grading:
  Verified == true  → CRITICAL (high-confidence credential leak)
  Verified == false → INFO     (informational, archived for review)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp

from reconmaster.config.settings import (
    HTTP_PROXY,
    JS_ANALYSIS_MODE,
    JS_ANALYSIS_TIMEOUT,
    JS_DOWNLOAD_CONCURRENCY,
    JS_DOWNLOAD_TIMEOUT,
    JS_WORKSPACE_PREFIX,
    TOOL_PATHS,
)

logger = logging.getLogger("reconmaster.js_analyzer")

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

# Common JS entry points probed in fast mode
_PROBE_PATHS = [
    "/app.js", "/main.js", "/bundle.js", "/index.js",
    "/static/js/app.js", "/static/js/main.js",
    "/js/app.js", "/js/main.js", "/assets/index.js",
    "/build/bundle.js",
]


class JSAnalyzer:
    """JavaScript secret scanner: download → trufflehog → classify → cleanup."""

    def __init__(self, target_domain: str, mode: str | None = None) -> None:
        self.target = target_domain.lower().rstrip(".")
        self.mode = mode or JS_ANALYSIS_MODE
        self._workspace: Path | None = None
        self._session: aiohttp.ClientSession | None = None
        self.critical_vulns: list[dict[str, Any]] = []
        self.info_findings: list[dict[str, Any]] = []
        self.stats: dict[str, Any] = {}

    # ------------------------------------------------------------------
    #  Public API
    # ------------------------------------------------------------------

    async def run(self, js_url_pool: list[str] | None = None) -> dict[str, Any]:
        """Execute JS analysis.

        fast mode: js_url_pool is ignored; scans homepage + probe paths directly.
        deep mode: downloads and scans every URL in js_url_pool.
        """
        if self.mode == "deep" and js_url_pool:
            return await self._run_deep(js_url_pool)
        return await self._run_fast()

    # ------------------------------------------------------------------
    #  Fast mode
    # ------------------------------------------------------------------

    async def _run_fast(self) -> dict[str, Any]:
        """Fetch homepage HTML → extract <script src> → download → trufflehog."""
        self._workspace = Path(tempfile.mkdtemp(prefix=JS_WORKSPACE_PREFIX))
        logger.info("Fast scan: %s (workspace: %s)", self.target, self._workspace)

        try:
            html, base_url = await self._fetch_homepage()
            if not html:
                logger.warning("Homepage unreachable for %s", self.target)
                return self._build_result()

            js_urls = self._extract_script_urls(html, base_url)

            # Append probe paths for commonly named bundles
            for path in _PROBE_PATHS:
                js_urls.add(f"{base_url.rstrip('/')}{path}")

            # Save homepage HTML itself (secrets may be inline)
            html_file = self._workspace / f"{self.target}.html"
            html_file.write_text(html, encoding="utf-8")

            downloaded = await self._download_js_files(js_urls)
            logger.info("Fast scan: %d JS downloaded, %d URLs attempted",
                        len(downloaded), len(js_urls))

            if not downloaded and not html:
                return self._build_result()

            findings = await self._run_trufflehog()
            self._classify(findings)
            self.stats = {"mode": "fast", "js_downloaded": len(downloaded),
                          "js_attempted": len(js_urls)}
        except Exception:
            logger.exception("Fast scan failed for %s", self.target)
        finally:
            self._cleanup()

        return self._build_result()

    async def _fetch_homepage(self) -> tuple[str | None, str]:
        """Try HTTPS then HTTP, returning (html, base_url)."""
        os.environ.setdefault("HTTP_PROXY", HTTP_PROXY)
        os.environ.setdefault("HTTPS_PROXY", HTTP_PROXY)

        timeout = aiohttp.ClientTimeout(total=12)
        async with aiohttp.ClientSession(
            timeout=timeout, trust_env=True,
            connector=aiohttp.TCPConnector(ssl=False, limit=4),
        ) as session:
            for scheme in ("https", "http"):
                url = f"{scheme}://{self.target}"
                try:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            return await resp.text(), url
                except Exception:
                    continue
        return None, f"https://{self.target}"

    @staticmethod
    def _extract_script_urls(html: str, base_url: str) -> set[str]:
        """Extract absolute JS URLs from <script src> tags."""
        urls: set[str] = set()
        for m in _SCRIPT_SRC_RE.finditer(html):
            src = m.group(1)
            if not src:
                continue
            if src.startswith("http"):
                urls.add(src)
            elif src.startswith("//"):
                urls.add(f"https:{src}")
            elif src.startswith("/"):
                p = base_url.split("/")
                urls.add(f"{p[0]}//{p[2]}{src}")
            else:
                urls.add(f"{base_url.rstrip('/')}/{src}")
        return urls

    async def _download_js_files(self, urls: set[str]) -> dict[str, Path]:
        """Concurrently download JS files, return {url: local_path}."""
        result: dict[str, Path] = {}
        semaphore = asyncio.Semaphore(JS_DOWNLOAD_CONCURRENCY)

        async def dl_one(url: str) -> None:
            async with semaphore:
                path = await self._download_single(url)
                if path:
                    result[url] = path

        timeout = aiohttp.ClientTimeout(total=JS_DOWNLOAD_TIMEOUT)
        async with aiohttp.ClientSession(
            timeout=timeout, trust_env=True,
            connector=aiohttp.TCPConnector(ssl=False, limit=JS_DOWNLOAD_CONCURRENCY),
        ) as session:
            self._session = session
            tasks = [dl_one(u) for u in urls]
            await asyncio.gather(*tasks, return_exceptions=True)

        return result

    # ------------------------------------------------------------------
    #  Deep mode — full URL pool
    # ------------------------------------------------------------------

    async def _run_deep(self, js_url_pool: list[str]) -> dict[str, Any]:
        """Download all JS from the URL collection pool, then scan."""
        if not js_url_pool:
            logger.info("JS URL pool empty, skipping deep scan")
            return self._build_result()

        self._workspace = Path(tempfile.mkdtemp(prefix=JS_WORKSPACE_PREFIX))
        logger.info("Deep scan: %s | %d URLs queued", self._workspace, len(js_url_pool))

        try:
            downloaded = await self._download_js_files(set(js_url_pool))
            logger.info("Deep scan: %d/%d downloaded", len(downloaded), len(js_url_pool))
            if not downloaded:
                return self._build_result()

            findings = await self._run_trufflehog()
            self._classify(findings)
            self.stats = {"mode": "deep", "js_downloaded": len(downloaded),
                          "js_attempted": len(js_url_pool)}
        except Exception:
            logger.exception("Deep scan failed for %s", self.target)
        finally:
            self._cleanup()

        return self._build_result()

    # ------------------------------------------------------------------
    #  Shared: download single file
    # ------------------------------------------------------------------

    async def _download_single(self, url: str) -> Path | None:
        assert self._workspace is not None
        assert self._session is not None
        try:
            async with self._session.get(url, timeout=JS_DOWNLOAD_TIMEOUT) as resp:
                if resp.status != 200:
                    return None
                content = await resp.read()
        except (asyncio.TimeoutError, aiohttp.ClientError):
            return None

        if not content or len(content) < 20:
            return None

        url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
        local = self._workspace / f"{url_hash}.js"
        header = (
            f"// source: {url}\n"
            f"// downloaded: {datetime.now(timezone.utc).isoformat()}\n\n"
        )
        local.write_bytes(header.encode() + content)
        return local

    # ------------------------------------------------------------------
    #  Shared: trufflehog subprocess
    # ------------------------------------------------------------------

    async def _run_trufflehog(self) -> list[dict[str, Any]]:
        assert self._workspace is not None
        cmd = [
            str(TOOL_PATHS["trufflehog"]),
            "filesystem", str(self._workspace),
            "--json", "--no-update",
            "--results", "verified,unverified,unknown",
        ]
        logger.info("→ trufflehog on %s", self._workspace.name)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=JS_ANALYSIS_TIMEOUT,
                )
            except asyncio.TimeoutError:
                logger.error("trufflehog timed out after %ds", JS_ANALYSIS_TIMEOUT)
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()
                return []
        except FileNotFoundError:
            logger.error("trufflehog not found — download from https://github.com/trufflesecurity/trufflehog/releases")
            return []
        except Exception:
            logger.exception("trufflehog subprocess error")
            return []

        return self._parse_trufflehog_output(stdout_bytes)

    @staticmethod
    def _parse_trufflehog_output(stdout_bytes: bytes) -> list[dict[str, Any]]:
        """Parse trufflehog v3 JSONL output.

        Key fields: RawV2, Verified, DetectorName, SourceMetadata.Data.Filesystem
        Log lines (contain "level" but no "DetectorType") are filtered out.
        """
        findings: list[dict[str, Any]] = []
        for line in stdout_bytes.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "level" in obj and "DetectorType" not in obj:
                continue

            meta = obj.get("SourceMetadata", {})
            fs_data = meta.get("Data", {}).get("Filesystem", {})

            findings.append({
                "raw": obj.get("RawV2", "") or obj.get("Raw", ""),
                "verified": obj.get("Verified", False),
                "detector_type": str(obj.get("DetectorName", obj.get("DetectorType", "Unknown"))),
                "source_file": fs_data.get("file", obj.get("SourceName", "")),
                "line": fs_data.get("line", 0),
            })

        logger.info("trufflehog: %d findings (verified=%d)",
                    len(findings), sum(1 for f in findings if f["verified"]))
        return findings

    # ------------------------------------------------------------------
    #  Shared: classification
    # ------------------------------------------------------------------

    def _classify(self, findings: list[dict[str, Any]]) -> None:
        """Grade by Verified field: True → CRITICAL, False → INFO."""
        for f in findings:
            if f["verified"]:
                f["severity"] = "CRITICAL"
                self.critical_vulns.append(f)
                logger.warning("[CRITICAL] %s | %s… | %s",
                               f["detector_type"], str(f["raw"])[:60],
                               Path(f.get("source_file", "")).name)
            else:
                f["severity"] = "INFO"
                self.info_findings.append(f)
                logger.info("[INFO] %s | %s… | %s",
                            f["detector_type"], str(f["raw"])[:40],
                            Path(f.get("source_file", "")).name)

        logger.info("Classification: CRITICAL=%d  INFO=%d",
                    len(self.critical_vulns), len(self.info_findings))

    # ------------------------------------------------------------------
    #  Shared: cleanup
    # ------------------------------------------------------------------

    def _cleanup(self) -> None:
        if self._workspace and self._workspace.exists():
            try:
                shutil.rmtree(self._workspace, ignore_errors=True)
            except Exception:
                logger.warning("Workspace cleanup failed: %s", self._workspace)

    def _build_result(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "mode": self.mode,
            "stats": self.stats,
            "critical_count": len(self.critical_vulns),
            "info_count": len(self.info_findings),
            "critical_vulns": self.critical_vulns,
            "info_findings": self.info_findings,
        }
