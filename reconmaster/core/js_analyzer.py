"""
JSAnalyzer — JS 深度分析（基于 Trufflehog）。

工作流：
1. aiohttp 并发下载 js_url_pool 中 JS 到本地 tmp_js_workspace/
2. asyncio 子进程调用 trufflehog filesystem --json --verify
3. 解析 JSONL，按 Verified 分级：
   - Verified == true  → CRITICAL（高置信度，优先交付）
   - Verified == false → INFO（信息性发现，存档备查）
4. shutil.rmtree 自动清理本地临时目录
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp

from reconmaster.config.settings import (
    HTTP_PROXY,
    JS_ANALYSIS_TIMEOUT,
    JS_DOWNLOAD_CONCURRENCY,
    JS_DOWNLOAD_TIMEOUT,
    JS_WORKSPACE_PREFIX,
    TOOL_PATHS,
)

logger = logging.getLogger("reconmaster.js_analyzer")


class JSAnalyzer:
    """JS 分析器：下载 → Trufflehog → 分级 → 清理。"""

    def __init__(self, target_domain: str) -> None:
        self.target = target_domain.lower().rstrip(".")
        self._workspace: Path | None = None
        self._session: aiohttp.ClientSession | None = None
        self.critical_vulns: list[dict[str, Any]] = []
        self.info_findings: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    #  公共入口
    # ------------------------------------------------------------------

    async def run(self, js_url_pool: list[str]) -> dict[str, Any]:
        """主入口：下载 → 扫描 → 分级 → 清理。"""
        if not js_url_pool:
            logger.info("JS URL pool 为空，跳过分析")
            return self._build_result()

        self._workspace = Path(tempfile.mkdtemp(prefix=JS_WORKSPACE_PREFIX))
        logger.info("JS 工作区: %s | 待下载: %d", self._workspace, len(js_url_pool))

        try:
            # Step 1 — 并发下载
            downloaded = await self._download_all(js_url_pool)
            logger.info("下载完成: %d/%d", len(downloaded), len(js_url_pool))

            if not downloaded:
                logger.warning("无 JS 文件可扫描")
                return self._build_result()

            # Step 2 — Trufflehog 子进程扫描
            findings = await self._run_trufflehog_analysis(downloaded)

            # Step 3 — 分级
            self._classify(findings)

        except Exception:
            logger.exception("JS 分析流程异常")
        finally:
            self._cleanup()

        return self._build_result()

    # ------------------------------------------------------------------
    #  Step 1 — 并发下载 JS 到本地
    # ------------------------------------------------------------------

    async def _download_all(self, urls: list[str]) -> dict[str, Path]:
        """并发下载，返回 {source_url: local_path}。"""
        semaphore = asyncio.Semaphore(JS_DOWNLOAD_CONCURRENCY)
        result: dict[str, Path] = {}

        async def download_one(url: str) -> None:
            async with semaphore:
                local = await self._download_single(url)
                if local:
                    result[url] = local

        timeout = aiohttp.ClientTimeout(total=JS_DOWNLOAD_TIMEOUT)
        # 注入代理环境变量，aiohttp trust_env 读取
        os.environ.setdefault("HTTP_PROXY", HTTP_PROXY)
        os.environ.setdefault("HTTPS_PROXY", HTTP_PROXY)
        async with aiohttp.ClientSession(
            timeout=timeout,
            trust_env=True,
            connector=aiohttp.TCPConnector(ssl=False, limit=JS_DOWNLOAD_CONCURRENCY),
        ) as session:
            self._session = session
            tasks = [download_one(u) for u in urls]
            await asyncio.gather(*tasks, return_exceptions=True)

        return result

    async def _download_single(self, url: str) -> Path | None:
        """下载单个 JS 文件，失败返回 None。"""
        assert self._workspace is not None
        assert self._session is not None
        try:
            async with self._session.get(url, timeout=JS_DOWNLOAD_TIMEOUT) as resp:
                if resp.status != 200:
                    logger.debug("HTTP %d: %s", resp.status, url)
                    return None
                content = await resp.read()
        except (asyncio.TimeoutError, aiohttp.ClientError) as exc:
            logger.debug("下载失败 %s: %s", url, exc)
            return None

        if not content or len(content) < 20:
            return None

        url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
        # 保留原始文件名后缀，便于 trufflehog 按类型识别
        fname = f"{url_hash}.js"
        local_path = self._workspace / fname

        header = (
            f"// source: {url}\n"
            f"// downloaded: {datetime.now(timezone.utc).isoformat()}\n\n"
        )
        local_path.write_bytes(header.encode() + content)
        logger.debug("已下载: %s → %s (%d bytes)", url, fname, len(content))
        return local_path

    # ------------------------------------------------------------------
    #  Step 2 — Trufflehog 子进程分析
    # ------------------------------------------------------------------

    async def _run_trufflehog_analysis(
        self, downloaded: dict[str, Path],
    ) -> list[dict[str, Any]]:
        """通过 trufflehog filesystem 扫描本地 JS 目录。

        cmd: trufflehog filesystem <workspace> --json --verify
        返回: 结构化 findings 列表
        """
        assert self._workspace is not None
        cmd = [
            str(TOOL_PATHS["trufflehog"]),
            "filesystem",
            str(self._workspace),
            "--json",             # JSONL 输出
            "--no-update",
            "--results", "verified,unverified,unknown",
        ]
        logger.info("→ trufflehog: %s", " ".join(cmd))

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
                logger.error("trufflehog 超时 (%ds)，正在 kill", JS_ANALYSIS_TIMEOUT)
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()
                return []

        except FileNotFoundError:
            logger.error("trufflehog 未找到，检查 TOOL_PATHS")
            return []
        except Exception:
            logger.exception("trufflehog 子进程异常")
            return []

        # stderr 中的 warning 不致命
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        if stderr_text:
            logger.debug("trufflehog stderr: %s", stderr_text[:500])

        return self._parse_trufflehog_output(stdout_bytes, stderr_text)

    # ------------------------------------------------------------------
    #  JSONL 解析
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_trufflehog_output(
        stdout_bytes: bytes, stderr_text: str,
    ) -> list[dict[str, Any]]:
        """解析 trufflehog v3 JSONL 输出，提取关键字段。

        trufflehog 3.x 每行 JSON 格式：
        - Raw / RawV2:    原始匹配内容
        - Verified:       是否通过在线验证（bool）
        - DetectorName:   检测器名称（GitHub, AWS, SlackWebhook …）
        - DetectorType:   检测器类型编号（int）
        - SourceMetadata.Data.Filesystem.file: 源文件路径
        - SourceMetadata.Data.Filesystem.line: 行号
        注意：部分行是日志（含 level 字段），非发现结果，需过滤。
        """
        findings: list[dict[str, Any]] = []
        raw_text = stdout_bytes.decode("utf-8", errors="replace")

        for line_no, line in enumerate(raw_text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            # 过滤日志行（trufflehog 内部日志也走 stdout）
            if "level" in obj and "DetectorType" not in obj:
                continue

            raw = obj.get("RawV2", "") or obj.get("Raw", "")
            verified = obj.get("Verified", False)
            detector = obj.get("DetectorName", obj.get("DetectorType", "Unknown"))

            # 提取文件路径 + 行号 (trufflehog 3.x 嵌套结构)
            meta = obj.get("SourceMetadata", {})
            fs_data = meta.get("Data", {}).get("Filesystem", {})
            file_path = fs_data.get("file", obj.get("SourceName", ""))
            line_num = fs_data.get("line", 0)

            findings.append({
                "raw": raw,
                "verified": verified,
                "detector_type": str(detector),
                "source_file": file_path,
                "line": line_num,
            })

        logger.info(
            "trufflehog 发现 %d 条 (verified=%d)",
            len(findings),
            sum(1 for f in findings if f["verified"]),
        )

        # 同时处理 stderr 中可能存在的引擎错误（如网络验证超时）
        if "error" in stderr_text.lower():
            logger.debug("trufflehog stderr 含 error: %s", stderr_text[:300])

        return findings

    # ------------------------------------------------------------------
    #  Step 3 — 分级处理
    # ------------------------------------------------------------------

    def _classify(self, findings: list[dict[str, Any]]) -> None:
        """按 Verified 字段分级。

        Verified == True  → CRITICAL（高置信度密钥泄露，优先交付）
        Verified == False → INFO    （信息性发现，存档备查）
        """
        for f in findings:
            if f["verified"]:
                f["severity"] = "CRITICAL"
                self.critical_vulns.append(f)
                logger.warning(
                    "[CRITICAL] %s | %s… | %s",
                    f["detector_type"],
                    str(f["raw"])[:60],
                    Path(f.get("source_file", "")).name,
                )
            else:
                f["severity"] = "INFO"
                self.info_findings.append(f)
                logger.info(
                    "[INFO] %s | %s… | %s",
                    f["detector_type"],
                    str(f["raw"])[:40],
                    Path(f.get("source_file", "")).name,
                )

        logger.info(
            "分级完成: CRITICAL=%d  INFO=%d",
            len(self.critical_vulns), len(self.info_findings),
        )

    # ------------------------------------------------------------------
    #  清理
    # ------------------------------------------------------------------

    def _cleanup(self) -> None:
        if self._workspace and self._workspace.exists():
            try:
                shutil.rmtree(self._workspace, ignore_errors=True)
                logger.debug("JS 工作区已清理: %s", self._workspace)
            except Exception:
                logger.warning("清理 JS 工作区失败: %s", self._workspace)

    # ------------------------------------------------------------------
    #  结果构建
    # ------------------------------------------------------------------

    def _build_result(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "critical_count": len(self.critical_vulns),
            "info_count": len(self.info_findings),
            "critical_vulns": self.critical_vulns,
            "info_findings": self.info_findings,
        }
