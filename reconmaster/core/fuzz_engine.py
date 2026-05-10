"""
FuzzEngine — 基于 ffuf 的异步 Web Fuzzer。

对 URLProcessor 产出的 fuzz_tasks 逐条调度 ffuf：
- 自动校准 -ac（过滤 200 OK 伪造页面）
- JSON 输出 + 临时文件
- asyncio 子进程管理 + 超时 kill
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from reconmaster.config.settings import FUZZ_CONCURRENCY, FUZZ_TIMEOUT, FUZZ_WORDLIST, TOOL_PATHS

logger = logging.getLogger("reconmaster.fuzz_engine")


class FuzzEngine:
    """ffuf 异步调度器。"""

    def __init__(
        self,
        wordlist: Path | None = None,
        concurrency: int = FUZZ_CONCURRENCY,
        timeout: float = FUZZ_TIMEOUT,
    ) -> None:
        self.wordlist = Path(wordlist) if wordlist else FUZZ_WORDLIST
        self.concurrency = concurrency
        self.timeout = timeout
        self._results: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    #  公共入口
    # ------------------------------------------------------------------

    async def run(self, fuzz_tasks: list[str]) -> list[dict[str, Any]]:
        """并发调度 ffuf 对每个 fuzz task 进行爆破。"""
        if not fuzz_tasks:
            logger.warning("Fuzz 任务为空")
            return []

        if not self.wordlist.exists():
            logger.error("Fuzz 字典不存在: %s", self.wordlist)
            return []

        logger.info(
            "ffuf 调度: %d tasks, concurrency=%d, wordlist=%s",
            len(fuzz_tasks), self.concurrency, self.wordlist,
        )

        semaphore = asyncio.Semaphore(self.concurrency)

        async def worker(task_url: str) -> list[dict[str, Any]]:
            async with semaphore:
                return await self._run_ffuf(task_url)

        tasks = [worker(u) for u in fuzz_tasks]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, res in enumerate(batch_results):
            if isinstance(res, Exception):
                logger.warning("ffuf[%s] 异常: %s", fuzz_tasks[i], res)
            elif res:
                self._results.extend(res)

        logger.info("ffuf 完成: %d matches", len(self._results))
        return self._results

    # ------------------------------------------------------------------
    #  ffuf 子进程执行
    # ------------------------------------------------------------------

    async def _run_ffuf(self, task_url: str) -> list[dict[str, Any]]:
        """对单个 FUZZ URL 调度 ffuf 子进程，解析 JSON 输出。"""
        # 临时 JSON 输出文件
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="ffuf_")
        tmp_file = Path(tmp_path)

        cmd = [
            str(TOOL_PATHS["ffuf"]),
            "-u", task_url,
            "-w", str(self.wordlist),
            "-ac",              # 自动校准，过滤无意义的 200 OK 页面
            "-of", "json",      # 输出格式
            "-o", str(tmp_file),
            "-t", "40",         # 并发线程数
            "-noninteractive",
            "-s",               # silent
        ]
        logger.debug("→ ffuf: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                logger.warning("ffuf 超时 (%ds): %s", self.timeout, task_url)
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()
                return []

        except FileNotFoundError:
            logger.error("ffuf 未找到，检查 TOOL_PATHS")
            return []
        except Exception:
            logger.exception("ffuf 子进程异常: %s", task_url)
            return []

        # 解析 JSON 输出
        results: list[dict[str, Any]] = []
        try:
            if tmp_file.exists() and tmp_file.stat().st_size > 0:
                data = json.loads(tmp_file.read_text(encoding="utf-8"))
                # ffuf JSON 结构: {"results": [...], "config": {...}}
                for entry in data.get("results", []):
                    results.append({
                        "url": entry.get("url", task_url),
                        "status": entry.get("status", 0),
                        "length": entry.get("length", 0),
                        "words": entry.get("words", 0),
                        "lines": entry.get("lines", 0),
                        "content_type": entry.get("content-type", ""),
                        "redirect_location": entry.get("redirectlocation", ""),
                    })
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("ffuf JSON 解析失败: %s", exc)
        finally:
            _safe_unlink(tmp_file)

        return results

    @property
    def results(self) -> list[dict[str, Any]]:
        return self._results


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
