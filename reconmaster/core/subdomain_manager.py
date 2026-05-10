from __future__ import annotations

import asyncio
import base64
import csv
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
    DEFAULT_WORDLIST,
    DNSX_RESOLVERS_FILE,
    FOFA_API,
    FOFA_FIELDS,
    FOFA_KEY,
    FOFA_SIZE,
    FOFA_SSL,
    ONEFORALL_RESULTS_DIR,
    ONEFORALL_SCRIPT,
    PROJECT_ROOT,
    TIMEOUT_DNSX_BRUTE,
    TIMEOUT_DNSX_VERIFY,
    TIMEOUT_FOFA,
    TIMEOUT_GITHUB_SUBDOMAINS,
    TIMEOUT_ONEFORALL,
    TIMEOUT_SUBFINDER,
    TOOL_PATHS,
)
from reconmaster.utils.domain_utils import (
    extract_dnsx_host,
    filter_and_dedup,
    is_valid_subdomain,
    merge_unique,
    normalize,
)

logger = logging.getLogger("reconmaster.subdomain")


# ---------------------------------------------------------------------------
#  dnsx 输出行匹配（host [ip] 或 纯 host）
# ---------------------------------------------------------------------------
_DNSX_LINE_RE = re.compile(r"^\s*([a-z0-9.-]+)")


class SubdomainManager:
    """子域名收集与验活的核心调度类。

    工作流：
    1. 串行被动收集  subfinder → github-subdomains → FOFA → OneForAll
    2. dnsx 主动爆破
    3. dnsx 验活清洗（被动结果）
    4. 合并去重输出

    FOFA 结果中域名类 host 归入被动收集；ip:port/protocol 缓存为
    _fofa_context，供下游端口扫描 / httpx 探测直接使用。
    """

    def __init__(
        self,
        target: str,
        *,
        wordlist: Path | None = None,
        tool_paths: dict[str, str | Path] | None = None,
        dnsx_resolvers: Path | None = None,
        output_dir: Path | None = None,
    ) -> None:
        self.target = target.lower().rstrip(".")
        self.wordlist = Path(wordlist) if wordlist else DEFAULT_WORDLIST
        self.tool_paths = {**TOOL_PATHS, **(tool_paths or {})}
        self.dnsx_resolvers = Path(dnsx_resolvers) if dnsx_resolvers else DNSX_RESOLVERS_FILE
        self.output_dir = Path(output_dir) if output_dir else PROJECT_ROOT.parent / "results"

        # 运行时状态
        self._passive_raw: list[str] = []
        self._active_raw: list[str] = []
        self._fofa_context: list[dict[str, Any]] = []  # FOFA ip:port/protocol 缓存
        self._tmp_dir: Path | None = None
        self._tmp_files: list[Path] = []

    # ------------------------------------------------------------------
    #  公共入口
    # ------------------------------------------------------------------

    async def run(self) -> dict[str, Any]:
        """执行完整收集 + 验活流程，返回结构化结果。"""
        started = datetime.now(timezone.utc)
        self._tmp_dir = Path(tempfile.mkdtemp(prefix="reconmaster_"))
        logger.info("临时目录: %s", self._tmp_dir)

        try:
            # -- 阶段 1: 串行被动收集 -----------------------------------
            logger.info("[阶段 1/4] 串行被动收集 (subfinder → github-subdomains → OneForAll)")
            await self._collect_passive()

            # -- 阶段 2: 被动结果验活清洗 -----------------------------------
            logger.info("[阶段 2/4] dnsx 验活清洗被动收集结果")
            verified_passive = await self._verify_passive()

            # -- 阶段 3: 主动爆破 -----------------------------------
            logger.info("[阶段 3/4] dnsx 主动子域名爆破")
            self._active_raw = await self._enumerate_active()

            # -- 阶段 4: 合并去重 -----------------------------------
            logger.info("[阶段 4/4] 合并去重最终输出")
            final = merge_unique(verified_passive, self._active_raw)

        except Exception:
            logger.exception("子域名收集流程异常中断")
            raise
        finally:
            self._cleanup()

        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        logger.info(
            "收集完成: 耗时 %.1fs | 被动原始 %d | 被动验活 %d | 主动爆破 %d | 最终 %d",
            elapsed,
            len(self._passive_raw),
            len(verified_passive),
            len(self._active_raw),
            len(final),
        )

        # 持久化结果文件
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        result_file = self.output_dir / f"{self.target}_{timestamp}.txt"
        result_file.write_text("\n".join(final), encoding="utf-8")
        logger.info("结果已保存: %s", result_file)

        return {
            "target": self.target,
            "elapsed_sec": elapsed,
            "passive_raw_count": len(self._passive_raw),
            "verified_passive_count": len(verified_passive),
            "active_count": len(self._active_raw),
            "final_count": len(final),
            "subdomains": final,
            "verified_passive": verified_passive,
            "active": self._active_raw,
            "fofa_context": self._fofa_context,
        }

    # ------------------------------------------------------------------
    #  阶段 1 — 串行被动收集
    # ------------------------------------------------------------------

    async def _collect_passive(self) -> None:
        """依次运行 subfinder → github-subdomains → FOFA → OneForAll。"""
        # subfinder
        try:
            sf = await self._run_subfinder()
            self._passive_raw.extend(sf)
            logger.info("subfinder 完成: %d 条", len(sf))
        except Exception:
            logger.exception("subfinder 失败，继续下一工具")

        # github-subdomains
        try:
            gs = await self._run_github_subdomains()
            self._passive_raw.extend(gs)
            logger.info("github-subdomains 完成: %d 条", len(gs))
        except Exception:
            logger.exception("github-subdomains 失败，继续下一工具")

        # FOFA API
        try:
            fofa_domains, fofa_context = await self._run_fofa_api()
            self._passive_raw.extend(fofa_domains)
            self._fofa_context = fofa_context
            logger.info(
                "FOFA 完成: %d 域名 + %d 端口上下文",
                len(fofa_domains), len(fofa_context),
            )
        except Exception:
            logger.exception("FOFA 失败，继续下一工具")

        # OneForAll
        try:
            oa = await self._run_oneforall()
            self._passive_raw.extend(oa)
            logger.info("OneForAll 完成: %d 条", len(oa))
        except Exception:
            logger.exception("OneForAll 失败，继续后续流程")

    # ------------------------------------------------------------------
    #  阶段 2 — 被动结果验活
    # ------------------------------------------------------------------

    async def _verify_passive(self) -> list[str]:
        """将被动收集的子域名清洗去重后写入临时文件，dnsx 验活。"""
        cleaned = filter_and_dedup(self._passive_raw)
        if not cleaned:
            logger.warning("无有效被动子域名可验活")
            return []

        tmp_file = self._tmp_path("passive_cleaned.txt")
        tmp_file.write_text("\n".join(cleaned), encoding="utf-8")
        logger.info("待验活子域名: %d (已去重/清洗)", len(cleaned))

        output = await self._run_dnsx_verify(tmp_file)
        verified = [extract_dnsx_host(line) for line in output.splitlines()]
        verified = [h for h in verified if h is not None]
        verified = sorted(set(verified))
        logger.info("验活通过: %d 条", len(verified))
        return verified

    # ------------------------------------------------------------------
    #  阶段 3 — 主动爆破
    # ------------------------------------------------------------------

    async def _enumerate_active(self) -> list[str]:
        """dnsx 基于字典的主动子域名爆破。"""
        output = await self._run_dnsx_brute()
        hosts = [extract_dnsx_host(line) for line in output.splitlines()]
        hosts = [h for h in hosts if h is not None]
        hosts = sorted(set(hosts))
        logger.info("主动爆破结果: %d 条", len(hosts))
        return hosts

    # ==================================================================
    #  各工具调用实现
    # ==================================================================

    # ---- subfinder ---------------------------------------------------

    async def _run_subfinder(self) -> list[str]:
        cmd = [
            str(self.tool_paths["subfinder"]),
            "-d", self.target,
            "-silent",
        ]
        logger.info("→ 调用 subfinder: %s", " ".join(cmd))
        stdout = await self._exec(*cmd, timeout=TIMEOUT_SUBFINDER)
        return [normalize(line) for line in stdout.splitlines() if line.strip()]

    # ---- github-subdomains -------------------------------------------

    async def _run_github_subdomains(self) -> list[str]:
        tool = str(self.tool_paths["github-subdomains"])
        if tool.endswith(".py"):
            cmd = [str(self.tool_paths["python"]), tool]
        else:
            cmd = [tool]
        cmd += ["-d", self.target]
        token = str(self.tool_paths.get("github_token", ""))
        if token:
            cmd += ["-t", token]
        logger.info("→ 调用 github-subdomains: %s", " ".join(cmd))
        stdout = await self._exec(*cmd, timeout=TIMEOUT_GITHUB_SUBDOMAINS)
        return [normalize(line) for line in stdout.splitlines() if line.strip()]

    # ---- FOFA API ----------------------------------------------------

    async def _run_fofa_api(self) -> tuple[list[str], list[dict[str, Any]]]:
        """通过 FOFA API 异步拉取资产，分流为子域名 + 端口上下文。

        Returns:
            (subdomains, context_list)

            subdomains   — host 为域名格式的条目，归入被动收集
            context_list — 全部 ip:port / protocol / host 结构化记录，
                           供后续端口扫描 / httpx 精准探测
        """
        key = os.getenv("FOFA_KEY") or FOFA_KEY
        if not key:
            logger.info("FOFA 未配置 (FOFA_KEY 为空)，跳过")
            return [], []

        # base64(domain="{target}")
        query_str = f'domain="{self.target}"'
        qbase64 = base64.b64encode(query_str.encode()).decode()
        params = {
            "key": key,
            "qbase64": qbase64,
            "fields": FOFA_FIELDS,
            "size": FOFA_SIZE,
        }

        logger.info("→ 调用 FOFA API: %s?%s", FOFA_API,
                     "&".join(f"{k}={v}" for k, v in params.items()))
        all_results: list[dict[str, Any]] = []
        page = 1

        connector = aiohttp.TCPConnector(ssl=FOFA_SSL)
        async with aiohttp.ClientSession(connector=connector) as session:
            while True:
                if page > 1:
                    params["page"] = page
                try:
                    async with session.get(
                        FOFA_API, params=params,
                        timeout=aiohttp.ClientTimeout(total=TIMEOUT_FOFA),
                    ) as resp:
                        if resp.status == 401 or resp.status == 403:
                            logger.warning("FOFA API 密钥无效或权限不足 (HTTP %d)", resp.status)
                            break
                        if resp.status == 429:
                            logger.warning("FOFA API 频率限制，停止翻页")
                            break
                        if resp.status != 200:
                            logger.warning("FOFA API 返回 HTTP %d", resp.status)
                            break
                        data = await resp.json()

                except asyncio.TimeoutError:
                    logger.warning("FOFA API 请求超时 (%ds)", TIMEOUT_FOFA)
                    break
                except aiohttp.ClientError as exc:
                    logger.warning("FOFA API 网络异常: %s", exc)
                    break

                # 业务错误
                if isinstance(data, dict) and data.get("error"):
                    err_msg = data["error"]
                    logger.warning("FOFA API 业务错误: %s", err_msg)
                    if "额度" in str(err_msg) or "balance" in str(err_msg).lower():
                        logger.warning("FOFA 可用额度不足")
                    break

                results = data.get("results") if isinstance(data, dict) else []
                if not results:
                    break
                all_results.extend(results)

                # 结果数不足 size 说明已拉完
                if len(results) < FOFA_SIZE:
                    break
                page += 1

        domains: list[str] = []
        contexts: list[dict[str, Any]] = []
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

        for row in all_results:
            if not isinstance(row, list) or len(row) < 4:
                continue
            host, ip, port, protocol = row[0], row[1], row[2], row[3]

            ctx = {
                "host": host,
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "source": "fofa",
            }
            contexts.append(ctx)

            # 域名类 host → 被动子域名，纯 IP → 仅保留 context
            if host and not ip_pattern.match(host) and is_valid_subdomain(host):
                domains.append(normalize(host))

        return domains, contexts

    # ---- OneForAll ---------------------------------------------------

    async def _run_oneforall(self) -> list[str]:
        results_before = set(ONEFORALL_RESULTS_DIR.glob(f"*{self.target}*.csv"))
        cmd = [
            str(self.tool_paths["python"]),
            str(ONEFORALL_SCRIPT),
            "--target", self.target,
            "--req", "False",
            "--dns", "False",
            "run",
        ]
        logger.info("→ 调用 OneForAll: %s", " ".join(cmd))

        # OneForAll 需在其自身目录下运行（相对导入依赖）
        await self._exec(*cmd, timeout=TIMEOUT_ONEFORALL, cwd=str(ONEFORALL_SCRIPT.parent))

        return self._parse_oneforall_output(results_before)

    def _parse_oneforall_output(self, before: set[Path]) -> list[str]:
        """定位 OneForAll 新生成的 CSV/JSON 并提取子域名列。"""
        after = set(ONEFORALL_RESULTS_DIR.glob(f"*{self.target}*.csv"))
        new_files = sorted(after - before)
        if not new_files:
            # 回退：直接取最新修改的匹配 csv
            candidates = sorted(
                ONEFORALL_RESULTS_DIR.glob(f"*{self.target}*.csv"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            new_files = candidates[:1]

        if not new_files:
            logger.warning("OneForAll 未生成可识别的 CSV 文件")
            # 尝试 JSON 回退
            json_files = sorted(
                ONEFORALL_RESULTS_DIR.glob(f"*{self.target}*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if json_files:
                return self._parse_oneforall_json(json_files[0])
            return []

        logger.info("OneForAll 输出文件: %s", new_files[0])
        return self._parse_oneforall_csv(new_files[0])

    @staticmethod
    def _parse_oneforall_csv(csv_path: Path) -> list[str]:
        results: list[str] = []
        try:
            with csv_path.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    sub = row.get("subdomain", "").strip().rstrip(".").lower()
                    if sub:
                        results.append(sub)
        except Exception:
            logger.exception("解析 OneForAll CSV 失败: %s", csv_path)
        return results

    @staticmethod
    def _parse_oneforall_json(json_path: Path) -> list[str]:
        results: list[str] = []
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            entries = data if isinstance(data, list) else data.get("results", [])
            for entry in entries:
                sub = (
                    entry.get("subdomain")
                    or entry.get("domain")
                    or entry.get("host")
                    or ""
                )
                sub = sub.strip().rstrip(".").lower()
                if sub:
                    results.append(sub)
        except Exception:
            logger.exception("解析 OneForAll JSON 失败: %s", json_path)
        return results

    # ---- dnsx brute --------------------------------------------------

    async def _run_dnsx_brute(self) -> str:
        cmd = [
            str(self.tool_paths["dnsx"]),
            "-d", self.target,
            "-w", str(self.wordlist),
            "-wd", "-a", "-ro",
            "-silent",
        ]
        if self.dnsx_resolvers.exists():
            cmd.extend(["-r", str(self.dnsx_resolvers)])
        logger.info("→ dnsx 主动爆破: %s", " ".join(cmd))
        return await self._exec(*cmd, timeout=TIMEOUT_DNSX_BRUTE)

    # ---- dnsx verify -------------------------------------------------

    async def _run_dnsx_verify(self, target_list: Path) -> str:
        cmd = [
            str(self.tool_paths["dnsx"]),
            "-l", str(target_list),
            "-wd", "-a", "-ro",
            "-silent",
        ]
        if self.dnsx_resolvers.exists():
            cmd.extend(["-r", str(self.dnsx_resolvers)])
        logger.info("→ dnsx 验活: %s", " ".join(cmd))
        return await self._exec(*cmd, timeout=TIMEOUT_DNSX_VERIFY)

    # ==================================================================
    #  异步子进程基础设施
    # ==================================================================

    async def _exec(
        self,
        *cmd: str,
        timeout: float,
        cwd: str | None = None,
    ) -> str:
        """以 asyncio 子进程执行命令，捕获 stdout；超时 kill 防僵尸。"""
        logger.debug("exec[%ds]: %s", timeout, " ".join(cmd))
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.error("命令超时 (%ds)，正在 kill: %s", timeout, cmd[0])
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()
                raise RuntimeError(f"命令超时 ({timeout}s): {' '.join(cmd)}")

            if proc.returncode != 0 and proc.returncode is not None:
                stderr_tail = (
                    stderr_bytes.decode("utf-8", errors="replace")[-500:]
                    if stderr_bytes
                    else ""
                )
                logger.warning(
                    "%s 退出码 %d%s",
                    cmd[0],
                    proc.returncode,
                    f"\nstderr: {stderr_tail}" if stderr_tail else "",
                )

            return stdout_bytes.decode("utf-8", errors="replace")

        except FileNotFoundError:
            logger.error("工具未找到: %s，请检查 TOOL_PATHS 配置", cmd[0])
            raise
        except Exception:
            logger.exception("命令执行异常: %s", " ".join(cmd))
            raise

    # ------------------------------------------------------------------
    #  辅助方法
    # ------------------------------------------------------------------

    def _tmp_path(self, name: str) -> Path:
        assert self._tmp_dir is not None
        path = self._tmp_dir / name
        self._tmp_files.append(path)
        return path

    def _cleanup(self) -> None:
        if self._tmp_dir and self._tmp_dir.exists():
            try:
                shutil.rmtree(self._tmp_dir, ignore_errors=True)
                logger.debug("临时目录已清理: %s", self._tmp_dir)
            except Exception:
                logger.warning("清理临时目录失败: %s", self._tmp_dir)
