"""
URLProcessor — 智能去重与 FUZZ 注入引擎。

对 gau + katana 收集的全量 URL 执行：
1. 静态资源分离（.js 收入 pool，其余丢弃）
2. 参数级去重（同路径 + 同键名组合只保留 1~2 个样本）
3. FUZZ 标记注入（值替换 + 纯路径末尾拼接）
4. 输出 fuzz_tasks 队列
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from reconmaster.config.settings import MAX_PARAM_SAMPLES, STATIC_SKIP_EXT

logger = logging.getLogger("reconmaster.url_processor")


class URLProcessor:
    """全量 URL 去重、分类、FUZZ 注入。"""

    def __init__(self, target_domain: str) -> None:
        self.target = target_domain.lower().rstrip(".")
        self.js_url_pool: list[str] = []
        self.fuzz_tasks: list[str] = []
        self.stats: dict[str, int] = {}

    # ------------------------------------------------------------------
    #  公共入口
    # ------------------------------------------------------------------

    def process(self, urls: list[str]) -> tuple[list[str], list[str]]:
        """处理全量 URL，返回 (fuzz_tasks, js_url_pool)。"""
        if not urls:
            logger.warning("URL 列表为空，跳过处理")
            return [], []

        total_in = len(urls)

        # Step 1 — 去空白 / 去重 / 限定目标域名
        cleaned = self._pre_clean(urls)
        logger.info("URL 预处理: %d → %d (去重/域名过滤)", total_in, len(cleaned))

        # Step 2 — 分离静态资源
        dynamic, js_list, skipped_static = self._separate_static(cleaned)
        self.js_url_pool = sorted(set(js_list))
        logger.info(
            "静态分离: dynamic=%d  js=%d  skipped=%d",
            len(dynamic), len(self.js_url_pool), skipped_static,
        )

        # Step 3 — 参数级去重 + FUZZ 注入
        fuzz_tasks = self._dedup_and_fuzz(dynamic)
        self.fuzz_tasks = fuzz_tasks
        logger.info("FUZZ 任务生成: %d 条", len(fuzz_tasks))

        self.stats = {
            "total_in": total_in,
            "cleaned": len(cleaned),
            "dynamic": len(dynamic),
            "js_pool": len(self.js_url_pool),
            "static_skipped": skipped_static,
            "fuzz_tasks": len(fuzz_tasks),
        }
        return self.fuzz_tasks, self.js_url_pool

    # ------------------------------------------------------------------
    #  Step 1 — 预处理
    # ------------------------------------------------------------------

    @staticmethod
    def _pre_clean(urls: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for u in urls:
            u = u.strip()
            if not u:
                continue
            # 去 fragment
            if "#" in u:
                u = u.split("#")[0]
            if u not in seen:
                seen.add(u)
                result.append(u)
        return result

    # ------------------------------------------------------------------
    #  Step 2 — 静态资源分离
    # ------------------------------------------------------------------

    @staticmethod
    def _separate_static(urls: list[str]) -> tuple[list[str], list[str], int]:
        """返回 (dynamic_urls, js_urls, skip_count)。"""
        js_pool: list[str] = []
        dynamic: list[str] = []
        skipped = 0

        for url in urls:
            path = urlparse(url).path.lower()
            _, ext = _split_ext(path)
            if ext == ".js":
                js_pool.append(url)
            elif ext in STATIC_SKIP_EXT:
                skipped += 1
            else:
                dynamic.append(url)

        return dynamic, js_pool, skipped

    # ------------------------------------------------------------------
    #  Step 3 — 参数级去重 + FUZZ 注入
    # ------------------------------------------------------------------

    def _dedup_and_fuzz(self, urls: list[str]) -> list[str]:
        """按 (path, keyset) 分组去重后注入 FUZZ 标记。"""
        # 分为含参 URL 和纯路径 URL
        param_urls: list[tuple[str, str, str, tuple[str, ...]]] = []
        # (original_url, normalized_path, raw_query, sorted_keyset)
        path_only: list[str] = []

        for url in urls:
            parsed = urlparse(url)
            path = self._normalize_path(parsed.path)
            query = parsed.query
            if query:
                qs = parse_qs(query, keep_blank_values=True)
                keyset = tuple(sorted(k for k in qs.keys()))
                param_urls.append((url, path, query, keyset))
            else:
                path_only.append(url)

        # ---- 含参 URL 去重 ----
        groups: dict[tuple[str, tuple[str, ...]], list[str]] = defaultdict(list)
        for url, path, _query, keyset in param_urls:
            groups[(path, keyset)].append(url)

        fuzz: list[str] = []
        for (path, keyset), group in groups.items():
            keep = group[:MAX_PARAM_SAMPLES]
            for orig_url in keep:
                fuzz_url = self._inject_fuzz(orig_url)
                if fuzz_url:
                    fuzz.append(fuzz_url)

        # ---- 纯路径 URL — 按路径去重后末尾追加 FUZZ ----
        seen_paths: set[str] = set()
        for url in path_only:
            parsed = urlparse(url)
            norm_path = self._normalize_path(parsed.path)
            if norm_path not in seen_paths:
                seen_paths.add(norm_path)
                fuzz.append(self._path_to_fuzz(url))

        return sorted(set(fuzz))

    # ------------------------------------------------------------------
    #  辅助方法
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_path(path: str) -> str:
        """去末尾 /，统一小写。"""
        p = path.lower().rstrip("/")
        return p if p else "/"

    @staticmethod
    def _inject_fuzz(url: str) -> str | None:
        """将含参 URL 的所有参数值替换为 FUZZ。"""
        parsed = urlparse(url)
        if not parsed.query:
            return None
        qs = parse_qs(parsed.query, keep_blank_values=True)
        fuzzed_qs = {k: "FUZZ" for k in qs}
        new_query = urlencode(fuzzed_qs, doseq=True)
        return urlunparse((
            parsed.scheme or "https",
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            "",  # fragment already stripped
        ))

    @staticmethod
    def _path_to_fuzz(url: str) -> str:
        """纯路径 URL → 末尾拼接 FUZZ，保留 scheme + host。"""
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            # 完整 URL
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path.rstrip("/") or "/"
            return f"{base}{path}/FUZZ"
        else:
            # 相对路径
            p = url.rstrip("/")
            return f"{p}/FUZZ" if p else "/FUZZ"


# ------------------------------------------------------------------
#  工具函数
# ------------------------------------------------------------------

def _split_ext(path: str) -> tuple[str, str]:
    """拆分路径为 (stem, extension)。"""
    m = re.search(r"(\.[a-z0-9]{1,10})$", path)
    if m:
        return path[:m.start()], m.group(1)
    return path, ""
