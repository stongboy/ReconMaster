#!/usr/bin/env python3
"""github-subdomains fallback: 通过 GitHub REST API 搜索子域名。

原生 github-subdomains 仅有 Linux/macOS 二进制，Windows 下自动降级为此脚本。
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time

import requests

GITHUB_API = "https://api.github.com"
SEARCH_ENDPOINT = f"{GITHUB_API}/search/code"
PER_PAGE = 100
MAX_PAGES = 5
DELAY = 2.0

SUBDOMAIN_RE = re.compile(r"\b([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


def search_github(token: str | None, domain: str) -> set[str]:
    headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    found: set[str] = set()
    query = f'"{domain}"'

    for page in range(1, MAX_PAGES + 1):
        params = {"q": query, "per_page": PER_PAGE, "page": page}
        try:
            resp = requests.get(
                SEARCH_ENDPOINT,
                headers=headers,
                params=params,
                timeout=30,
            )
        except requests.RequestException as exc:
            logging.warning("GitHub API 请求失败 (page=%d): %s", page, exc)
            continue

        if resp.status_code == 403:
            logging.warning("GitHub API 速率限制，停止搜索")
            break
        if resp.status_code != 200:
            logging.warning("GitHub API 返回 %d: %s", resp.status_code, resp.text[:300])
            break

        data = resp.json()
        items = data.get("items", [])
        if not items:
            break

        for item in items:
            text = item.get("name", "") + " " + item.get("path", "")
            for match in SUBDOMAIN_RE.findall(text):
                if match.lower().endswith("." + domain.lower()):
                    found.add(match.lower().rstrip("."))

        if len(items) < PER_PAGE:
            break
        time.sleep(DELAY)

    return found


def main() -> None:
    parser = argparse.ArgumentParser(description="GitHub subdomain search (fallback)")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-t", "--token", default=os.getenv("GITHUB_TOKEN", ""), help="GitHub PAT")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    results = search_github(args.token, args.domain)
    for sub in sorted(results):
        print(sub)


if __name__ == "__main__":
    main()
