from __future__ import annotations

import re
from pathlib import Path

SUBDOMAIN_RE = re.compile(
    r"^(?!-)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$"
)


def normalize(line: str) -> str:
    """Strip whitespace / trailing dot, lowercase."""
    return line.strip().rstrip(".").lower()


def is_valid_subdomain(raw: str) -> bool:
    """Return True if *raw* looks like a plausible FQDN subdomain."""
    return bool(SUBDOMAIN_RE.match(raw))


def extract_dnsx_host(line: str) -> str | None:
    """Parse a single dnsx output line; return the hostname or None.

    dnsx -a -ro prints lines like::

         host.example.com [1.2.3.4]
         host.example.com

    We take everything before the first space.
    """
    stripped = line.strip()
    if not stripped:
        return None
    host = stripped.split()[0]
    host = host.rstrip(".")
    return host.lower() if host else None


def filter_and_dedup(candidates: list[str]) -> list[str]:
    """Lowercase → regex-filter → unique → sort."""
    seen: set[str] = set()
    result: list[str] = []
    for raw in candidates:
        name = normalize(raw)
        if name and name not in seen and is_valid_subdomain(name):
            seen.add(name)
            result.append(name)
    result.sort()
    return result


def merge_unique(*lists: list[str]) -> list[str]:
    """Merge multiple subdomain lists, dedup, sort."""
    return sorted(set().union(*lists))
