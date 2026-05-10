from __future__ import annotations

import sys
from pathlib import Path

# ---- Project Roots ----
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ONEFORALL_DIR = PROJECT_ROOT.parent / "oneforall"

# ---- Tool Paths (可替换为用户环境实际路径) ----
_TOOLS_DIR = PROJECT_ROOT.parent / "tools"
TOOL_PATHS: dict[str, str | Path] = {
    "subfinder":          _TOOLS_DIR / "subfinder.exe",
    "github-subdomains":  PROJECT_ROOT / "core" / "github_subdomains_fallback.py",
    "dnsx":               _TOOLS_DIR / "dnsx.exe",
    "gau":                _TOOLS_DIR / "gau.exe",
    "katana":             _TOOLS_DIR / "katana.exe",
    "ffuf":               _TOOLS_DIR / "ffuf.exe",
    "trufflehog":         _TOOLS_DIR / "trufflehog.exe",
    "python":             sys.executable,
}

# ---- OneForAll ----
ONEFORALL_SCRIPT = ONEFORALL_DIR / "oneforall.py"
ONEFORALL_RESULTS_DIR = ONEFORALL_DIR / "results"

# ---- Wordlist ----
DEFAULT_WORDLIST = PROJECT_ROOT / "wordlists" / "subdomains-top-5000.txt"

# ---- FOFA API ----
# 第三方代理站，仅需 key 认证
FOFA_KEY = "7b074c7e2cef25947dd2d0d8d42e56c8"
FOFA_API = "https://58.185.25.6:8443/api/v1/search/all"
FOFA_SSL = False
FOFA_FIELDS = "host,ip,port,protocol"
FOFA_SIZE = 10000
TIMEOUT_FOFA = 60

# ---- Timeouts (seconds) ----
TIMEOUT_SUBFINDER         = 10 * 60    # 10 min
TIMEOUT_GITHUB_SUBDOMAINS = 5 * 60     # 5 min
TIMEOUT_ONEFORALL         = 30 * 60    # 30 min
TIMEOUT_DNSX_BRUTE        = 20 * 60    # 20 min
TIMEOUT_DNSX_VERIFY       = 10 * 60    # 10 min

# ---- DNSX Resolver Config ----
DNSX_RESOLVERS_FILE = PROJECT_ROOT / "resolvers.txt"

# ---- Regex: lowercase labels + hyphen, label ≤63 chars, valid TLD ----
SUBDOMAIN_REGEX = r"^(?!-)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$"

# ---- URL Collection ----
TIMEOUT_GAU    = 5 * 60
TIMEOUT_KATANA = 2 * 60
KATANA_DEPTH   = 2
KATANA_CONCURRENCY = 5
URL_CONCURRENCY = 10  # aiohttp 并发数

# ---- Proxy (gau — 国内访问 Wayback Machine 需要) ----
HTTP_PROXY  = "http://127.0.0.1:7890"   # 替换为你的代理地址
HTTPS_PROXY = "http://127.0.0.1:7890"

# ---- URLProcessor ----
STATIC_SKIP_EXT = {".css", ".png", ".jpg", ".jpeg", ".gif", ".woff", ".woff2",
                   ".svg", ".ico", ".ttf", ".eot", ".webp", ".mp4", ".mp3",
                   ".avi", ".pdf", ".doc", ".docx", ".xls", ".xlsx"}
MAX_PARAM_SAMPLES = 2  # 每 (path, keyset) 最多保留样本数

# ---- Fuzz Engine (Python fallback, 替代 ffuf) ----
FUZZ_TIMEOUT         = 15.0   # 单请求超时
FUZZ_CONCURRENCY     = 20
FUZZ_CALIBRATION_REQ = 5      # 自动校准请求数
FUZZ_WORDLIST        = PROJECT_ROOT / "wordlists" / "fuzz_payloads.txt"

# ---- JS Analysis ----
JS_DOWNLOAD_CONCURRENCY = 8
JS_DOWNLOAD_TIMEOUT     = 30.0
JS_ANALYSIS_TIMEOUT     = 5 * 60
JS_WORKSPACE_PREFIX     = "tmp_js_workspace_"
