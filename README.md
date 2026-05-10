# ReconMaster

Automated security reconnaissance framework — subdomain discovery → URL collection → web fuzzing → credential leak detection.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Download external tools into tools/ (see Tool Dependencies below)

# 3. Configure proxy if needed
#    Edit reconmaster/config/settings.py → HTTP_PROXY

# 4. Run
python run.py example.com
python run.py example.com --deep     # comprehensive JS analysis (slower)
```

## Pipeline

Run `python run.py <target>` to execute all five phases:

### Phase 1 — Subdomain Enumeration

Discovers subdomains via passive and active methods, then verifies DNS resolution.

| Source | Method |
|---|---|
| subfinder | Passive: certificate transparency, search engines, etc. |
| FOFA API | Passive: network space search engine |
| OneForAll | Passive: 30+ data sources aggregated |
| dnsx (brute-force) | Active: dictionary-based subdomain guess + DNS resolve |

Output: list of verified, resolvable subdomains.

### Phase 2 — URL Collection

Collects endpoint URLs for each verified subdomain.

| Tool | Method | Requires proxy in China? |
|---|---|---|
| gau | Wayback Machine historical URLs | Yes |
| katana | Active crawl (depth 2) | Yes |

Output: deduplicated URL list across all subdomains.

### Phase 3 — URL Processing

Intelligently deduplicates URLs and generates fuzzing targets.

- **Static separation**: `.css`, `.png`, `.jpg`, etc. are discarded; `.js` files go to the JS pool.
- **Parameter dedup**: URLs sharing the same `(path, parameter_keys)` fingerprint are collapsed — only 2 samples kept per group.
- **FUZZ injection**: Parameter values are replaced with `FUZZ`; path-only URLs get `/FUZZ` appended.

Output: fuzz task queue + JS URL pool.

### Phase 4 — Web Fuzzing

Runs ffuf against each FUZZ-injected URL with auto-calibration (`-ac`) to filter false positives.

### Phase 5 — Secret Detection

Scans JavaScript files for leaked credentials (API keys, tokens, passwords) using trufflehog.

**Default: Fast mode** (~3–8s per target)
- Fetches the homepage HTML
- Extracts `<script src>` URLs
- Downloads and scans referenced JS + homepage
- Does NOT require prior URL collection

**Deep mode** (`--deep` flag)
- Downloads ALL JS files collected in Phase 2–3
- More comprehensive but slower

All findings are graded by trufflehog's `Verified` field:
- `Verified=true` → **CRITICAL** (confirmed credential leak, prioritize)
- `Verified=false` → **INFO** (potential finding, archived for review)

## Tool Dependencies

Download each tool and place in the `tools/` directory:

| Tool | v | Size | Download |
|---|---|---|---|
| subfinder | 2.x | ~32MB | [Releases](https://github.com/projectdiscovery/subfinder/releases) |
| dnsx | 1.x | ~32MB | [Releases](https://github.com/projectdiscovery/dnsx/releases) |
| gau | 2.x | ~8MB | [Releases](https://github.com/lc/gau/releases) |
| katana | 1.x | ~45MB | [Releases](https://github.com/projectdiscovery/katana/releases) |
| ffuf | 2.x | ~8MB | [Releases](https://github.com/ffuf/ffuf/releases) |
| trufflehog | 3.x | ~162MB | [Releases](https://github.com/trufflesecurity/trufflehog/releases) |

> **trufflehog.exe** is 162MB (exceeds GitHub's 100MB limit) — not included in this repo.
> Download it separately if you need Phase 5 secret detection. Without it, phases 1–4 still work.

## Configuration

Edit `reconmaster/config/settings.py`:

```python
# Proxy — required for gau/katana if accessing from China
HTTP_PROXY  = "http://127.0.0.1:7890"

# FOFA API key
FOFA_KEY = "your-key-here"

# JS analysis mode
JS_ANALYSIS_MODE = "fast"   # "fast" (default) or "deep"

# Timeouts and concurrency (tune for your environment)
TIMEOUT_KATANA  = 2 * 60   # katana crawl timeout per subdomain
KATANA_DEPTH    = 2        # crawl depth (1=shallow, 3=deep)
FUZZ_TIMEOUT    = 15.0     # single ffuf request timeout
FUZZ_CONCURRENCY = 20      # concurrent ffuf threads
```

## Output Structure

Results are saved to `results/<target>_<timestamp>/`:

```
results/example.com_20260510_143000/
├── summary.json          # Pipeline summary
├── phase2_urls.json      # Collected URLs (gau + katana)
├── phase3_processed.json # Processed URLs + fuzz tasks
├── phase4_fuzz.json      # ffuf matches
└── phase5_secrets.json   # Credential findings (CRITICAL + INFO)
```

## Project Structure

```
.
├── run.py                      # CLI entry point
├── reconmaster/                # Core framework
│   ├── core/
│   │   ├── subdomain_manager.py    # Phase 1: subdomain orchestration
│   │   ├── url_collector.py        # Phase 2: gau + katana scheduler
│   │   ├── url_processor.py        # Phase 3: dedup + FUZZ injection
│   │   ├── fuzz_engine.py          # Phase 4: ffuf async scheduler
│   │   └── js_analyzer.py          # Phase 5: secret detection
│   ├── config/settings.py          # All configurable parameters
│   ├── utils/domain_utils.py       # Domain validation helpers
│   └── wordlists/                  # Built-in wordlists
├── oneforall/                 # OneForAll subdomain module
├── tools/                     # External binaries
└── requirements.txt
```
