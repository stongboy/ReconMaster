#!/usr/bin/env python3
"""Local browser UI for ReconMaster and the domain asset workflow."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from reconmaster.core.asset_store import AssetStore


BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"
ASSET_DB = BASE_DIR / "assets.db"
PUBLIC_SUFFIX_FILE = BASE_DIR / "oneforall" / "data" / "public_suffix_list.dat"
MAX_LOG_LINES = 2000
TARGET_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)

RESULT_FILES = {
    "phase1": "phase1_subdomains.json",
    "summary": "summary.json",
    "urls": "phase2_urls.json",
    "processed": "phase3_processed.json",
    "fuzz": "phase4_fuzz.json",
    "secrets": "phase5_secrets.json",
}

DEFAULT_SCAN_MODULES = [
    "subfinder",
    "github",
    "fofa",
    "oneforall",
    "dnsx_verify",
    "dnsx_brute",
    "gau",
    "katana",
    "ffuf",
    "js",
]


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def validate_target(value: str) -> str:
    target = value.strip().lower().rstrip(".")
    if not TARGET_RE.match(target):
        raise ValueError("目标必须是类似 example.com 的域名")
    return target


@dataclass
class Job:
    id: str
    target: str
    deep: bool
    verbose: bool
    modules: list[str]
    command: list[str]
    status: str = "queued"
    created_at: str = field(default_factory=now_iso)
    started_at: str | None = None
    ended_at: str | None = None
    returncode: int | None = None
    result_dir: str | None = None
    error: str | None = None
    cancel_requested: bool = False
    logs: list[str] = field(default_factory=list)
    process: subprocess.Popen[str] | None = field(default=None, repr=False, compare=False)
    before_result_dirs: set[Path] = field(default_factory=set, repr=False, compare=False)

    def add_log(self, line: str) -> None:
        clean = line.rstrip("\r\n")
        self.logs.append(clean)
        if len(self.logs) > MAX_LOG_LINES:
            self.logs = self.logs[-MAX_LOG_LINES:]

    def to_dict(self, include_logs: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "target": self.target,
            "deep": self.deep,
            "verbose": self.verbose,
            "modules": self.modules,
            "command": self.command,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "returncode": self.returncode,
            "result_dir": self.result_dir,
            "error": self.error,
            "summary": load_summary(self),
            "result_files": list_result_files(self),
        }
        data["logs" if include_logs else "log_tail"] = self.logs if include_logs else self.logs[-120:]
        return data


class JobManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, Job] = {}

    def start(
        self,
        target: str,
        deep: bool = False,
        verbose: bool = False,
        modules: list[str] | None = None,
    ) -> Job:
        target = validate_target(target)
        selected_modules = normalize_modules(modules)
        with self._lock:
            active = [j for j in self._jobs.values() if j.status in {"queued", "running", "cancelling"}]
            if active:
                raise RuntimeError(f"{active[0].target} 的扫描任务正在运行，请等待结束或先取消")

            command = [sys.executable, "-u", str(BASE_DIR / "run.py"), target]
            if deep:
                command.append("--deep")
            if verbose:
                command.append("--verbose")
            if selected_modules:
                command.extend(["--modules", ",".join(selected_modules)])

            job = Job(
                id=uuid.uuid4().hex[:12],
                target=target,
                deep=deep,
                verbose=verbose,
                modules=selected_modules,
                command=command,
                before_result_dirs=set(_matching_result_dirs(target)),
            )
            self._jobs[job.id] = job
            threading.Thread(target=self._run_job, args=(job,), daemon=True).start()
            return job

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)
            return [job.to_dict(include_logs=False) for job in jobs]

    def get(self, job_id: str, include_logs: bool = False) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            if job.status not in {"queued", "running"}:
                return job
            job.cancel_requested = True
            job.status = "cancelling"
            proc = job.process
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    job.add_log("[web-ui] 已请求取消，扫描进程已终止")
                except OSError as exc:
                    job.add_log(f"[web-ui] 终止扫描进程失败: {exc}")
        return job

    def _run_job(self, job: Job) -> None:
        with self._lock:
            job.status = "running"
            job.started_at = now_iso()
            job.add_log(f"[web-ui] 已启动任务 {job.id}，目标 {job.target}")
            job.add_log("[web-ui] 执行命令: " + " ".join(job.command))

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        try:
            proc = subprocess.Popen(
                job.command,
                cwd=str(BASE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
            )
            with self._lock:
                job.process = proc

            assert proc.stdout is not None
            for line in proc.stdout:
                with self._lock:
                    job.add_log(line)

            returncode = proc.wait()
            with self._lock:
                job.returncode = returncode
                job.result_dir = _detect_result_dir(job)
                job.ended_at = now_iso()
                job.process = None
                if job.cancel_requested:
                    job.status = "cancelled"
                elif returncode == 0:
                    job.status = "completed"
                else:
                    job.status = "failed"
                    job.error = f"扫描流程退出码: {returncode}"
                if job.result_dir:
                    job.add_log(f"[web-ui] 结果目录: {job.result_dir}")
                    try:
                        backfill = ASSETS.backfill_from_result(job.target, Path(job.result_dir))
                        job.add_log(f"[web-ui] 已回填资产库: {backfill.get('imported', 0)} 条")
                    except Exception as exc:
                        job.add_log(f"[web-ui] 回填资产库失败: {exc}")
        except Exception as exc:  # pragma: no cover - defensive job boundary
            with self._lock:
                job.status = "failed"
                job.error = str(exc)
                job.ended_at = now_iso()
                job.process = None
                job.result_dir = _detect_result_dir(job)
                job.add_log(f"[web-ui] 任务失败: {exc}")


def _matching_result_dirs(target: str) -> list[Path]:
    if not RESULTS_DIR.exists():
        return []
    return [p for p in RESULTS_DIR.glob(f"{target}_*") if p.is_dir()]


def _detect_result_dir(job: Job) -> str | None:
    candidates = [p for p in _matching_result_dirs(job.target) if p not in job.before_result_dirs]
    if not candidates:
        candidates = _matching_result_dirs(job.target)
    if not candidates:
        return None
    newest = max(candidates, key=lambda p: p.stat().st_mtime)
    try:
        return str(newest.resolve())
    except OSError:
        return str(newest)


def load_summary(job: Job) -> dict[str, Any] | None:
    if not job.result_dir:
        return None
    path = Path(job.result_dir) / "summary.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def list_result_files(job: Job) -> list[dict[str, Any]]:
    if not job.result_dir:
        return []
    result_dir = Path(job.result_dir)
    files: list[dict[str, Any]] = []
    for key, filename in RESULT_FILES.items():
        path = result_dir / filename
        files.append({
            "key": key,
            "filename": filename,
            "exists": path.exists(),
            "size": path.stat().st_size if path.exists() else 0,
        })
    return files


def tool_status() -> dict[str, Any]:
    tools_dir = BASE_DIR / "tools"
    tools = ["subfinder.exe", "dnsx.exe", "gau.exe", "katana.exe", "ffuf.exe", "trufflehog.exe"]
    return {
        "project_root": str(BASE_DIR),
        "results_dir": str(RESULTS_DIR),
        "asset_db": str(ASSET_DB),
        "python": sys.executable,
        "tools": [
            {
                "name": name,
                "exists": (tools_dir / name).exists(),
                "size": (tools_dir / name).stat().st_size if (tools_dir / name).exists() else 0,
            }
            for name in tools
        ],
    }


def normalize_modules(modules: list[str] | None) -> list[str]:
    if not modules:
        return DEFAULT_SCAN_MODULES.copy()
    allowed = set(DEFAULT_SCAN_MODULES)
    clean: list[str] = []
    for module in modules:
        value = str(module).strip()
        if value in allowed and value not in clean:
            clean.append(value)
    return clean or DEFAULT_SCAN_MODULES.copy()


ASSETS = AssetStore(ASSET_DB, PUBLIC_SUFFIX_FILE)
MANAGER = JobManager()


class ReconRequestHandler(BaseHTTPRequestHandler):
    server_version = "ReconMasterWeb/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        filters = {key: values[-1] for key, values in query.items()}

        if path == "/":
            return self._send_html(INDEX_HTML)
        if path == "/api/system":
            return self._send_json(tool_status())
        if path in {"/api/assets", "/api/assets/list"}:
            return self._send_json(ASSETS.list_assets(filters))
        if path == "/api/assets/stats":
            return self._send_json(ASSETS.stats())
        if path == "/api/assets/export/csv":
            raw = ASSETS.export_csv(filters).encode("utf-8-sig")
            return self._send_bytes(raw, "text/csv; charset=utf-8", "attachment; filename=assets.csv")
        if path == "/api/import-records":
            return self._send_json(ASSETS.list_import_records())
        if path == "/api/fofa/history":
            return self._send_json(ASSETS.fofa_history())
        if path == "/api/jobs":
            return self._send_json({"jobs": MANAGER.list()})

        parts = [p for p in path.split("/") if p]
        if len(parts) == 3 and parts[:2] == ["api", "jobs"]:
            job = MANAGER.get(parts[2], include_logs=True)
            if not job:
                return self._send_json({"error": "任务不存在"}, status=404)
            return self._send_json(job.to_dict(include_logs=True))
        if len(parts) == 4 and parts[:2] == ["api", "jobs"] and parts[3] == "file":
            return self._send_result_file(parts[2], query)

        self._send_json({"error": "接口不存在"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/jobs":
            payload = self._read_payload()
            try:
                job = MANAGER.start(
                    target=str(payload.get("target", "")),
                    deep=bool(payload.get("deep", False)),
                    verbose=bool(payload.get("verbose", False)),
                    modules=list(payload.get("modules") or []),
                )
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, status=400)
            except RuntimeError as exc:
                return self._send_json({"error": str(exc)}, status=409)
            return self._send_json(job.to_dict(include_logs=True), status=201)

        if path == "/api/assets/preview":
            payload = self._read_payload()
            return self._send_json(ASSETS.preview(payload))

        if path == "/api/assets/import":
            payload = self._read_payload()
            items = payload.get("items") or []
            if not isinstance(items, list):
                return self._send_json({"error": "导入内容格式错误"}, status=400)
            return self._send_json(
                ASSETS.import_assets(
                    items,
                    import_type=str(payload.get("import_type") or "manual"),
                    raw_content=json.dumps(items, ensure_ascii=False),
                )
            )

        if path == "/api/assets/single-add":
            payload = self._read_payload()
            preview = ASSETS.preview({
                "mode": "single",
                "company": payload.get("company_name") or payload.get("company"),
                "root_domains": payload.get("root_domains"),
                "subdomain": payload.get("subdomain"),
                "url": payload.get("url"),
            })
            result = ASSETS.import_assets(preview["items"], import_type="single", raw_content=json.dumps(payload, ensure_ascii=False))
            return self._send_json({"success": True, **result, "skipped": preview["counts"]["rejected"]})

        if path == "/api/assets/batch-subdomains":
            payload = self._read_payload()
            preview = ASSETS.preview({"mode": "batch", "subdomains": payload.get("subdomains")})
            result = ASSETS.import_assets(preview["items"], import_type="batch", raw_content=str(payload.get("subdomains") or ""))
            default_count = sum(1 for item in preview["items"] if item.get("company") == "默认公司")
            return self._send_json({"success": True, **result, "default_company_count": default_count})

        if path == "/api/assets/resolve":
            count = ASSETS.queue_resolve_all()
            return self._send_json({"queued": count})

        if path == "/api/tools/extract":
            payload = self._read_payload()
            return self._send_json(ASSETS.extract_content(str(payload.get("content") or "")))

        if path == "/api/import/excel":
            try:
                filename, file_bytes = self._read_multipart_file("file")
                result = ASSETS.parse_excel(file_bytes)
                result["filename"] = filename
                return self._send_json(result)
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, status=400)
            except Exception as exc:
                return self._send_json({"error": f"Excel 解析失败: {exc}"}, status=400)

        if path == "/api/fofa/generate":
            payload = self._read_payload()
            try:
                return self._send_json(ASSETS.generate_fofa_query(payload))
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, status=400)

        parts = [p for p in path.split("/") if p]
        if len(parts) == 4 and parts[:2] == ["api", "jobs"] and parts[3] == "cancel":
            try:
                job = MANAGER.cancel(parts[2])
            except KeyError:
                return self._send_json({"error": "任务不存在"}, status=404)
            return self._send_json(job.to_dict(include_logs=True))

        self._send_json({"error": "接口不存在"}, status=404)

    def do_DELETE(self) -> None:  # noqa: N802
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        if len(parts) == 4 and parts[:3] == ["api", "fofa", "history"]:
            try:
                record_id = int(parts[3])
            except ValueError:
                return self._send_json({"error": "历史记录 ID 无效"}, status=400)
            return self._send_json(ASSETS.delete_fofa_history(record_id))
        self._send_json({"error": "接口不存在"}, status=404)

    def _send_result_file(self, job_id: str, query: dict[str, list[str]]) -> None:
        job = MANAGER.get(job_id, include_logs=False)
        if not job:
            return self._send_json({"error": "任务不存在"}, status=404)
        if not job.result_dir:
            return self._send_json({"error": "该任务暂时没有结果目录"}, status=404)

        key = (query.get("name") or ["summary"])[0]
        filename = RESULT_FILES.get(key)
        if not filename:
            return self._send_json({"error": "未知结果文件"}, status=400)

        path = Path(job.result_dir) / filename
        if not path.exists():
            return self._send_json({"error": f"{filename} 不存在"}, status=404)

        ctype = mimetypes.guess_type(path.name)[0] or "application/json"
        self._send_bytes(path.read_bytes(), f"{ctype}; charset=utf-8")

    def _read_payload(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        content_type = self.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                return json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                return {}
        form = parse_qs(raw.decode("utf-8"))
        return {key: values[-1] for key, values in form.items()}

    def _read_multipart_file(self, field_name: str) -> tuple[str, bytes]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            raise ValueError("请使用 multipart/form-data 上传文件")
        message = BytesParser(policy=default).parsebytes(
            b"Content-Type: " + content_type.encode("utf-8") + b"\r\nMIME-Version: 1.0\r\n\r\n" + raw
        )
        for part in message.iter_parts():
            if part.get_param("name", header="content-disposition") == field_name:
                payload = part.get_payload(decode=True) or b""
                filename = part.get_filename() or "assets.xlsx"
                if not payload:
                    raise ValueError("上传文件为空")
                return filename, payload
        raise ValueError("没有找到上传字段 file")

    def _send_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self._send_bytes(raw, "application/json; charset=utf-8", status=status)

    def _send_html(self, html: str, status: int = 200) -> None:
        self._send_bytes(html.encode("utf-8"), "text/html; charset=utf-8", status=status)

    def _send_bytes(
        self,
        raw: bytes,
        content_type: str,
        disposition: str | None = None,
        status: int = 200,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>域名资产管理系统</title>
  <style>
    :root {
      --bg: #f6f8fb;
      --surface: #ffffff;
      --ink: #202938;
      --muted: #697586;
      --line: #dbe3ee;
      --accent: #16a34a;
      --accent-strong: #15803d;
      --accent-soft: #ecfdf5;
      --warn: #b7791f;
      --danger: #b91c1c;
      --ok: #166534;
      --code-bg: #111827;
      --code-ink: #e5e7eb;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--ink);
      font-family: Segoe UI, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      line-height: 1.5;
      letter-spacing: 0;
    }
    header {
      background: var(--surface);
      border-bottom: 1px solid var(--line);
      padding: 20px 28px 14px;
      position: sticky;
      top: 0;
      z-index: 20;
      box-shadow: 0 8px 24px rgba(15, 23, 42, .04);
    }
    .header-inner, main { max-width: 1680px; margin: 0 auto; }
    main { padding: 18px 24px 28px; }
    h1 { margin: 0; font-size: 28px; line-height: 1.2; }
    h2 { margin: 0 0 14px; font-size: 20px; }
    h3 { margin: 0 0 10px; font-size: 16px; }
    .subtle { color: var(--muted); font-size: 13px; margin-top: 6px; }
    .nav { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 18px; }
    .nav button, button {
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--ink);
      padding: 0 16px;
      font-weight: 600;
      cursor: pointer;
      transition: background .16s ease, border-color .16s ease, box-shadow .16s ease;
    }
    .nav button { flex: 0 1 112px; }
    button:hover { border-color: #b7c4d6; box-shadow: 0 6px 18px rgba(15, 23, 42, .06); }
    .nav button.active, button.primary {
      background: var(--accent);
      color: #fff;
      border-color: var(--accent);
      box-shadow: 0 10px 22px rgba(22, 163, 74, .18);
    }
    button.primary:hover { background: var(--accent-strong); }
    button.danger { color: var(--danger); border-color: #f3b7b7; }
    button:disabled { opacity: .55; cursor: not-allowed; }
    .view { display: none; }
    .view.active { display: block; }
    .panel {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 16px;
      box-shadow: 0 12px 30px rgba(15, 23, 42, .05);
    }
    .grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
    .grid-3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
    label { display: block; color: var(--muted); font-size: 13px; font-weight: 600; margin-bottom: 6px; }
    input[type="text"], input[type="file"], textarea, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px 12px;
      color: var(--ink);
      background: #fff;
      font-size: 14px;
      font-family: inherit;
    }
    input[type="text"], select { height: 40px; }
    input[type="file"] { min-height: 40px; }
    textarea {
      min-height: 150px;
      resize: vertical;
      font-family: Consolas, Cascadia Mono, Menlo, monospace;
    }
    textarea[readonly] { background: #f8fafc; }
    input:focus, textarea:focus, select:focus {
      outline: 2px solid rgba(22, 163, 74, .15);
      border-color: var(--accent);
    }
    .field { margin-bottom: 14px; }
    .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
    .message { min-height: 22px; margin-top: 10px; color: var(--muted); font-size: 13px; font-weight: 600; }
    .message.success { color: var(--ok); }
    .message.error { color: var(--danger); }
    .toast {
      position: fixed;
      right: 22px;
      bottom: 22px;
      z-index: 50;
      max-width: min(420px, calc(100vw - 32px));
      padding: 12px 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      color: var(--ink);
      box-shadow: 0 18px 36px rgba(15, 23, 42, .18);
      opacity: 0;
      pointer-events: none;
      transform: translateY(8px);
      transition: opacity .18s ease, transform .18s ease;
      font-size: 13px;
      font-weight: 700;
    }
    .toast.show { opacity: 1; transform: translateY(0); }
    .toast.success { border-color: #bbf7d0; background: var(--accent-soft); color: var(--ok); }
    .toast.error { border-color: #fecaca; background: #fff1f2; color: var(--danger); }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
      gap: 10px;
      margin-bottom: 16px;
    }
    .metric {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      min-height: 86px;
      box-shadow: 0 10px 24px rgba(15, 23, 42, .04);
    }
    .metric .value { font-size: 26px; font-weight: 800; }
    .metric .label { color: var(--muted); font-size: 12px; margin-top: 4px; }
    .table-wrap { width: 100%; overflow: auto; border: 1px solid var(--line); border-radius: 8px; }
    table { width: 100%; border-collapse: collapse; background: #fff; min-width: 980px; }
    th, td {
      border-bottom: 1px solid #edf1f7;
      padding: 10px 12px;
      text-align: left;
      vertical-align: top;
      font-size: 13px;
    }
    th { background: #f8fafc; color: #526071; font-weight: 700; position: sticky; top: 0; }
    tbody tr:hover { background: #fbfefc; }
    .tag {
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      padding: 0 8px;
      border-radius: 999px;
      background: #eef2f7;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      white-space: nowrap;
    }
    .tag.Pending, .tag.running, .tag.queued, .tag.cancelling { color: var(--warn); background: #fff8e5; }
    .tag.Resolved, .tag.completed { color: var(--ok); background: #ecfdf5; }
    .tag.Failed, .tag.failed, .tag.cancelled { color: var(--danger); background: #fef2f2; }
    .scan-layout { display: grid; grid-template-columns: minmax(320px, 420px) minmax(0, 1fr); gap: 16px; }
    .check-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .check-grid label, label.check-line {
      color: var(--ink);
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 0;
    }
    .jobs { display: grid; gap: 8px; max-height: 260px; overflow: auto; }
    .job-row { width: 100%; height: auto; padding: 10px; text-align: left; display: grid; gap: 4px; }
    .job-row.active { border-color: var(--accent); }
    .content-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(340px, .8fr); gap: 16px; }
    .tabs { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
    .tabs button { min-height: 32px; padding: 0 10px; font-size: 13px; }
    .tabs button.active { border-color: var(--accent); color: var(--accent); background: #ecfdf5; }
    pre {
      margin: 0;
      border-radius: 8px;
      background: var(--code-bg);
      color: var(--code-ink);
      padding: 14px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: Consolas, Cascadia Mono, Menlo, monospace;
      font-size: 12px;
      line-height: 1.45;
      min-height: 320px;
      max-height: 560px;
    }
    .tools { display: grid; gap: 6px; font-size: 13px; }
    .tool-row { display: flex; justify-content: space-between; gap: 12px; border-bottom: 1px solid #eef2f7; padding-bottom: 6px; }
    .ok { color: var(--ok); font-weight: 700; }
    .missing { color: var(--danger); font-weight: 700; }
    @media (max-width: 1080px) {
      .grid-2, .grid-3, .scan-layout, .content-grid { grid-template-columns: 1fr; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 640px) {
      header { padding: 18px 20px 12px; }
      main { padding: 14px 14px 24px; }
      h1 { font-size: 24px; }
      .nav { gap: 8px; }
      .nav button { flex: 1 1 calc(50% - 8px); padding: 0 10px; }
      .panel { padding: 16px; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .metric { min-height: 78px; padding: 12px; }
      .metric .value { font-size: 22px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <h1>域名资产管理系统</h1>
      <div class="subtle">用于红队前期信息打点的资产管理、提取、FOFA 查询与 ReconMaster 扫描调度</div>
      <nav class="nav" id="main-nav">
        <button data-view="single" class="active">单个录入</button>
        <button data-view="batch">批量录入</button>
        <button data-view="excel">Excel 导入</button>
        <button data-view="url-extract">URL 提取</button>
        <button data-view="fofa">FOFA 查询</button>
        <button data-view="assets">资产列表</button>
        <button data-view="imports">导入统计</button>
        <button data-view="scan">扫描任务</button>
      </nav>
    </div>
  </header>
  <main>
    <div class="metrics">
      <div class="metric"><div class="value" id="stat-total">0</div><div class="label">资产总数</div></div>
      <div class="metric"><div class="value" id="stat-companies">0</div><div class="label">公司数</div></div>
      <div class="metric"><div class="value" id="stat-roots">0</div><div class="label">根域名</div></div>
      <div class="metric"><div class="value" id="stat-resolved">0</div><div class="label">已解析</div></div>
      <div class="metric"><div class="value" id="stat-pending">0</div><div class="label">待解析</div></div>
      <div class="metric"><div class="value" id="stat-failed">0</div><div class="label">解析失败</div></div>
    </div>

    <section id="view-single" class="view active">
      <div class="panel">
        <h2>新增资产</h2>
        <div class="field">
          <label for="single-company">公司名称</label>
          <input id="single-company" type="text" placeholder="请输入公司全称，不填则使用默认公司">
        </div>
        <div class="field">
          <label for="single-roots">根域名（每行一个）</label>
          <textarea id="single-roots" placeholder="例如：&#10;www.example.com&#10;test.com"></textarea>
          <div class="subtle">自动移除 www. 前缀，并按公共后缀规则识别根域名。</div>
        </div>
        <div class="grid-2">
          <div class="field">
            <label for="single-subdomain">子域名（可选）</label>
            <input id="single-subdomain" type="text" placeholder="例如：www.subdomain.com">
          </div>
          <div class="field">
            <label for="single-url">URL（可选）</label>
            <input id="single-url" type="text" placeholder="例如：http://www.subdomain.com">
          </div>
        </div>
        <div class="actions">
          <button class="primary" onclick="previewSingle()">清洗预览</button>
          <button onclick="confirmImport()">确认入库</button>
        </div>
        <div id="single-message" class="message"></div>
      </div>
    </section>

    <section id="view-batch" class="view">
      <div class="panel">
        <h2>批量录入</h2>
        <div class="field">
          <label for="batch-subdomains">子域名（每行一个）</label>
          <textarea id="batch-subdomains" placeholder="119.baidu.com&#10;911.baidu.com&#10;中文说明 abc.baidu.com 其他文字"></textarea>
          <div class="subtle">这里只填子域名。系统会自动提取根域，匹配已有根域主资产后继承公司；匹配不到则归入默认公司。</div>
        </div>
        <div class="actions">
          <button class="primary" onclick="previewBatch()">清洗预览</button>
          <button onclick="confirmImport()">批量入库</button>
        </div>
        <div id="batch-message" class="message"></div>
      </div>
    </section>

    <section id="view-excel" class="view">
      <div class="panel">
        <h2>Excel 导入</h2>
        <div class="field">
          <label for="excel-file">资产表格</label>
          <input id="excel-file" type="file" accept=".xlsx,.xlsm">
          <div class="subtle">表头支持：公司名称、根域名、子域名、URL。上传后先生成预览，确认后才入库。</div>
        </div>
        <div class="actions">
          <button class="primary" onclick="previewExcel()">读取预览</button>
          <button onclick="confirmImport()">确认入库</button>
        </div>
        <div id="excel-message" class="message"></div>
      </div>
    </section>

    <section id="view-url-extract" class="view">
      <div class="panel">
        <h2>URL 提取</h2>
        <div class="field">
          <label for="url-company">公司名称（生成资产预览时使用）</label>
          <input id="url-company" type="text" placeholder="不填则使用默认公司">
        </div>
        <div class="field">
          <label for="url-text">粘贴原始文本</label>
          <textarea id="url-text" placeholder="粘贴网页、聊天记录、FOFA 导出、搜索结果或接口文本，系统会提取 URL、域名和 IP"></textarea>
        </div>
        <div class="actions">
          <button class="primary" onclick="extractTools()">提取 URL / 域名 / IP</button>
          <button onclick="sendExtractedDomainsToBatch()">域名送入批量录入</button>
          <button onclick="previewExtractedUrls()">URL 生成资产预览</button>
        </div>
        <div id="url-message" class="message"></div>
      </div>
      <div class="grid-3">
        <div class="panel">
          <h3>域名</h3>
          <textarea id="url-domains" readonly></textarea>
        </div>
        <div class="panel">
          <h3>IP</h3>
          <textarea id="url-ips" readonly></textarea>
        </div>
        <div class="panel">
          <h3>URL</h3>
          <textarea id="url-urls" readonly></textarea>
        </div>
      </div>
    </section>

    <section id="view-fofa" class="view">
      <div class="grid-2">
        <div class="panel">
          <h2>一键 FOFA 查询生成</h2>
          <div class="field">
            <label for="fofa-domains">域名列表</label>
            <textarea id="fofa-domains" placeholder="baidu.com&#10;91.com&#10;vdes.com"></textarea>
          </div>
          <div class="actions">
            <label class="check-line"><input id="fofa-domain" type="checkbox" checked> domain</label>
            <label class="check-line"><input id="fofa-cert" type="checkbox" checked> cert</label>
          </div>
          <div class="actions">
            <button class="primary" onclick="generateFofa()">生成查询</button>
            <button onclick="clearFofa()">重新生成</button>
          </div>
          <div id="fofa-message" class="message"></div>
        </div>
        <div class="panel">
          <h2>生成结果</h2>
          <textarea id="fofa-result" readonly></textarea>
          <div class="actions">
            <button onclick="copyText('fofa-result')">复制查询</button>
          </div>
        </div>
      </div>
      <div class="panel">
        <h2>最近生成记录</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th>时间</th><th>数量</th><th>查询预览</th><th>操作</th></tr></thead>
            <tbody id="fofa-history-body"><tr><td colspan="4">正在加载...</td></tr></tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="panel" id="preview-panel">
      <h2>清洗预览</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>公司名称</th><th>根域名</th><th>子域名</th><th>URL</th><th>唯一键</th><th>来源</th><th>状态</th></tr></thead>
          <tbody id="preview-body"><tr><td colspan="7">暂无预览数据</td></tr></tbody>
        </table>
      </div>
    </section>

    <section id="view-assets" class="view">
      <div class="panel">
        <h2>资产列表</h2>
        <div class="grid-3">
          <div class="field"><label>公司名称</label><input id="filter-company" type="text"></div>
          <div class="field"><label>根域名</label><input id="filter-root" type="text"></div>
          <div class="field"><label>状态</label><select id="filter-status"><option value="">全部</option><option>Pending</option><option>Resolved</option><option>Failed</option></select></div>
          <div class="field"><label>来源</label><input id="filter-source" type="text"></div>
          <div class="field"><label>关键词</label><input id="filter-q" type="text"></div>
          <div class="field"><label>&nbsp;</label><button class="primary" onclick="loadAssets()">搜索</button></div>
        </div>
        <div class="actions">
          <button onclick="queueResolveAll()">重新解析全部</button>
          <button onclick="loadAssets()">刷新列表</button>
          <button onclick="exportAssets()">导出 CSV</button>
        </div>
      </div>
      <div class="panel">
        <div class="table-wrap">
          <table>
            <thead><tr><th>公司名称</th><th>根域名</th><th>子域名</th><th>URL</th><th>解析 IP</th><th>状态</th><th>来源</th><th>更新时间</th></tr></thead>
            <tbody id="assets-body"><tr><td colspan="8">正在加载...</td></tr></tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="view-imports" class="view">
      <div class="panel">
        <h2>导入统计</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th>时间</th><th>类型</th><th>总数</th><th>成功</th><th>失败</th><th>原始内容预览</th></tr></thead>
            <tbody id="imports-body"><tr><td colspan="6">正在加载...</td></tr></tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="view-scan" class="view">
      <div class="scan-layout">
        <div>
          <section class="panel">
            <h2>扫描任务</h2>
            <form id="scan-form">
              <div class="field">
                <label for="target">目标域名</label>
                <input id="target" type="text" placeholder="example.com" required>
              </div>
              <div class="field">
                <label>子域名与采集模块</label>
                <div class="check-grid" id="module-box">
                  <label><input type="checkbox" value="subfinder" checked> subfinder</label>
                  <label><input type="checkbox" value="github" checked> GitHub</label>
                  <label><input type="checkbox" value="fofa" checked> FOFA</label>
                  <label><input type="checkbox" value="oneforall" checked> OneForAll</label>
                  <label><input type="checkbox" value="dnsx_verify" checked> dnsx 验活</label>
                  <label><input type="checkbox" value="dnsx_brute" checked> dnsx 爆破</label>
                  <label><input type="checkbox" value="gau" checked> gau URL</label>
                  <label><input type="checkbox" value="katana" checked> katana 爬取</label>
                  <label><input type="checkbox" value="ffuf" checked> ffuf Fuzz</label>
                  <label><input type="checkbox" value="js" checked> JS 敏感信息</label>
                </div>
              </div>
              <label class="check-grid"><span><input id="deep" type="checkbox"> 深度 JS 扫描</span><span><input id="verbose" type="checkbox"> 详细日志</span></label>
              <div class="actions">
                <button type="submit" class="primary">开始扫描</button>
                <button type="button" id="cancel-btn" class="danger" disabled>取消任务</button>
              </div>
              <div id="scan-message" class="message"></div>
            </form>
          </section>
          <section class="panel">
            <h2>任务列表</h2>
            <div id="jobs" class="jobs"></div>
          </section>
          <section class="panel">
            <h2>工具检查</h2>
            <div id="server-status" class="subtle">正在加载系统状态...</div>
            <div id="tools" class="tools"></div>
          </section>
        </div>
        <div class="content-grid">
          <section class="panel">
            <h2>扫描结果</h2>
            <div class="tabs" id="tabs">
              <button data-file="summary" class="active">概览</button>
              <button data-file="phase1">子域名</button>
              <button data-file="urls">URL</button>
              <button data-file="processed">处理结果</button>
              <button data-file="fuzz">Fuzz</button>
              <button data-file="secrets">敏感信息</button>
            </div>
            <pre id="result-view">请启动扫描，或选择一个已完成的任务。</pre>
          </section>
          <section class="panel">
            <h2>实时日志</h2>
            <pre id="log-view">尚未选择任务。</pre>
          </section>
        </div>
      </div>
    </section>
  </main>
  <div id="toast" class="toast" role="status" aria-live="polite"></div>
  <script>
    const state = { currentJobId: null, currentFile: "summary", previewItems: [], extracted: { domains: [], ips: [], urls: [] }, fofaHistory: [] };
    const $ = (id) => document.getElementById(id);
    const statusText = { queued: "排队中", running: "运行中", cancelling: "取消中", cancelled: "已取消", completed: "已完成", failed: "失败" };

    async function request(path, options = {}) {
      const isForm = options.body instanceof FormData;
      const headers = isForm ? {} : { "Content-Type": "application/json" };
      const response = await fetch(path, { headers, ...options });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || response.statusText);
      return data;
    }
    function setText(id, text) { const el = $(id); if (el) el.textContent = text ?? ""; }
    function setValue(id, text) { const el = $(id); if (el) el.value = text ?? ""; }
    function setMessage(id, text, type = "") {
      const el = $(id);
      if (!el) return;
      el.textContent = text ?? "";
      el.className = `message ${type}`.trim();
    }
    function tag(status) { return `<span class="tag ${status}">${statusText[status] || status}</span>`; }
    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, (s) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[s]));
    }
    let toastTimer = null;
    function showToast(text, type = "success") {
      const toast = $("toast");
      toast.textContent = text;
      toast.className = `toast ${type} show`;
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => { toast.className = "toast"; }, 2600);
    }
    function activeImportType() {
      const active = document.querySelector(".view.active")?.id?.replace("view-", "");
      return ({ single: "single", batch: "batch", excel: "excel", "url-extract": "url_extract" })[active] || "manual";
    }

    document.querySelectorAll("#main-nav button").forEach((btn) => {
      btn.addEventListener("click", () => switchView(btn.dataset.view));
    });
    function switchView(name) {
      document.querySelectorAll("#main-nav button").forEach((btn) => btn.classList.toggle("active", btn.dataset.view === name));
      document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${name}`));
      $("preview-panel").style.display = ["single", "batch", "excel", "url-extract"].includes(name) ? "block" : "none";
      if (name === "assets") loadAssets();
      if (name === "imports") loadImportRecords();
      if (name === "fofa") loadFofaHistory();
    }

    async function loadStats() {
      const stats = await request("/api/assets/stats");
      setText("stat-total", stats.total);
      setText("stat-companies", stats.companies);
      setText("stat-roots", stats.roots);
      setText("stat-resolved", stats.resolved);
      setText("stat-pending", stats.pending);
      setText("stat-failed", stats.failed);
    }

    async function previewSingle() {
      await previewAssets({
        mode: "single",
        company: $("single-company").value,
        root_domains: $("single-roots").value,
        subdomain: $("single-subdomain").value,
        url: $("single-url").value
      }, "single-message");
    }
    async function previewBatch() {
      await previewAssets({ mode: "batch", subdomains: $("batch-subdomains").value }, "batch-message");
    }
    async function previewExcel() {
      const file = $("excel-file").files[0];
      if (!file) {
        setMessage("excel-message", "请选择 Excel 文件", "error");
        return;
      }
      const form = new FormData();
      form.append("file", file);
      try {
        const data = await request("/api/import/excel", { method: "POST", body: form });
        state.previewItems = data.items || [];
        renderPreview();
        setMessage("excel-message", `读取 ${data.filename || file.name}，识别到 ${state.previewItems.length} 条有效资产`, "success");
      } catch (error) {
        setMessage("excel-message", error.message, "error");
      }
    }
    async function previewExtractedUrls() {
      const text = $("url-urls").value || $("url-text").value;
      await previewAssets({
        mode: "url_extract",
        company: $("url-company").value,
        text
      }, "url-message");
    }
    async function previewAssets(payload, messageId) {
      setMessage(messageId, "");
      try {
        const data = await request("/api/assets/preview", { method: "POST", body: JSON.stringify(payload) });
        state.previewItems = data.items || [];
        renderPreview();
        setMessage(messageId, `识别到 ${state.previewItems.length} 条有效资产`, "success");
      } catch (error) {
        setMessage(messageId, error.message, "error");
      }
    }
    function renderPreview() {
      const body = $("preview-body");
      if (!state.previewItems.length) {
        body.innerHTML = `<tr><td colspan="7">暂无预览数据</td></tr>`;
        return;
      }
      body.innerHTML = state.previewItems.map((item) => `
        <tr>
          <td>${escapeHtml(item.company_name || item.company)}</td>
          <td>${escapeHtml(item.root_domain)}</td>
          <td>${escapeHtml(item.subdomain || "-")}</td>
          <td>${escapeHtml(item.url || "-")}</td>
          <td>${escapeHtml(item.domain_key || item.asset_key || "-")}</td>
          <td>${escapeHtml(item.source)}</td>
          <td>${tag(item.status || "Pending")}</td>
        </tr>
      `).join("");
    }
    async function confirmImport() {
      if (!state.previewItems.length) {
        showToast("请先清洗预览", "error");
        return;
      }
      try {
        const importType = activeImportType();
        const data = await request("/api/assets/import", {
          method: "POST",
          body: JSON.stringify({ items: state.previewItems, import_type: importType })
        });
        showToast(`已写入 ${data.imported} 条资产，新建 ${data.created} 条，更新 ${data.updated} 条`);
        state.previewItems = [];
        renderPreview();
        await loadStats();
        await loadAssets();
        await loadImportRecords();
      } catch (error) {
        showToast(error.message, "error");
      }
    }

    async function extractTools() {
      try {
        const data = await request("/api/tools/extract", {
          method: "POST",
          body: JSON.stringify({ content: $("url-text").value })
        });
        state.extracted = data;
        setValue("url-domains", (data.domains || []).join("\n"));
        setValue("url-ips", (data.ips || []).join("\n"));
        setValue("url-urls", (data.urls || []).join("\n"));
        setMessage("url-message", `提取到 ${data.domains.length} 个域名、${data.ips.length} 个 IP、${data.urls.length} 个 URL`, "success");
      } catch (error) {
        setMessage("url-message", error.message, "error");
      }
    }
    function sendExtractedDomainsToBatch() {
      const domains = $("url-domains").value.trim();
      if (!domains) {
        showToast("请先提取域名", "error");
        return;
      }
      setValue("batch-subdomains", domains);
      switchView("batch");
      setMessage("batch-message", "已从 URL 提取结果带入批量录入", "success");
    }

    async function generateFofa() {
      try {
        const data = await request("/api/fofa/generate", {
          method: "POST",
          body: JSON.stringify({
            domains: $("fofa-domains").value,
            include_domain: $("fofa-domain").checked,
            include_cert: $("fofa-cert").checked
          })
        });
        setValue("fofa-result", data.query_text);
        setMessage("fofa-message", `已处理 ${data.processed_count} 个域名`, "success");
        await loadFofaHistory();
      } catch (error) {
        setMessage("fofa-message", error.message, "error");
      }
    }
    function clearFofa() {
      setValue("fofa-result", "");
      setMessage("fofa-message", "");
    }
    async function loadFofaHistory() {
      const data = await request("/api/fofa/history");
      state.fofaHistory = data.items || [];
      const body = $("fofa-history-body");
      if (!data.items.length) {
        body.innerHTML = `<tr><td colspan="4">暂无生成记录</td></tr>`;
        return;
      }
      body.innerHTML = data.items.map((item) => `
        <tr>
          <td>${escapeHtml(item.created_at)}</td>
          <td>${escapeHtml(item.processed_count)}</td>
          <td>${escapeHtml(item.query_preview)}</td>
          <td>
            <button onclick="copyFofaHistory(${item.id})">复制</button>
            <button class="danger" onclick="deleteFofa(${item.id})">删除</button>
          </td>
        </tr>
      `).join("");
    }
    async function copyFofaHistory(id) {
      const item = state.fofaHistory.find((entry) => entry.id === id);
      if (item) await copyInline(item.query_text);
    }
    async function deleteFofa(id) {
      await fetch(`/api/fofa/history/${id}`, { method: "DELETE" });
      await loadFofaHistory();
    }
    async function copyText(id) {
      await copyInline($(id).value);
    }
    async function copyInline(text) {
      try {
        await navigator.clipboard.writeText(text);
        showToast("已复制");
      } catch {
        showToast("复制失败，请手动选中文本", "error");
      }
    }

    async function loadAssets() {
      const params = new URLSearchParams({
        company: $("filter-company")?.value || "",
        root_domain: $("filter-root")?.value || "",
        status: $("filter-status")?.value || "",
        source: $("filter-source")?.value || "",
        q: $("filter-q")?.value || "",
        page_size: "100"
      });
      const data = await request(`/api/assets?${params}`);
      const body = $("assets-body");
      if (!data.items.length) {
        body.innerHTML = `<tr><td colspan="8">暂无资产</td></tr>`;
        return;
      }
      body.innerHTML = data.items.map((item) => `
        <tr>
          <td>${escapeHtml(item.company_name || item.company)}</td>
          <td>${escapeHtml(item.root_domain)}</td>
          <td>${escapeHtml(item.subdomain || "-")}</td>
          <td>${escapeHtml(item.url || "-")}</td>
          <td>${escapeHtml(item.resolved_ip || item.ip_address || "-")}</td>
          <td>${tag(item.status)}</td>
          <td>${escapeHtml(item.source)}</td>
          <td>${escapeHtml(item.updated_at)}</td>
        </tr>
      `).join("");
    }
    function exportAssets() {
      window.location.href = "/api/assets/export/csv";
    }
    async function queueResolveAll() {
      const data = await request("/api/assets/resolve", { method: "POST", body: "{}" });
      showToast(`已加入解析队列：${data.queued} 条`);
    }
    async function loadImportRecords() {
      const data = await request("/api/import-records");
      const body = $("imports-body");
      if (!data.items.length) {
        body.innerHTML = `<tr><td colspan="6">暂无导入记录</td></tr>`;
        return;
      }
      body.innerHTML = data.items.map((item) => `
        <tr>
          <td>${escapeHtml(item.created_at)}</td>
          <td>${escapeHtml(item.import_type)}</td>
          <td>${escapeHtml(item.total_count)}</td>
          <td>${escapeHtml(item.success_count)}</td>
          <td>${escapeHtml(item.failed_count)}</td>
          <td>${escapeHtml((item.raw_content || "").slice(0, 160))}</td>
        </tr>
      `).join("");
    }

    function selectedModules() {
      return Array.from(document.querySelectorAll("#module-box input:checked")).map((input) => input.value);
    }
    async function loadSystem() {
      try {
        const system = await request("/api/system");
        $("server-status").textContent = `SQLite：${system.asset_db}`;
        $("tools").innerHTML = system.tools.map((tool) => `
          <div class="tool-row"><span>${tool.name}</span><span class="${tool.exists ? "ok" : "missing"}">${tool.exists ? "正常" : "缺失"}</span></div>
        `).join("");
      } catch (error) {
        $("server-status").textContent = error.message;
      }
    }
    function renderJobs(jobs) {
      const box = $("jobs");
      if (!jobs.length) {
        box.innerHTML = `<div class="subtle">暂无扫描任务。</div>`;
        return;
      }
      box.innerHTML = jobs.map((job) => `
        <button class="job-row ${job.id === state.currentJobId ? "active" : ""}" data-job="${job.id}">
          <strong>${escapeHtml(job.target)}</strong>
          <span>${tag(job.status)} <span class="subtle">${escapeHtml(job.created_at)}</span></span>
        </button>
      `).join("");
      box.querySelectorAll("[data-job]").forEach((btn) => btn.addEventListener("click", () => selectJob(btn.dataset.job)));
    }
    async function loadJobs() {
      const data = await request("/api/jobs");
      renderJobs(data.jobs || []);
      if (!state.currentJobId && data.jobs && data.jobs[0]) await selectJob(data.jobs[0].id);
    }
    async function selectJob(jobId) {
      state.currentJobId = jobId;
      await refreshJob();
      await loadResultFile(state.currentFile);
      await loadJobs();
    }
    async function refreshJob() {
      if (!state.currentJobId) return;
      const job = await request(`/api/jobs/${state.currentJobId}`);
      $("log-view").textContent = (job.logs || []).join("\n") || "暂无日志。";
      $("log-view").scrollTop = $("log-view").scrollHeight;
      $("cancel-btn").disabled = !["queued", "running"].includes(job.status);
    }
    async function loadResultFile(name) {
      state.currentFile = name;
      document.querySelectorAll("#tabs button").forEach((btn) => btn.classList.toggle("active", btn.dataset.file === name));
      if (!state.currentJobId) return;
      try {
        const data = await request(`/api/jobs/${state.currentJobId}/file?name=${name}`);
        $("result-view").textContent = JSON.stringify(data, null, 2);
      } catch (error) {
        $("result-view").textContent = error.message;
      }
    }
    $("scan-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      setMessage("scan-message", "");
      try {
        const job = await request("/api/jobs", {
          method: "POST",
          body: JSON.stringify({
            target: $("target").value,
            deep: $("deep").checked,
            verbose: $("verbose").checked,
            modules: selectedModules()
          })
        });
        state.currentJobId = job.id;
        await loadJobs();
        await refreshJob();
      } catch (error) {
        setMessage("scan-message", error.message, "error");
      }
    });
    $("cancel-btn").addEventListener("click", async () => {
      if (!state.currentJobId) return;
      try {
        await request(`/api/jobs/${state.currentJobId}/cancel`, { method: "POST", body: "{}" });
        await refreshJob();
      } catch (error) {
        setMessage("scan-message", error.message, "error");
      }
    });
    document.querySelectorAll("#tabs button").forEach((btn) => btn.addEventListener("click", () => loadResultFile(btn.dataset.file)));
    async function tick() {
      try {
        await loadStats();
        await loadJobs();
        await refreshJob();
        if (state.currentJobId) await loadResultFile(state.currentFile);
        if (document.querySelector("#view-assets.active")) await loadAssets();
      } catch (error) {
        setMessage("scan-message", error.message, "error");
      }
    }
    loadSystem();
    loadStats();
    loadAssets();
    loadImportRecords();
    loadFofaHistory();
    loadJobs();
    switchView("single");
    setInterval(tick, 2500);
  </script>
</body>
</html>
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the ReconMaster local web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=8765, help="Port to bind")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    RESULTS_DIR.mkdir(exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), ReconRequestHandler)
    print(f"ReconMaster web UI listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
