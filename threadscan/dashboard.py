"""Local, read-only dashboard: scan progress and verified findings.

``threadscan dashboard`` serves ``dashboard.html`` and a small JSON API over the runs
directory. It binds to 127.0.0.1 only, checks the Host header (so a web page cannot
reach it through DNS rebinding), serves nothing but files inside ``runs/<run-id>/``
that it names itself, and never writes.
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from threadscan.redact import redact_obj

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$")
HTML_PATH = Path(__file__).resolve().parent / "dashboard.html"
STATIC_DIR = Path(__file__).resolve().parent / "static"
# The only static files served, by exact name: self-hosted fonts (no font CDN) and the mark.
STATIC_FILES = {
    "/static/threadscan.svg": ("threadscan.svg", "image/svg+xml"),
    "/favicon.svg": ("threadscan.svg", "image/svg+xml"),
    "/static/fonts/inter.woff2": ("fonts/inter-latin-wght-normal.woff2", "font/woff2"),
    "/static/fonts/jetbrains-mono-400.woff2": ("fonts/jetbrains-mono-latin-400-normal.woff2", "font/woff2"),
    "/static/fonts/jetbrains-mono-500.woff2": ("fonts/jetbrains-mono-latin-500-normal.woff2", "font/woff2"),
}
CSP = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; font-src 'self'; "
    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_runs(runs_dir: Path) -> list[dict]:
    out = []
    if not runs_dir.is_dir():
        return out
    for d in runs_dir.iterdir():
        st = _load(d / "status.json") if d.is_dir() and RUN_ID_RE.match(d.name) else None
        if not st:
            continue
        out.append({k: st.get(k) for k in ("run_id", "project", "mode", "base", "dry_run", "phase", "started", "updated", "finished", "counts", "message")})
    out.sort(key=lambda r: r.get("started") or 0, reverse=True)
    return out


def run_dir_for(runs_dir: Path, run_id: str) -> Path | None:
    if not RUN_ID_RE.match(run_id):
        return None
    d = (runs_dir / run_id).resolve()
    if d.parent != runs_dir.resolve() or not (d / "status.json").is_file():
        return None
    return d


def run_status(run_dir: Path) -> dict:
    st = _load(run_dir / "status.json") or {}
    for c in st.get("components", []):
        if c.get("state") == "running" and c.get("slug"):
            prog = _load(run_dir / "components" / c["slug"] / "out" / "progress.json")
            if prog:
                c["progress"] = {k: prog.get(k) for k in ("turns", "tool_calls", "last", "updated", "state")}
    summary = _load(run_dir / "summary.json")
    if summary:
        st["summary"] = {k: summary.get(k) for k in ("components_scanned", "components_failed", "candidates", "verified", "dropped", "dropped_by_reason", "by_severity", "tokens", "cost_usd", "seeds", "components_skipped", "limit_reached", "resume_command")}
    return st


def run_findings(run_dir: Path) -> list:
    return _load(run_dir / "findings.json") or []


def make_handler(runs_dir: Path, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "threadscan-dashboard"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def _send(self, code: int, body: bytes, ctype: str, cache: str = "no-store") -> None:
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", cache)
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("referrer-policy", "no-referrer")
            self.send_header("content-security-policy", CSP)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(redact_obj(obj), default=str).encode("utf-8"), "application/json; charset=utf-8")

        def do_GET(self):
            if self.headers.get("host") not in allowed_hosts:
                return self._send(403, b"forbidden host", "text/plain")
            path = unquote(urlparse(self.path).path)
            if path in ("/", "/index.html"):
                return self._send(200, HTML_PATH.read_bytes(), "text/html; charset=utf-8")
            if path in STATIC_FILES:
                name, ctype = STATIC_FILES[path]
                return self._send(200, (STATIC_DIR / name).read_bytes(), ctype, "public, max-age=86400")
            if path == "/api/runs":
                return self._json(list_runs(runs_dir))
            m = re.match(r"^/api/runs/([^/]+)(?:/(findings|report))?$", path)
            if m:
                d = run_dir_for(runs_dir, m.group(1))
                if d is None:
                    return self._json({"error": "unknown run"}, 404)
                if m.group(2) == "findings":
                    return self._json(run_findings(d))
                if m.group(2) == "report":
                    rp = d / "report.md"
                    text = rp.read_text(encoding="utf-8") if rp.is_file() else ""
                    return self._send(200, text.encode("utf-8"), "text/plain; charset=utf-8")
                return self._json(run_status(d))
            return self._send(404, b"not found", "text/plain")

    return Handler


def serve(runs_dir: Path, port: int = 8765) -> None:
    runs_dir = runs_dir.resolve()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(runs_dir, port))
    server.daemon_threads = True
    print(f"threadscan dashboard: http://127.0.0.1:{port}/  (runs: {runs_dir}; Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
