"""Local dashboard: scan progress, verified issues, trends, compliance and triage.

``threadscan dashboard`` serves ``dashboard.html`` and a small JSON API over the runs
directory. It binds to 127.0.0.1 only and checks the Host header (so a web page cannot
reach it through DNS rebinding). It reads only files it names inside ``runs/<run-id>/``.
Its one write is triage state (``runs/triage.json``), accepted only as a JSON POST that
carries the ``X-Threadscan-Request`` header from the dashboard's own origin: a page on
another site cannot send that header without a CORS preflight, which this server never
answers.
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from threadscan import history
from threadscan.exporters import FORMATS, export
from threadscan.owasp import categories, categorize
from threadscan.redact import redact_obj
from threadscan.triage import STATUSES, TriageError, TriageStore

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
HTML_PATH = Path(__file__).resolve().parent / "dashboard.html"
STATIC_DIR = Path(__file__).resolve().parent / "static"
# The only static files served, by exact name: self-hosted fonts (no font CDN) and the mark.
STATIC_FILES = {
    "/static/threadscan.svg": ("threadscan.svg", "image/svg+xml"),
    "/favicon.svg": ("threadscan.svg", "image/svg+xml"),
    # Rubik and Fira Code: the fonts Wiz's product UI uses (both SIL OFL).
    "/static/fonts/rubik.woff2": ("fonts/rubik-latin-wght-normal.woff2", "font/woff2"),
    "/static/fonts/fira-code.woff2": ("fonts/fira-code-latin-wght-normal.woff2", "font/woff2"),
}
CSP = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; font-src 'self'; "
    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
CSRF_HEADER = "x-threadscan-request"
MAX_POST = 16 * 1024


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
        out.append({k: st.get(k) for k in ("run_id", "project", "mode", "base", "dry_run", "phase", "started", "updated", "finished", "counts", "message", "auth")})
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
        st["summary"] = {k: summary.get(k) for k in (
            "components_scanned", "components_failed", "candidates", "verified", "dropped", "dropped_by_reason",
            "by_severity", "tokens", "cost_usd", "seeds", "components_skipped", "limit_reached", "resume_command", "lifecycle",
        )}
    return st


def run_findings(run_dir: Path) -> list:
    """Findings with their OWASP Top 10:2021 category added (older runs lack the field)."""
    out = []
    for f in _load(run_dir / "findings.json") or []:
        if "owasp" not in f:
            f["owasp"] = categorize(f.get("cwe"))
        out.append(f)
    return out


def run_lifecycle(run_dir: Path) -> dict:
    return _load(run_dir / "lifecycle.json") or {}


def run_seeds(run_dir: Path) -> dict:
    return _load(run_dir / "seeds.json") or {"seeds": [], "unassigned": 0}


def run_plan(run_dir: Path) -> dict:
    """The run's policy snapshot and planned docker commands. The commands hold local paths
    (this is a local page) and never secrets: credentials are passed to docker by name."""
    plan = _load(run_dir / "plan.json") or {}
    return {k: plan.get(k) for k in ("meta", "policy", "components", "seeds", "commands")}


def make_handler(runs_dir: Path, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}
    triage = TriageStore(runs_dir / "triage.json")

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

        def _download(self, filename: str, ctype: str, body: bytes) -> None:
            """Always an attachment: the HTML report is saved, never rendered on this origin."""
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
            self.send_response(200)
            self.send_header("content-type", ctype + "; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.send_header("content-disposition", f'attachment; filename="{safe}"')
            self.send_header("cache-control", "no-store")
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("content-security-policy", "default-src 'none'; sandbox")
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
            if path == "/api/triage":
                return self._json({"statuses": STATUSES, "issues": triage.load()})
            if path == "/api/rechecks":
                from threadscan.recheck import list_rechecks

                return self._json(list_rechecks(runs_dir))
            if path == "/api/owasp":
                return self._json(categories())
            m = re.match(r"^/api/projects/([^/]+)/history$", path)
            if m:
                if not PROJECT_RE.match(m.group(1)):
                    return self._json({"error": "unknown project"}, 404)
                return self._json(history.project_history(runs_dir, m.group(1)))
            m = re.match(r"^/api/runs/([^/]+)/export/([a-z]+)$", path)
            if m:
                d = run_dir_for(runs_dir, m.group(1))
                if d is None or m.group(2) not in FORMATS:
                    return self._json({"error": "unknown run or format"}, 404)
                name, ctype, content = export(d, m.group(2), triage.load())
                return self._download(f"threadscan-{d.name}-{name}", ctype, content.encode("utf-8"))
            m = re.match(r"^/api/runs/([^/]+)(?:/(findings|report|lifecycle|seeds|plan))?$", path)
            if m:
                d = run_dir_for(runs_dir, m.group(1))
                if d is None:
                    return self._json({"error": "unknown run"}, 404)
                if m.group(2) == "findings":
                    return self._json(run_findings(d))
                if m.group(2) == "lifecycle":
                    return self._json(run_lifecycle(d))
                if m.group(2) == "seeds":
                    return self._json(run_seeds(d))
                if m.group(2) == "plan":
                    return self._json(run_plan(d))
                if m.group(2) == "report":
                    rp = d / "report.md"
                    text = rp.read_text(encoding="utf-8") if rp.is_file() else ""
                    return self._send(200, text.encode("utf-8"), "text/plain; charset=utf-8")
                return self._json(run_status(d))
            return self._send(404, b"not found", "text/plain")

        def do_POST(self):
            if self.headers.get("host") not in allowed_hosts:
                return self._send(403, b"forbidden host", "text/plain")
            origin = self.headers.get("origin")
            if origin is not None and origin not in allowed_origins:
                return self._json({"error": "cross-origin request refused"}, 403)
            if self.headers.get(CSRF_HEADER) != "1":
                return self._json({"error": "missing request header"}, 403)
            if not (self.headers.get("content-type") or "").startswith("application/json"):
                return self._json({"error": "JSON only"}, 415)
            try:
                length = int(self.headers.get("content-length") or 0)
            except ValueError:
                length = -1
            if length < 0 or length > MAX_POST:
                return self._json({"error": "body too large"}, 413)
            path = unquote(urlparse(self.path).path)
            m = re.match(r"^/api/triage/([^/]+)$", path)
            if not m:
                return self._send(404, b"not found", "text/plain")
            try:
                body = json.loads(self.rfile.read(length) or b"null")
                entry = triage.update(m.group(1), body)
            except (ValueError, TriageError) as exc:
                return self._json({"error": str(exc)}, 400)
            return self._json(entry)

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
