"""Anthropic API gateway: the scan network's only way out.

Runs in its own small container (stdlib only; it is bind-mounted, not installed).
It listens on the internal scan network, accepts plain HTTP from the agent, and:

* allows only the Messages API (``POST /v1/messages``, ``POST /v1/messages/count_tokens``)
  and model lookups (``GET /v1/models``...); everything else gets 403;
* forwards to one fixed upstream, ``https://api.anthropic.com``, with certificate
  verification; absolute-form proxy requests (``GET http://other.host/``) are refused,
  so it cannot be used as a general proxy;
* drops any credential the client sent and injects the real one from its own
  environment, so it never enters the scan container: an API key (``x-api-key``) or,
  in subscription mode, the ``claude setup-token`` OAuth token (``Authorization: Bearer``
  plus the OAuth beta flag);
* records 429 responses (``limit_hit_at`` in the stats file): with a subscription that is
  the plan's usage limit, and the host stops starting new components;
* records refused paths, so a first run shows anything else Claude Code tried to reach;
* stops forwarding after ``--max-requests`` (a run-wide backstop on spend);
* streams responses (server-sent events) through unbuffered.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM_HOST = "api.anthropic.com"
ALLOWED = {
    ("POST", "/v1/messages"),
    ("POST", "/v1/messages/count_tokens"),
}
ALLOWED_GET_PREFIX = "/v1/models"
OAUTH_BETA = "oauth-2025-04-20"
CREDENTIAL_ENV = {"api_key": "ANTHROPIC_API_KEY", "subscription": "CLAUDE_CODE_OAUTH_TOKEN"}
MAX_BODY = 32 * 1024 * 1024
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "transfer-encoding", "upgrade", "host", "content-length",
}
DROP_REQUEST = HOP_BY_HOP | {"x-api-key", "authorization", "cookie", "proxy-connection", "forwarded", "x-forwarded-for"}


def is_allowed(method: str, target: str) -> bool:
    """Request-target check. Only origin-form paths on the allow-list pass."""
    if not target.startswith("/") or target.startswith("//"):
        return False
    path = target.split("?", 1)[0]
    if ".." in path or "%" in path or "\\" in path:
        return False
    if (method, path) in ALLOWED:
        return True
    if method == "GET" and (path == ALLOWED_GET_PREFIX or path.startswith(ALLOWED_GET_PREFIX + "/")):
        return True
    return False


def upstream_headers(incoming: list[tuple[str, str]], credential: str, auth: str = "api_key") -> dict[str, str]:
    out: dict[str, str] = {}
    beta: list[str] = []
    for k, v in incoming:
        lk = k.lower()
        if lk in DROP_REQUEST:
            continue
        if lk == "anthropic-beta":
            beta += [b.strip() for b in v.split(",") if b.strip()]
            continue
        out[k] = v
    if auth == "subscription":
        out["authorization"] = f"Bearer {credential}"
        if OAUTH_BETA not in beta:
            beta.append(OAUTH_BETA)
    else:
        out["x-api-key"] = credential
    if beta:
        out["anthropic-beta"] = ",".join(dict.fromkeys(beta))
    return out


class Stats:
    def __init__(self, path: str | None, max_requests: int, auth: str = "api_key"):
        self.path = path
        self.max_requests = max_requests
        self.lock = threading.Lock()
        self.data = {
            "auth": auth, "forwarded": 0, "denied": 0, "over_limit": 0, "by_status": {},
            "denied_paths": {}, "rate_limited": 0, "limit_hit_at": None, "started": time.time(),
        }

    def take_slot(self) -> bool:
        with self.lock:
            if self.data["forwarded"] >= self.max_requests:
                self.data["over_limit"] += 1
                self._flush()
                return False
            self.data["forwarded"] += 1
            return True

    def record(self, key: str, status: int | None = None, path: str | None = None) -> None:
        with self.lock:
            if key == "denied":
                self.data["denied"] += 1
                if path and (path in self.data["denied_paths"] or len(self.data["denied_paths"]) < 50):
                    self.data["denied_paths"][path] = self.data["denied_paths"].get(path, 0) + 1
            if status == 429 and key == "forwarded":
                self.data["rate_limited"] += 1
                if self.data["limit_hit_at"] is None:
                    self.data["limit_hit_at"] = time.time()
            if status is not None:
                s = str(status)
                self.data["by_status"][s] = self.data["by_status"].get(s, 0) + 1
            self._flush()

    def _flush(self) -> None:
        if not self.path:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh)
        os.replace(tmp, self.path)


def make_handler(
    credential: str, stats: Stats, upstream_host: str = UPSTREAM_HOST, ssl_ctx: ssl.SSLContext | None = None, auth: str = "api_key"
):
    ctx = ssl_ctx or ssl.create_default_context()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "threadscan-gw"
        sys_version = ""

        def log_message(self, fmt, *args):  # one line per request, no bodies, no headers
            sys.stdout.write("%s %s\n" % (time.strftime("%H:%M:%S"), fmt % args))

        def _deny(self, code: int, msg: str) -> None:
            stats.record("denied", code, f"{self.command} {self.path.split('?')[0][:120]}")
            body = json.dumps({"type": "error", "error": {"type": "threadscan_gateway", "message": msg}}).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _proxy(self) -> None:
            method = self.command
            if not is_allowed(method, self.path):
                return self._deny(403, f"{method} {self.path.split('?')[0]} is not on the gateway allow-list")
            if self.headers.get("transfer-encoding"):
                return self._deny(411, "chunked request bodies are not accepted")
            try:
                length = int(self.headers.get("content-length") or 0)
            except ValueError:
                return self._deny(400, "bad content-length")
            if length < 0 or length > MAX_BODY:
                return self._deny(413, "request body too large")
            body = self.rfile.read(length) if length else None
            if not stats.take_slot():
                return self._deny(429, "run-wide request limit reached (scan.max_requests)")
            conn = http.client.HTTPSConnection(upstream_host, 443, context=ctx, timeout=900)
            try:
                conn.request(method, self.path, body=body, headers=upstream_headers(list(self.headers.items()), credential, auth))
                resp = conn.getresponse()
                self.send_response(resp.status)
                clen = resp.getheader("content-length")
                for k, v in resp.getheaders():
                    if k.lower() not in HOP_BY_HOP:
                        self.send_header(k, v)
                chunked = clen is None
                if chunked:
                    self.send_header("transfer-encoding", "chunked")
                else:
                    self.send_header("content-length", clen)
                self.end_headers()
                while True:
                    chunk = resp.read1(65536)
                    if not chunk:
                        break
                    if chunked:
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    else:
                        self.wfile.write(chunk)
                    self.wfile.flush()
                if chunked:
                    self.wfile.write(b"0\r\n\r\n")
                stats.record("forwarded", resp.status)
            except (OSError, http.client.HTTPException) as exc:
                stats.record("error", 502)
                try:
                    self._deny(502, f"upstream error: {type(exc).__name__}")
                except OSError:
                    pass
            finally:
                conn.close()

        do_POST = _proxy
        do_GET = _proxy

        def _refuse(self):
            self._deny(405, "method not allowed")

        do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_CONNECT = _refuse

    return Handler


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="threadscan Anthropic API gateway")
    ap.add_argument("--listen", default="0.0.0.0:8080")
    ap.add_argument("--stats", default=None)
    ap.add_argument("--max-requests", type=int, default=2000)
    ap.add_argument("--auth", choices=sorted(CREDENTIAL_ENV), default="api_key")
    args = ap.parse_args(argv)
    env_name = CREDENTIAL_ENV[args.auth]
    credential = os.environ.pop(env_name, "")
    if not credential:
        print(f"{env_name} is not set in the gateway's environment", file=sys.stderr)
        return 2
    host, _, port = args.listen.rpartition(":")
    stats = Stats(args.stats, args.max_requests, args.auth)
    stats.record("start")
    server = ThreadingHTTPServer((host or "0.0.0.0", int(port)), make_handler(credential, stats, auth=args.auth))
    server.daemon_threads = True
    print(f"threadscan gateway listening on {args.listen}, upstream https://{UPSTREAM_HOST}, auth {args.auth}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
