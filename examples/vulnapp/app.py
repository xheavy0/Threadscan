"""Tiny intentionally vulnerable web app: the target for Threadscan's end-to-end test.

Never deploy this. It exists so a real scan can exercise the agent, the reproducer
contract and the verification gate in a couple of minutes, without a large build.
Standard library only, so it builds and runs offline.
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.join(BASE, "public")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "local-admin-token")
USERS = [
    {"id": 1, "email": "ana@example.test", "role": "admin"},
    {"id": 2, "email": "levan@example.test", "role": "viewer"},
]


def read_public_file(name: str) -> bytes:
    path = os.path.join(PUBLIC, name)
    with open(path, "rb") as fh:
        return fh.read()


def is_admin(headers) -> bool:
    return headers.get("X-Admin-Token") == ADMIN_TOKEN


class Handler(BaseHTTPRequestHandler):
    server_version = "vulnapp"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if url.path == "/health":
            return self._json(200, {"ok": True})
        if url.path == "/files":
            name = (query.get("name") or [""])[0]
            try:
                data = read_public_file(name)
            except OSError:
                return self._json(404, {"error": "not found"})
            return self._send(200, data, "application/octet-stream")
        if url.path == "/admin/users":
            if not is_admin(self.headers):
                return self._json(403, {"error": "forbidden"})
            return self._json(200, USERS)
        if url.path == "/admin/export":
            return self._json(200, {"users": USERS})
        return self._json(404, {"error": "not found"})


def make_server(port: int, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), Handler)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    make_server(args.port).serve_forever()
