"""Live HTTP tests for the gateway's refusal paths and the dashboard (no network beyond loopback)."""

import http.client
import json
import shutil
import subprocess
import threading
from http.server import ThreadingHTTPServer

import pytest

from vulnscan import dashboard
from vulnscan.gateway import Stats, make_handler
from vulnscan.status import StatusTracker, write_json


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _req(port, method, path, host=None, body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if body is not None:
        headers["content-type"] = "application/json"
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


def test_gateway_refuses_without_contacting_upstream(tmp_path):
    stats = Stats(str(tmp_path / "stats.json"), max_requests=0)
    srv = _serve(make_handler("real-key", stats, upstream_host="upstream.invalid"))
    try:
        port = srv.server_address[1]
        assert _req(port, "POST", "/v1/files", body=b"{}")[0] == 403
        assert _req(port, "GET", "http://evil.example/")[0] == 403
        assert _req(port, "DELETE", "/v1/messages")[0] == 405
        status, body = _req(port, "POST", "/v1/messages", body=b"{}")
        assert status == 429 and b"request limit" in body  # limit reached before any upstream call
        s = json.loads((tmp_path / "stats.json").read_text())
        assert s["forwarded"] == 0 and s["over_limit"] == 1 and s["denied"] >= 3
    finally:
        srv.shutdown()


@pytest.fixture
def runs(tmp_path):
    d = tmp_path / "runs"
    run = d / "20260101-000000-demo"
    run.mkdir(parents=True)
    st = StatusTracker(run, run.name, "demo", "diff", "HEAD~1", False)
    st.set_components([{"name": "auth", "slug": "auth-1", "kind": "explicit", "file_count": 3}])
    st.component("auth", state="running")
    st.phase("scanning")
    write_json(run / "components" / "auth-1" / "out" / "progress.json", {"turns": 4, "tool_calls": 9, "last": "Grep: password", "state": "running"})
    write_json(run / "findings.json", [{"id": "VS-1", "title": "t", "severity": "high"}])
    (run / "report.md").write_text("# report\n")
    (tmp_path / "secret.txt").write_text("outside runs")
    return d


def test_dashboard_api(runs):
    port_holder = {}
    srv = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.make_handler(runs, 0))
    port = srv.server_address[1]
    srv.RequestHandlerClass = dashboard.make_handler(runs, port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body = _req(port, "GET", "/")
        assert status == 200 and b"vulnscan" in body
        lst = json.loads(_req(port, "GET", "/api/runs")[1])
        assert lst[0]["run_id"] == "20260101-000000-demo" and lst[0]["phase"] == "scanning"
        st = json.loads(_req(port, "GET", "/api/runs/20260101-000000-demo")[1])
        assert st["components"][0]["progress"]["tool_calls"] == 9  # live progress merged in
        f = json.loads(_req(port, "GET", "/api/runs/20260101-000000-demo/findings")[1])
        assert f[0]["id"] == "VS-1"
        assert _req(port, "GET", "/api/runs/20260101-000000-demo/report")[1] == b"# report\n"
        # traversal and unknown runs
        assert _req(port, "GET", "/api/runs/..%2Fsecret.txt")[0] == 404
        assert _req(port, "GET", "/api/runs/nope")[0] == 404
        assert _req(port, "GET", "/../secret.txt")[0] == 404
        # DNS-rebinding guard
        assert _req(port, "GET", "/api/runs", host="evil.example")[0] == 403
    finally:
        srv.shutdown()


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_dashboard_script_is_valid_javascript(tmp_path):
    html = dashboard.HTML_PATH.read_text(encoding="utf-8")
    js = tmp_path / "dash.js"
    js.write_text(html[html.index("<script>") + 8 : html.index("</script>")], encoding="utf-8")
    proc = subprocess.run(["node", "--check", str(js)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_dashboard_run_dir_validation(runs):
    assert dashboard.run_dir_for(runs, "20260101-000000-demo") is not None
    for bad in ["..", "../x", "a/b", "", ".hidden", "x" * 200]:
        assert dashboard.run_dir_for(runs, bad) is None
