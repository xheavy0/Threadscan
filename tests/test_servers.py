"""Live HTTP tests for the gateway's refusal paths and the dashboard (no network beyond loopback)."""

import http.client
import json
import shutil
import subprocess
import threading
from http.server import ThreadingHTTPServer

import pytest

from threadscan import dashboard
from threadscan.gateway import Stats, make_handler
from threadscan.status import StatusTracker, write_json


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
    write_json(run / "findings.json", [{"id": "TS-1", "title": "t", "severity": "high"}])
    (run / "report.md").write_text("# report\n")
    (tmp_path / "secret.txt").write_text("outside runs")
    return d


def test_dashboard_api(runs):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.make_handler(runs, 0))
    port = srv.server_address[1]
    srv.RequestHandlerClass = dashboard.make_handler(runs, port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, body = _req(port, "GET", "/")
        assert status == 200 and b"threadscan" in body
        lst = json.loads(_req(port, "GET", "/api/runs")[1])
        assert lst[0]["run_id"] == "20260101-000000-demo" and lst[0]["phase"] == "scanning"
        st = json.loads(_req(port, "GET", "/api/runs/20260101-000000-demo")[1])
        assert st["components"][0]["progress"]["tool_calls"] == 9  # live progress merged in
        f = json.loads(_req(port, "GET", "/api/runs/20260101-000000-demo/findings")[1])
        assert f[0]["id"] == "TS-1"
        assert _req(port, "GET", "/api/runs/20260101-000000-demo/report")[1] == b"# report\n"
        # traversal and unknown runs
        assert _req(port, "GET", "/api/runs/..%2Fsecret.txt")[0] == 404
        assert _req(port, "GET", "/api/runs/nope")[0] == 404
        assert _req(port, "GET", "/../secret.txt")[0] == 404
        # DNS-rebinding guard
        assert _req(port, "GET", "/api/runs", host="evil.example")[0] == 403
        # self-hosted fonts and the mark, by exact name only
        for path in dashboard.STATIC_FILES:
            status, body = _req(port, "GET", path)
            assert status == 200 and len(body) > 500, path
        assert _req(port, "GET", "/static/fonts/../../dashboard.py")[0] == 404
        assert _req(port, "GET", "/static/fonts/LICENSE-Inter.txt")[0] == 404
    finally:
        srv.shutdown()


def test_dashboard_never_references_a_font_cdn():
    # the SVG namespace is an identifier, not a request
    html = dashboard.HTML_PATH.read_text(encoding="utf-8").replace("http://www.w3.org/2000/svg", "")
    for host in ("fonts.googleapis", "fonts.gstatic", "cdn.", "unpkg", "jsdelivr", "http://", "https://"):
        assert host not in html, host
    # the design system's own assets, all served from this origin
    for asset in ("/static/fonts/dm-sans.woff2", "/static/fonts/poppins-500.woff2", "/static/threadscan.svg"):
        assert asset in html and asset in dashboard.STATIC_FILES, asset


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


def test_run_status_passes_usage_limit_fields(runs):
    run = runs / "20260101-000000-demo"
    write_json(run / "summary.json", {"verified": 0, "components_skipped": ["a", "b"], "limit_reached": True,
                                      "resume_command": 'threadscan scan "t" --full --only "a" --only "b"'})
    st = dashboard.run_status(run)
    assert st["summary"]["components_skipped"] == ["a", "b"]
    assert st["summary"]["limit_reached"] is True and "--only" in st["summary"]["resume_command"]


def _post(port, path, body, headers):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("POST", path, body=body, headers={"Host": f"127.0.0.1:{port}", **headers})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


def test_triage_writes_need_same_origin_json_and_the_custom_header(runs):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.make_handler(runs, 0))
    port = srv.server_address[1]
    srv.RequestHandlerClass = dashboard.make_handler(runs, port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ok_headers = {"Content-Type": "application/json", "X-Threadscan-Request": "1", "Origin": f"http://127.0.0.1:{port}"}
    body = json.dumps({"status": "in_progress", "assignee": "nino"})
    try:
        # a cross-site form post or fetch cannot set the custom header or a foreign Origin
        assert _post(port, "/api/triage/TS-0123456789", body, {"Content-Type": "application/json"})[0] == 403
        assert _post(port, "/api/triage/TS-0123456789", body, {**ok_headers, "Origin": "https://evil.example"})[0] == 403
        assert _post(port, "/api/triage/TS-0123456789", body, {**ok_headers, "Content-Type": "text/plain"})[0] == 415
        assert _post(port, "/api/triage/../../x", body, ok_headers)[0] in (400, 404)
        assert _post(port, "/api/triage/TS-0123456789", json.dumps({"status": "done"}), ok_headers)[0] == 400
        status, data = _post(port, "/api/triage/TS-0123456789", body, ok_headers)
        assert status == 200 and json.loads(data)["status"] == "in_progress"
        got = json.loads(_req(port, "GET", "/api/triage")[1])
        assert got["issues"]["TS-0123456789"]["assignee"] == "nino"
        assert (runs / "triage.json").is_file()
    finally:
        srv.shutdown()
