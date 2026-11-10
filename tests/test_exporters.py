"""Exports: SARIF structure and suppressions, CSV formula escaping, HTML escaping, download endpoint."""

import csv
import io
import json
import re
import threading
from http.server import ThreadingHTTPServer

import pytest
from helpers import ScriptedExecutor, candidate, clean, proof

from threadscan import dashboard
from threadscan.exporters import FORMATS, RunData, export, to_csv, to_html, to_sarif, write_exports
from threadscan.report import build_summary, finding_dict, write_outputs
from threadscan.status import StatusTracker, write_json
from threadscan.verify import Policy, Verifier


def make_run(tmp_path, **over):
    runs = tmp_path / "runs"
    run = runs / "20260101-000000-demo"
    run.mkdir(parents=True)
    c = candidate(**over)
    v = Verifier(ScriptedExecutor(lambda cc, m, n: proof(n) if m == "unpatched" else clean()), Policy()).verify_one(c)
    f = finding_dict(c, v)
    meta = {"run_id": run.name, "project": "demo", "mode": "full", "base": None, "commit": "abc123def456", "model": "claude-opus-5-5", "dry_run": False, "auth": "subscription"}
    summary = build_summary(1, [{"name": "auth", "state": "done", "cost_usd": 1.5, "input_tokens": 10, "output_tokens": 2}], 2, [f], [], 0, 0, {}, None)
    write_outputs(run, meta, [f], [], summary, {"previous_run": None, "new": [f["id"]]})
    StatusTracker(run, run.name, "demo", "full", None, False).phase("done")
    return runs, run, f


def test_sarif_shape_and_triage_suppression(tmp_path):
    runs, run, f = make_run(tmp_path, cwe="CWE-918", severity="high")
    sarif = to_sarif(RunData(run, {f["id"]: {"status": "risk_accepted", "note": "WAF rule in place", "assignee": "nino"}}))
    assert sarif["version"] == "2.1.0" and len(sarif["runs"]) == 1
    r = sarif["runs"][0]
    assert r["tool"]["driver"]["name"] == "Threadscan"
    rule, res = r["tool"]["driver"]["rules"][0], r["results"][0]
    assert rule["id"] == res["ruleId"] == f["id"] and res["ruleIndex"] == 0
    assert "external/cwe/cwe-918" in rule["properties"]["tags"] and "owasp/a10" in rule["properties"]["tags"]
    assert rule["properties"]["security-severity"] == "8.0" and res["level"] == "error"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == f["file"] and loc["region"]["startLine"] == f["line"]
    assert res["partialFingerprints"]["threadscanId/v1"] == f["id"]
    assert res["suppressions"] == [{"kind": "external", "status": "accepted", "justification": "WAF rule in place"}]
    assert res["properties"]["assignee"] == "nino" and res["properties"]["patchCheck"] == "fixed"
    open_res = to_sarif(RunData(run, {}))["runs"][0]["results"][0]
    assert "suppressions" not in open_res and open_res["properties"]["triageStatus"] == "open"


@pytest.mark.parametrize("sev,level", [("critical", "error"), ("medium", "warning"), ("low", "note")])
def test_sarif_levels(tmp_path, sev, level):
    _, run, _ = make_run(tmp_path, severity=sev)
    assert to_sarif(RunData(run))["runs"][0]["results"][0]["level"] == level


def test_csv_escapes_formulas_and_round_trips(tmp_path):
    _, run, f = make_run(tmp_path, title="=HYPERLINK(\"http://evil\") \"quoted\", comma")
    text = to_csv(RunData(run, {f["id"]: {"status": "in_progress", "assignee": "@nino"}}))
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows[0]["title"].startswith("'=HYPERLINK") and rows[0]["assignee"] == "'@nino"
    assert rows[0]["status"] == "in_progress" and rows[0]["owasp"].startswith("A07")


def test_html_is_self_contained_escaped_and_redacted(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-NEVERSHOWNEVERSHOW")
    _, run, f = make_run(tmp_path, title="<script>alert(1)</script> XSS in title",
                         description="key sk-ant-api03-NEVERSHOWNEVERSHOW leaked")
    page = to_html(RunData(run))
    assert "<script>alert" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "NEVERSHOW" not in page
    assert "<script" not in page.lower()  # no script at all
    assert re.findall(r"(?:src|href)=['\"]https?://", page) == []  # nothing loaded from elsewhere
    assert "data:font/woff2;base64," in page and f["id"] in page and "Proposed patch" in page
    assert "Usage at API prices (not billed)" in page


def test_every_format_and_auto_written_files(tmp_path):
    _, run, _ = make_run(tmp_path)
    for fmt in FORMATS:
        name, ctype, content = export(run, fmt)
        assert content and name == FORMATS[fmt][0]
    json.loads(export(run, "sarif")[2]) and json.loads(export(run, "json")[2])
    written = write_exports(run)
    assert {p.name for p in written} == {"findings.sarif", "report.html", "verified-fixes.patch"}
    with pytest.raises(ValueError):
        export(run, "pdf")


def _get(port, path):
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
    r = c.getresponse()
    body = r.read()
    headers = dict((k.lower(), v) for k, v in r.getheaders())
    c.close()
    return r.status, headers, body


def test_export_endpoint_is_an_attachment_with_current_triage(tmp_path):
    runs, run, f = make_run(tmp_path)
    write_json(runs / "triage.json", {f["id"]: {"status": "false_positive", "note": "test fixture", "assignee": "", "history": []}})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.make_handler(runs, 0))
    port = srv.server_address[1]
    srv.RequestHandlerClass = dashboard.make_handler(runs, port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        status, headers, body = _get(port, f"/api/runs/{run.name}/export/sarif")
        assert status == 200 and headers["content-disposition"].startswith("attachment;")
        assert "sandbox" in headers["content-security-policy"]
        res = json.loads(body)["runs"][0]["results"][0]
        assert res["suppressions"][0]["justification"] == "test fixture"
        status, headers, body = _get(port, f"/api/runs/{run.name}/export/html")
        assert status == 200 and headers["content-type"].startswith("text/html") and b"attachment" in headers["content-disposition"].encode()
        assert _get(port, f"/api/runs/{run.name}/export/exe")[0] == 404
        assert _get(port, "/api/runs/..%2F..%2Fx/export/csv")[0] == 404
    finally:
        srv.shutdown()


def test_severity_override_flows_into_exports(tmp_path):
    _, run, f = make_run(tmp_path, severity="critical")
    data = RunData(run, {f["id"]: {"status": "open", "severity": "low"}})
    assert data.findings[0]["severity"] == "low" and data.findings[0]["original_severity"] == "critical"
    res = to_sarif(data)["runs"][0]["results"][0]
    assert res["level"] == "note" and res["properties"]["originalSeverity"] == "critical"
    assert "adjusted from critical" in to_html(data)
    assert list(csv.DictReader(io.StringIO(to_csv(data))))[0]["severity"] == "low"
    plain = RunData(run, {})
    assert plain.findings[0]["severity"] == "critical" and "original_severity" not in plain.findings[0]


def test_patch_bundle_applies_with_git_and_skips_unverified(tmp_path):
    import subprocess
    _, run, f = make_run(tmp_path)
    bundle = export(run, "patches")[2]
    assert f["id"] in bundle and bundle.count("+++ b/app/Login.java") == 1
    repo = tmp_path / "target"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "Login.java").write_text("class Login { boolean check() { return true; } }\n")
    (tmp_path / "b.patch").write_text(bundle)
    check = subprocess.run(["git", "apply", "--check", str(tmp_path / "b.patch")], cwd=repo, capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    assert f["id"] not in export(run, "patches", {f["id"]: {"status": "false_positive"}})[2]
    # a patch the gate did not verify is never bundled
    findings = json.loads((run / "findings.json").read_text())
    findings[0]["verification"]["patch_check"] = "not_fixed"
    (run / "findings.json").write_text(json.dumps(findings))
    assert "+++ b/" not in export(run, "patches")[2]
