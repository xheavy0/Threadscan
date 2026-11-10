import json

import pytest
from helpers import ScriptedExecutor, candidate, clean, proof

from vulnscan.report import Dropped, build_summary, finding_dict, render_markdown, write_outputs
from vulnscan.verify import Policy, Verifier

META = {"run_id": "r1", "project": "demo", "mode": "diff", "base": "HEAD~1", "commit": "abc123", "model": "claude-opus-5-5", "dry_run": False}


def verified_finding(**over):
    c = candidate(**over)
    v = Verifier(ScriptedExecutor(lambda cc, m, n: proof(n) if m == "unpatched" else clean()), Policy()).verify_one(c)
    return finding_dict(c, v)


def comp_result(name="auth", state="done", cost=1.25, tin=1000, tout=200):
    return {"name": name, "state": state, "error": None, "cost_usd": cost, "input_tokens": tin, "output_tokens": tout, "turns": 12}


def test_finding_dict_has_every_required_field():
    f = verified_finding()
    for key in ["id", "title", "severity", "component", "file", "line", "location", "reproducer", "patch", "verification"]:
        assert f[key] not in (None, ""), key
    assert f["location"] == "app/Login.java:1"
    assert f["verification"]["unpatched_run"]["proof_line_seen"] is True
    assert f["verification"]["patched_run"]["proof_line_seen"] is False
    assert f["agent_self_test_claim"] == "ran it, saw 200"  # labelled as a claim, separate from evidence


def test_finding_dict_refuses_unverified():
    c = candidate()
    v = Verifier(ScriptedExecutor(lambda cc, m, n: clean()), Policy()).verify_one(c)
    with pytest.raises(AssertionError):
        finding_dict(c, v)


def test_markdown_report_contents():
    f = verified_finding()
    summary = build_summary(3, [comp_result(), comp_result("b", cost=0.5), comp_result("c", state="error", cost=None, tin=None, tout=None)], 4, [f], [Dropped("b", "not_reproduced", "x"), Dropped("b", "patch_did_not_fix", "y")], 10, 7, {"false_positive": 3}, None)
    md = render_markdown(META, [f], summary)
    assert "# vulnscan report: demo" in md
    assert "diff scan since `HEAD~1`" in md
    assert "### [CRITICAL] Admin API reachable without a session" in md
    assert "`app/Login.java:1`" in md
    assert "CWE-306" in md
    assert "```bash" in md and "VULNSCAN-PROOF:$VULNSCAN_NONCE" in md
    assert "```diff" in md and "+class Login" in md
    assert "proof line printed" in md and "Patched (result: fixed)" in md
    assert "| Components scanned | 2 of 3 (1 failed) |" in md
    assert "| Verified findings | 1 |" in md
    assert "| Cost | $1.75 |" in md
    assert "| Tokens in / out | 2,000 / 400 |" in md
    # dropped candidates are counted, never rendered as findings
    assert "reproducer ran but did not print the proof line | 1" in md
    assert md.count("### [") == 1


def test_cost_not_reported_is_never_invented():
    summary = build_summary(1, [comp_result(cost=None, tin=None, tout=None)], 0, [], [], 0, 0, {}, None)
    assert summary["cost_usd"] is None and summary["tokens"]["reported"] is False
    md = render_markdown(META, [], summary)
    assert "| Cost | not reported |" in md and "| Tokens in / out | not reported |" in md
    assert "No verified findings in this run." in md


def test_dry_run_report_says_so():
    meta = {**META, "dry_run": True, "not_exercised": ["docker build"]}
    md = render_markdown(meta, [], build_summary(2, [comp_result(state="planned", cost=None, tin=None, tout=None)] * 2, 0, [], [], 0, 0, {}, None))
    assert "Dry run" in md and "None: this was a dry run." in md and "## Not exercised in this run" in md


def test_fence_survives_backticks_in_content():
    f = verified_finding(reproducer={"script": "echo '```' ; echo $VULNSCAN_NONCE", "files": []})
    md = render_markdown(META, [f], build_summary(1, [comp_result()], 1, [f], [], 0, 0, {}, None))
    assert "````bash" in md


def test_write_outputs(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-DONOTLEAKDONOTLEAK")
    hi = verified_finding(title="high one", severity="high", description="leaks sk-ant-api03-DONOTLEAKDONOTLEAK")
    crit = verified_finding()
    dropped = [Dropped("auth", "not_reproduced", "maybe", "VS-x")]
    summary = build_summary(1, [comp_result()], 3, [hi, crit], dropped, 0, 0, {}, {"forwarded": 10})
    report = write_outputs(tmp_path, META, [hi, crit], dropped, summary)
    findings = json.loads((tmp_path / "findings.json").read_text())
    assert [f["severity"] for f in findings] == ["critical", "high"]  # sorted by severity
    assert (tmp_path / "findings" / f"{crit['id']}.json").is_file()
    assert json.loads((tmp_path / "dropped.json").read_text())[0]["reason"] == "not_reproduced"
    s = json.loads((tmp_path / "summary.json").read_text())
    assert s["verified"] == 2 and s["dropped"] == 1 and s["meta"]["run_id"] == "r1" and s["by_severity"] == {"critical": 1, "high": 1}
    for p in tmp_path.rglob("*.*"):
        assert "DONOTLEAK" not in p.read_text(encoding="utf-8"), p
    assert report.read_text().startswith("# vulnscan report")
