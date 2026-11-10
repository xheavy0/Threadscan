"""threadscan doctor: static checks with a fake command runner, and the judges for live results."""

import json

from threadscan.doctor import (
    Report,
    describe_credential,
    doctor_task,
    judge_agent,
    judge_probe,
    judge_verify,
    parse_probe,
    render,
    run_doctor,
    static_checks,
)
from threadscan.candidates import CANDIDATE_SCHEMA


class FakeRun:
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, args, timeout=None):
        self.calls.append(args)
        for prefix, ans in self.answers.items():
            if " ".join(args).startswith(prefix):
                return ans
        return 0, "", ""


GOOD = {
    "git --version": (0, "git version 2.51.0", ""),
    "docker version": (0, "28.1.1\n", ""),
    "docker info": (0, "linux|17179869184|8\n", ""),
    "docker buildx version": (0, "github.com/docker/buildx v0.24.0", ""),
}


def names(report):
    return {c.name: c.status for c in report.checks}


def test_all_good(tmp_path):
    r = Report()
    facts = static_checks(r, None, "subscription", FakeRun(GOOD), env={"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-x" * 3}, cwd=tmp_path)
    st = names(r)
    assert facts["docker_ok"] and not r.failed
    for k in ("Python", "git", "Docker daemon", "Docker engine type", "Docker memory", "BuildKit (buildx)", "Credential (subscription)", "Internal network"):
        assert st[k] == "ok", k


def test_missing_docker_still_checks_the_rest(tmp_path):
    r = Report()
    run = FakeRun({**GOOD, "docker version": (None, "", "docker: not found")})
    facts = static_checks(r, None, "api_key", run, env={}, cwd=tmp_path)
    st = names(r)
    assert st["Docker CLI"] == "fail" and not facts["docker_ok"]
    assert st["Credential (api_key)"] == "fail"  # still reported
    assert "Internal network" not in st  # docker-dependent check skipped
    assert not any("network" in " ".join(c) for c in run.calls)


def test_windows_containers_and_low_memory(tmp_path):
    r = Report()
    static_checks(r, None, "subscription", FakeRun({**GOOD, "docker info": (0, "windows|4294967296|4", "")}),
                  env={"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-abcdef"}, cwd=tmp_path)
    st = names(r)
    assert st["Docker engine type"] == "fail" and st["Docker memory"] == "warn"


def test_credential_is_described_never_shown():
    status, detail, _ = describe_credential("subscription", "sk-ant-oat01-SECRETSECRET")
    assert status == "ok" and "SECRET" not in detail
    assert describe_credential("api_key", "sk-ant-oat01-wrongkind")[0] == "warn"
    assert describe_credential("subscription", None)[0] == "fail"


def test_probe_judging():
    r = Report()
    judge_probe(r, parse_probe('noise\nPROBE {"gateway": 200, "internet": "blocked (URLError)"}\n'), "subscription")
    assert names(r) == {"Gateway from scan network": "ok", "Credential accepted upstream": "ok", "Scan network isolation": "ok"}
    r = Report()
    judge_probe(r, {"gateway": 401, "body": "x", "internet": "reachable"}, "api_key")
    st = names(r)
    assert st["Credential accepted upstream"] == "fail" and st["Scan network isolation"] == "fail"
    r = Report()
    judge_probe(r, {"gateway": 403, "body": "oauth", "internet": "blocked (x)"}, "subscription")
    assert names(r)["Credential accepted upstream"] == "warn"  # the agent check decides
    r = Report()
    judge_probe(r, None, "subscription")
    assert r.failed


def test_agent_judging(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    r = Report()
    judge_agent(r, out, None)
    assert r.failed  # no output at all
    (out / "candidates.json").write_text(json.dumps({"error": "401 authentication_error"}))
    r = Report()
    judge_agent(r, out, {"denied_paths": {"GET /api/oauth/profile": 2}})
    st = names(r)
    assert st["Claude Code through the gateway"] == "fail" and st["Gateway refusals"] == "warn"
    (out / "candidates.json").write_text(json.dumps({"structured": {"findings": [], "seed_triage": [], "notes": "doctor-ok"}, "parse": "structured_output",
                                                     "result": {"is_error": False, "num_turns": 1, "total_cost_usd": 0.0012}}))
    r = Report()
    judge_agent(r, out, {"denied_paths": {}})
    assert not r.failed and names(r)["Gateway refusals"] == "ok"


def test_verify_judging():
    r = Report()
    judge_verify(r, "THREADSCAN-PROOF:abc\n", "abc")
    assert not r.failed
    r = Report()
    judge_verify(r, "NETWORK-REACHABLE\nTHREADSCAN-PROOF:abc\n", "abc")
    assert names(r)["Verification isolation"] == "fail"


def test_doctor_task_is_tiny_and_tool_free():
    t = doctor_task("claude-haiku-5-5")
    assert t["max_turns"] <= 3 and t["max_budget_usd"] <= 0.5 and t["schema"] == CANDIDATE_SCHEMA
    assert "Do not use any tools" in t["system_prompt"]


def test_run_doctor_writes_report_and_skips_live_without_docker(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    run = FakeRun({**GOOD, "docker version": (None, "", "docker: not found")})
    report, run_dir = run_doctor(None, "subscription", True, "claude-haiku-5-5", tmp_path, run)
    assert names(report)["Live checks"] == "skip"
    saved = json.loads((run_dir / "doctor.json").read_text())
    assert saved["ok"] is False and saved["live"] is True
    assert "FAIL" in render(report)
