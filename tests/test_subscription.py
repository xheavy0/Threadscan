"""Subscription mode: the token stays in the gateway, concurrency 1, stop at the usage limit."""

import json
from pathlib import Path

import pytest
from test_pipeline import FakeBackend

from threadscan import docker_ops as dk
from threadscan.config import ConfigError, load_project
from threadscan.gateway import OAUTH_BETA, Stats, upstream_headers
from threadscan.orchestrator import ScanOptions, run_scan
from threadscan.redact import redact


@pytest.fixture
def make_cfg(target_dir, sample_repo):
    def make(scan_yaml: str = ""):
        d = target_dir(
            f"""
            name: demo
            repo: {sample_repo.as_posix()}
            components:
              auto:
                - root: backend/src/main/java/com/x
                  depth: 1
                - root: src
                  depth: 1
            scan:
              {scan_yaml}
            """
        )
        return load_project(d)

    return make


# ------------------------------------------------------------------ config


def test_auth_defaults(make_cfg):
    cfg = make_cfg("model: claude-opus-5-5")
    assert cfg.scan.auth == "api_key" and cfg.scan.concurrency == 2


def test_subscription_defaults_to_one_agent(make_cfg):
    cfg = make_cfg("auth: subscription")
    assert cfg.scan.auth == "subscription" and cfg.scan.concurrency == 1


def test_explicit_concurrency_is_honoured(target_dir, sample_repo):
    d = target_dir(f"name: demo\nrepo: {sample_repo.as_posix()}\nscan:\n  auth: subscription\n  concurrency: 2\n")
    assert load_project(d).scan.concurrency == 2


def test_unknown_auth_rejected(make_cfg):
    with pytest.raises(ConfigError) as exc:
        make_cfg("auth: password")
    assert any("auth" in p for p in exc.value.problems)


# ------------------------------------------------------------------ credential handling


def test_gateway_injects_bearer_token_and_oauth_beta():
    h = upstream_headers(
        [("x-api-key", "placeholder"), ("Authorization", "Bearer placeholder"), ("anthropic-beta", "a-1, b-2"), ("Anthropic-Beta", "a-1"), ("anthropic-version", "2023-06-01")],
        "sk-ant-oat01-REAL",
        "subscription",
    )
    assert h["authorization"] == "Bearer sk-ant-oat01-REAL"
    assert "x-api-key" not in {k.lower() for k in h}
    assert h["anthropic-beta"].split(",") == ["a-1", "b-2", OAUTH_BETA]
    assert h["anthropic-version"] == "2023-06-01"


def test_gateway_api_key_mode_unchanged():
    h = upstream_headers([("Authorization", "Bearer x"), ("anthropic-beta", "a-1")], "real-key", "api_key")
    assert h == {"anthropic-beta": "a-1", "x-api-key": "real-key"}


def test_scan_container_gets_a_placeholder_token_and_no_api_key(tmp_path):
    args = " ".join(dk.scan_run_args("n", "net", "img", tmp_path, tmp_path, "4g", 1.0, 512, "subscription"))
    assert f"CLAUDE_CODE_OAUTH_TOKEN={dk.PLACEHOLDER_OAUTH}" in args
    assert "ANTHROPIC_API_KEY" not in args  # it would outrank the OAuth token in Claude Code
    args = " ".join(dk.scan_run_args("n", "net", "img", tmp_path, tmp_path, "4g", 1.0, 512, "api_key"))
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in args and f"ANTHROPIC_API_KEY={dk.PLACEHOLDER_KEY}" in args


def test_gateway_receives_the_token_by_name_only(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-SHOULDNOTAPPEAR")
    args = dk.gateway_run_args("gw", "egress", "python:3.13-slim", Path("g.py"), tmp_path, 10, "subscription")
    assert args[args.index("-e") + 1] == "CLAUDE_CODE_OAUTH_TOKEN"
    assert args[-2:] == ["--auth", "subscription"]
    assert "SHOULDNOTAPPEAR" not in " ".join(args)


def test_token_is_redacted(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok-1234567890-abcdef")
    assert "tok-1234567890" not in redact("echo tok-1234567890-abcdef and sk-ant-oat01-abcdefghijkl")
    assert "sk-ant-oat01-abcdefghijkl" not in redact("sk-ant-oat01-abcdefghijkl")


def test_stats_record_the_usage_limit_and_refused_paths(tmp_path):
    s = Stats(str(tmp_path / "s.json"), 10, "subscription")
    s.record("forwarded", 200)
    assert s.data["limit_hit_at"] is None
    s.record("forwarded", 429)
    s.record("denied", 403, "GET /api/oauth/profile")
    data = json.loads((tmp_path / "s.json").read_text())
    assert data["limit_hit_at"] and data["rate_limited"] == 1
    assert data["denied_paths"] == {"GET /api/oauth/profile": 1}


# ------------------------------------------------------------------ pipeline


class LimitedBackend(FakeBackend):
    """The plan's limit is hit while the first component runs."""

    def __init__(self):
        super().__init__({})
        self.scanned = []

    def scan_component(self, comp, task_dir, out_dir):
        self.scanned.append(comp.name)
        super().scan_component(comp, task_dir, out_dir)

    def limit_reached(self):
        return bool(self.scanned)


def test_scan_stops_at_the_usage_limit_and_says_how_to_resume(make_cfg, tmp_path):
    cfg = make_cfg("auth: subscription")
    backend = LimitedBackend()
    run_dir = run_scan(cfg, ScanOptions(mode="full", max_components=4, runs_dir=tmp_path / "runs"), backend=backend, log=lambda *_: None)
    assert len(backend.scanned) == 1  # one agent at a time; nothing started after the limit
    summary = json.loads((run_dir / "summary.json").read_text())
    assert len(summary["components_skipped"]) == 3 and summary["limit_reached"] is True
    assert summary["resume_command"].count("--only") == 3 and "--full" in summary["resume_command"]
    md = (run_dir / "report.md").read_text()
    assert "## Not scanned: usage limit reached" in md
    assert "not billed, counts against your subscription limits" in md
    assert "Auth: your Claude subscription" in md
    status = json.loads((run_dir / "status.json").read_text())
    assert status["auth"] == "subscription"
    assert [c["state"] for c in status["components"]].count("skipped") == 3


def test_api_key_mode_ignores_429s(make_cfg, tmp_path):
    backend = LimitedBackend()
    run_scan(make_cfg("auth: api_key"), ScanOptions(mode="full", max_components=3, runs_dir=tmp_path / "runs"), backend=backend, log=lambda *_: None)
    assert len(backend.scanned) == 3


def test_full_scan_on_subscription_needs_intent(make_cfg, tmp_path):
    cfg = make_cfg("auth: subscription")
    with pytest.raises(RuntimeError, match="--allow-full"):
        run_scan(cfg, ScanOptions(mode="full", runs_dir=tmp_path / "runs"), backend=FakeBackend({}), log=lambda *_: None)
    assert not (tmp_path / "runs").exists()  # refused before anything ran
    run_scan(cfg, ScanOptions(mode="full", allow_full=True, runs_dir=tmp_path / "runs"), backend=FakeBackend({}), log=lambda *_: None)


def test_cli_auth_override_switches_concurrency(make_cfg, tmp_path):
    cfg = make_cfg("model: claude-opus-5-5")
    backend = FakeBackend({})
    run_scan(cfg, ScanOptions(mode="full", max_components=3, auth="subscription", runs_dir=tmp_path / "runs"), backend=backend, log=lambda *_: None)
    assert cfg.scan.auth == "subscription" and cfg.scan.concurrency == 1 and backend.max_active == 1


def test_missing_token_is_reported_before_docker(make_cfg, tmp_path, monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="claude setup-token"):
        run_scan(make_cfg("auth: subscription"), ScanOptions(mode="diff", runs_dir=tmp_path / "runs"), log=lambda *_: None)
