"""The scanner's own security model: gateway allow-list, container flags, agent options."""

import dataclasses
from pathlib import Path

import pytest

from threadscan import docker_ops as dk
from threadscan.agent_runner import DENIED, TOOLS, build_options, extract_json
from threadscan.gateway import is_allowed, upstream_headers


@pytest.mark.parametrize(
    "method,target",
    [("POST", "/v1/messages"), ("POST", "/v1/messages?beta=true"), ("POST", "/v1/messages/count_tokens"), ("GET", "/v1/models"), ("GET", "/v1/models/claude-opus-5-5")],
)
def test_gateway_allows_only_the_messages_api(method, target):
    assert is_allowed(method, target)


@pytest.mark.parametrize(
    "method,target",
    [
        ("GET", "/v1/messages"),
        ("POST", "/v1/files"),
        ("POST", "/v1/messages/batches"),
        ("POST", "/v1/organizations/x"),
        ("GET", "http://evil.example/v1/messages"),  # absolute-form: would make it an open proxy
        ("POST", "//evil.example/v1/messages"),
        ("POST", "/v1/messages/../files"),
        ("POST", "/v1/%6dessages"),
        ("GET", "/v1/modelsX"),
        ("GET", "/"),
    ],
)
def test_gateway_refuses_everything_else(method, target):
    assert not is_allowed(method, target)


def test_gateway_replaces_client_credentials():
    h = upstream_headers([("X-Api-Key", "placeholder"), ("Authorization", "Bearer stolen"), ("Host", "threadscan-gw"), ("anthropic-version", "2023-06-01"), ("Cookie", "a=b"), ("Content-Length", "10")], "real-key")
    assert h == {"anthropic-version": "2023-06-01", "x-api-key": "real-key"}


def test_scan_container_flags(tmp_path):
    args = dk.scan_run_args("n", "net-scan", "img", tmp_path / "in", tmp_path / "out", "6g", 2.0, 2048)
    assert args[args.index("--network") + 1] == "net-scan"
    for flag in ["--cap-drop", "ALL", "no-new-privileges", "--memory", "--pids-limit"]:
        assert flag in args
    joined = " ".join(args)
    assert f"ANTHROPIC_API_KEY={dk.PLACEHOLDER_KEY}" in joined  # placeholder only
    assert f"ANTHROPIC_BASE_URL=http://{dk.GATEWAY_ALIAS}:{dk.GATEWAY_PORT}" in joined
    assert "DISABLE_TELEMETRY=1" in joined and "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1" in joined
    assert f"dst={dk.IN_DIR},readonly" in joined


def test_verify_container_has_no_network(tmp_path):
    args = dk.verify_run_args("n", "img", tmp_path, "patched", "abc", "/src", "4g", 2.0)
    assert args[args.index("--network") + 1] == "none"
    assert "ANTHROPIC" not in " ".join(args)
    assert "THREADSCAN_NONCE=abc" in args and "--cap-drop" in args


def test_gateway_gets_key_by_name_only(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-appear")
    args = dk.gateway_run_args("gw", "egress", "python:3.13-slim", Path("gateway.py"), tmp_path, 100)
    assert "ANTHROPIC_API_KEY" in args  # docker copies the value from the environment
    assert "sk-ant-should-not-appear" not in " ".join(args)
    assert "--read-only" in args and "-p" not in args and "--publish" not in args


@dataclasses.dataclass
class FakeOptions:
    tools: list | None = None
    allowed_tools: list = dataclasses.field(default_factory=list)
    disallowed_tools: list = dataclasses.field(default_factory=list)
    permission_mode: str | None = None
    system_prompt: str | None = None
    setting_sources: list | None = None
    cwd: str | None = None
    model: str | None = None
    max_turns: int | None = None
    max_budget_usd: float | None = None
    output_format: dict | None = None


def test_agent_options_are_locked_down():
    task = {"system_prompt": "s", "workdir": "/src", "model": "m", "effort": "high", "max_turns": 5, "max_budget_usd": 1.0, "schema": {"type": "object"}}
    opts, dropped = build_options(task, FakeOptions)
    assert opts.tools == ["Read", "Grep", "Glob", "Bash"] == TOOLS
    assert opts.permission_mode == "dontAsk"
    assert opts.setting_sources == []  # never load the target repo's CLAUDE.md, hooks or settings
    assert {"Write", "Edit", "WebFetch", "WebSearch"} <= set(opts.disallowed_tools) and set(DENIED) == set(opts.disallowed_tools)
    assert opts.output_format["type"] == "json_schema"
    assert dropped == ["effort"]  # FakeOptions lacks it; reported, not silently lost


def test_extract_json_fallback():
    assert extract_json('done.\n```json\n{"findings": [], "notes": "x"}\n```') == {"findings": [], "notes": "x"}
    assert extract_json('text {"findings": [1]} more') == {"findings": [1]}
    assert extract_json("no json here") is None
    assert extract_json('{"other": 1}') is None
    assert extract_json(None) is None
