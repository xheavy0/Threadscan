"""threadscan watch: baseline, idle, scan on new commits, keep baseline on failure, pause at the limit."""

import json

import pytest

from threadscan.watch import load_state, parse_interval, watch_loop, watch_once


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def make_scan(tmp_path, summaries):
    calls = []

    def scan(last):
        calls.append(last)
        i = len(calls)
        d = tmp_path / f"run{i}"
        d.mkdir()
        s = summaries[i - 1]
        if isinstance(s, Exception):
            raise s
        (d / "summary.json").write_text(json.dumps(s))
        return d
    return scan, calls


def test_parse_interval():
    assert parse_interval("15m") == 900 and parse_interval("1h") == 3600 and parse_interval("120s") == 120 and parse_interval("5") == 300
    for bad in ("30s", "soon", "-5m"):
        with pytest.raises(ValueError):
            parse_interval(bad)


def test_baseline_idle_then_scan_since_last(tmp_path):
    state = tmp_path / "w.json"
    heads = iter(["aaa", "aaa", "bbb", "bbb"])
    scan, calls = make_scan(tmp_path, [{"verified": 2}])
    rechecks = []
    once = lambda: watch_once(state, lambda: next(heads), scan, lambda: rechecks.append(1) or {"summary": {"fixed": 1}}, log=lambda *_: None)
    assert once()["action"] == "baseline" and calls == []
    assert once()["action"] == "idle"
    r = once()
    assert r["action"] == "scanned" and calls == ["aaa"] and r["recheck"] == {"fixed": 1} and rechecks == [1]
    assert load_state(state)["last_commit"] == "bbb"
    assert once()["action"] == "idle" and calls == ["aaa"]


def test_initial_scans_against_diff_base(tmp_path):
    scan, calls = make_scan(tmp_path, [{"verified": 0}])
    r = watch_once(tmp_path / "w.json", lambda: "aaa", scan, initial=True, log=lambda *_: None)
    assert r["action"] == "scanned" and calls == [None]


def test_failure_keeps_baseline_and_retries(tmp_path):
    state = tmp_path / "w.json"
    heads = iter(["aaa", "bbb", "bbb"])
    scan, calls = make_scan(tmp_path, [RuntimeError("docker down"), {"verified": 1}])
    once = lambda: watch_once(state, lambda: next(heads), scan, log=lambda *_: None)
    once()
    assert once()["action"] == "failed" and load_state(state)["last_commit"] == "aaa" and load_state(state)["failures"] == 1
    assert once()["action"] == "scanned" and calls == ["aaa", "aaa"]


def test_usage_limit_pauses_and_keeps_baseline(tmp_path):
    state, clock = tmp_path / "w.json", Clock()
    heads = iter(["aaa", "bbb", "bbb"])
    scan, calls = make_scan(tmp_path, [{"verified": 1, "components_skipped": ["x"]}, {"verified": 1}])
    once = lambda: watch_once(state, lambda: next(heads), scan, pause_s=600, now=clock, log=lambda *_: None)
    once()
    assert once()["action"] == "limit" and load_state(state)["last_commit"] == "aaa"
    clock.t += 100
    assert once()["action"] == "paused" and len(calls) == 1  # head not even read while paused
    clock.t += 600
    assert once()["action"] == "scanned" and calls == ["aaa", "aaa"]


def test_loop_survives_errors_and_sleeps(tmp_path):
    slept, logs = [], []
    results = iter([RuntimeError("no HEAD"), {"action": "scanned", "run": "r1", "verified": 3}])

    def once():
        r = next(results)
        if isinstance(r, Exception):
            raise r
        return r

    watch_loop(900, once, sleep=slept.append, log=logs.append, max_rounds=2)
    assert slept == [900] and any("check failed" in m for m in logs) and any("scanned r1" in m for m in logs)
