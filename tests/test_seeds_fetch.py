"""threadscan seeds: CodeQL download via gh (faked), merge, slug inference; tools that are missing."""

import json

from threadscan.seeds import load_seed_file
from threadscan.seeds_fetch import fetch_all, github_slug, latest_per_category, merge_sarif


def sarif(rule, path):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": [
        {"ruleId": rule, "message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": 3}}}]}]}]}


class FakeGh:
    def __init__(self):
        self.calls = []

    def __call__(self, args, timeout=None):
        self.calls.append(args)
        cmd = " ".join(args)
        if "remote get-url origin" in cmd:
            return 0, "git@github.com:xheavy0/Aegis-2.git\n", ""
        if "rev-parse --abbrev-ref HEAD" in cmd:
            return 0, "main\n", ""
        if args[:2] == ["gh", "api"] and "analyses?" in args[2]:
            return 0, json.dumps([
                {"id": 1, "category": "/language:java", "tool": {"name": "CodeQL"}, "created_at": "2026-11-01T00:00:00Z", "commit_sha": "aaa"},
                {"id": 2, "category": "/language:java", "tool": {"name": "CodeQL"}, "created_at": "2026-11-09T00:00:00Z", "commit_sha": "bbbbbbbbbbbbbbbb"},
                {"id": 3, "category": "/language:javascript", "tool": {"name": "CodeQL"}, "created_at": "2026-11-08T00:00:00Z", "commit_sha": "ccc"},
                {"id": 4, "category": "trivy", "tool": {"name": "Trivy"}, "created_at": "2026-11-09T00:00:00Z"},
            ]), ""
        if args[:2] == ["gh", "api"] and args[2] == "-H":
            aid = args[-1].rsplit("/", 1)[1]
            return 0, json.dumps(sarif(f"rule-{aid}", f"src/f{aid}.java")), ""
        return 0, "", ""


def test_github_slug():
    assert github_slug("https://github.com/xheavy0/Aegis-2.git") == "xheavy0/Aegis-2"
    assert github_slug("git@github.com:xheavy0/Threadscan.git\n") == "xheavy0/Threadscan"
    assert github_slug("https://gitlab.com/a/b.git") is None


def test_latest_per_category_and_merge():
    picked = latest_per_category([
        {"id": 1, "category": "java", "tool": {"name": "CodeQL"}, "created_at": "1"},
        {"id": 2, "category": "java", "tool": {"name": "CodeQL"}, "created_at": "2"},
        {"id": 3, "category": "js", "tool": {"name": "Other"}, "created_at": "3"},
    ])
    assert [a["id"] for a in picked] == [2]
    assert len(merge_sarif([sarif("a", "x"), sarif("b", "y")])["runs"]) == 2


def test_fetch_codeql_newest_per_language_into_target_seeds(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)  # gitleaks / osv not installed
    gh = FakeGh()
    out = fetch_all(tmp_path, tmp_path / "repo", {"codeql", "gitleaks", "osv"}, run=gh)
    by = {o.tool: o for o in out}
    assert by["codeql"].status == "ok" and "2 analyses" in by["codeql"].detail
    assert by["gitleaks"].status == "skipped" and by["osv"].status == "skipped"
    list_call = next(c for c in gh.calls if c[:2] == ["gh", "api"] and "analyses?" in c[2])
    assert list_call[2].startswith("repos/xheavy0/Aegis-2/code-scanning/analyses") and "ref=refs/heads/main" in list_call[2]
    downloads = [c[-1] for c in gh.calls if c[:3] == ["gh", "api", "-H"]]
    assert downloads == ["repos/xheavy0/Aegis-2/code-scanning/analyses/2", "repos/xheavy0/Aegis-2/code-scanning/analyses/3"]
    seeds = load_seed_file("codeql", tmp_path / "seeds" / "codeql.sarif")
    assert sorted(s.rule for s in seeds) == ["rule-2", "rule-3"]
    assert all(c[:2] != ["git", "push"] for c in gh.calls)  # read-only


def test_codeql_errors_are_reported_not_raised(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)

    def denied(args, timeout=None):
        if args[:2] == ["gh", "api"]:
            return 1, "", "HTTP 403: Resource not accessible by integration"
        return 0, "", ""

    out = fetch_all(tmp_path, tmp_path, {"codeql"}, github="o/r", run=denied)
    assert out[0].status == "failed" and "security_events" in out[0].detail
    out = fetch_all(tmp_path, tmp_path, {"codeql"}, run=lambda a, t=None: (1, "", "no remote"))
    assert out[0].status == "skipped" and "--github" in out[0].detail
