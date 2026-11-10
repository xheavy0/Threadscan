"""End-to-end pipeline with a fake backend (no Docker, no API): fan-out, gate, report."""

import json
import threading
import time
from pathlib import Path

import pytest
from helpers import PATCH, clean, proof, raw_candidate

from vulnscan.config import load_project
from vulnscan.orchestrator import ScanOptions, run_scan
from vulnscan.status import write_json


@pytest.fixture
def cfg(target_dir, sample_repo):
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
          explicit:
            - name: deploy
              paths: ["deploy/**"]
        """
    )
    return load_project(d)


class FakeBackend:
    """Plays the agent: writes candidates.json per component; executes reproducers by script content."""

    def __init__(self, outputs: dict, fail: set = frozenset()):
        self.outputs, self.fail = outputs, fail
        self.active = 0
        self.max_active = 0
        self.lock = threading.Lock()
        self.prepared = self.closed = False

    def prepare(self, run_dir):
        self.prepared = True

    def scan_component(self, comp, task_dir, out_dir):
        task = json.loads((task_dir / "task.json").read_text())
        assert task["component"]["name"] == comp.name and "Threat model" in task["system_prompt"]
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(0.05)
        with self.lock:
            self.active -= 1
        if comp.name in self.fail:
            raise RuntimeError("container exited 137")
        out = self.outputs.get(comp.name, {"findings": [], "seed_triage": [], "notes": "nothing"})
        write_json(out_dir / "candidates.json", {"component": comp.name, "structured": out, "result": {"total_cost_usd": 0.5, "usage": {"input_tokens": 100, "output_tokens": 10}, "num_turns": 3, "subtype": "success"}})

    def executor(self, run_dir):
        class Ex:
            def run(self, cand, mode, nonce):
                if "ALWAYS" in cand.script:  # fabricated: prints proof unconditionally
                    return proof(nonce)
                if "NEVER" in cand.script:
                    return clean()
                return proof(nonce) if mode == "unpatched" else clean()

        return Ex()

    def gateway_stats(self):
        return {"forwarded": 7}

    def close(self):
        self.closed = True


def test_full_pipeline(cfg, tmp_path):
    auth = "backend/src/main/java/com/x/auth"
    outputs = {
        auth: {
            "findings": [
                raw_candidate(),  # real
                raw_candidate(title="Fabricated", line=50, cwe="CWE-1", reproducer={"script": "# ALWAYS\necho VULNSCAN-PROOF:$VULNSCAN_NONCE", "files": []}),
                raw_candidate(title="Unproven", line=90, cwe="CWE-2", reproducer={"script": "# NEVER $VULNSCAN_NONCE", "files": []}),
                raw_candidate(title="Same bug again", line=2),  # duplicate of the first
                {"title": "broken", "severity": "high"},  # invalid
            ],
            "seed_triage": [{"seed_id": "x", "verdict": "false_positive", "reason": "r"}],
            "notes": "",
        }
    }
    backend = FakeBackend(outputs, fail={"src"})
    run_dir = run_scan(cfg, ScanOptions(mode="full", runs_dir=tmp_path / "runs", concurrency=2), backend=backend, log=lambda *_: None)
    assert backend.prepared and backend.closed
    assert backend.max_active <= 2  # concurrency honoured

    summary = json.loads((run_dir / "summary.json").read_text())
    assert summary["candidates"] == 5
    assert summary["verified"] == 1
    assert summary["dropped_by_reason"] == {"patch_did_not_fix": 1, "not_reproduced": 1, "duplicate": 1, "invalid_candidate": 1}
    assert summary["components_failed"] == 1 and summary["agent_errors"] == 1
    assert summary["cost_usd"] == pytest.approx(0.5 * (summary["components_total"] - 1))
    assert summary["seeds"]["triage"] == {"false_positive": 1}
    assert summary["gateway"] == {"forwarded": 7}

    findings = json.loads((run_dir / "findings.json").read_text())
    assert [f["title"] for f in findings] == ["Admin API reachable without a session"]
    assert findings[0]["patch"] == PATCH
    md = (run_dir / "report.md").read_text()
    assert "Fabricated" not in md and "Unproven" not in md

    status = json.loads((run_dir / "status.json").read_text())
    assert status["phase"] == "done" and status["counts"]["verified"] == 1
    assert {v["state"] for v in status["verification"]} == {"kept", "dropped"}
    assert any(c["state"] == "error" for c in status["components"])


def test_diff_mode_scans_only_touched_components(cfg, tmp_path):
    backend = FakeBackend({})
    run_dir = run_scan(cfg, ScanOptions(mode="diff", runs_dir=tmp_path / "runs"), backend=backend, log=lambda *_: None)
    plan = json.loads((run_dir / "plan.json").read_text())
    assert [c["name"] for c in plan["components"]] == ["backend/src/main/java/com/x/auth"]
    task = json.loads(next((run_dir / "components").glob("*/task.json")).read_text())
    assert "diff scan" in task["user_prompt"] and "Mfa.java" in task["user_prompt"] and "+class Login { int changed; }" in task["user_prompt"]


def test_dry_run_writes_plan_and_empty_report_and_never_touches_backend(cfg, tmp_path):
    class Exploding:
        def __getattr__(self, name):
            raise AssertionError("dry run must not use the backend")

    run_dir = run_scan(cfg, ScanOptions(mode="full", max_components=2, dry_run=True, runs_dir=tmp_path / "runs"), backend=Exploding(), log=lambda *_: None)
    plan = json.loads((run_dir / "plan.json").read_text())
    assert len(plan["components"]) == 2
    assert plan["commands"]["verify_template"][plan["commands"]["verify_template"].index("--network") + 1] == "none"
    assert len(list((run_dir / "components").glob("*/task.json"))) == 2
    summary = json.loads((run_dir / "summary.json").read_text())
    assert summary["verified"] == 0 and summary["cost_usd"] is None
    assert "Dry run" in (run_dir / "report.md").read_text()
    assert json.loads((run_dir / "status.json").read_text())["phase"] == "done"


def test_failed_run_is_marked_failed(cfg, tmp_path):
    class Broken(FakeBackend):
        def prepare(self, run_dir):
            raise RuntimeError("target image build failed")

    with pytest.raises(RuntimeError):
        run_scan(cfg, ScanOptions(mode="full", runs_dir=tmp_path / "runs"), backend=Broken({}), log=lambda *_: None)
    status = json.loads(next((tmp_path / "runs").glob("*/status.json")).read_text())
    assert status["phase"] == "failed" and "build failed" in status["message"]


def test_known_issues_and_seeds_reach_the_task(cfg, tmp_path, sample_repo):
    (sample_repo / "KNOWN.md").write_text("F-1 accepted: something\n")
    cfg.known_issues = "KNOWN.md"
    sarif = tmp_path / "c.sarif"
    sarif.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": [{"ruleId": "r", "message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "backend/src/main/java/com/x/auth/Login.java"}, "region": {"startLine": 1}}}]}]}]}))
    from vulnscan.config import SeedSpec

    run_dir = run_scan(cfg, ScanOptions(mode="diff", dry_run=True, runs_dir=tmp_path / "runs", extra_seeds=[SeedSpec("codeql", sarif)]), log=lambda *_: None)
    task = json.loads(next((run_dir / "components").glob("*/task.json")).read_text())
    assert "F-1 accepted" in task["system_prompt"]
    assert len(task["seed_ids"]) == 1 and '"rule": "r"' in task["user_prompt"]
