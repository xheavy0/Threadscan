"""threadscan recheck: evidence-based triage updates from re-running old reproducers."""

import json

import pytest
from helpers import ScriptedExecutor, candidate, clean, proof

from threadscan.config import load_project
from threadscan.recheck import list_rechecks, pick_source_run, recheck
from threadscan.report import build_summary, finding_dict, write_outputs
from threadscan.status import StatusTracker
from threadscan.triage import TriageStore
from threadscan.verify import Policy, RunResult, Verifier


@pytest.fixture
def setup(tmp_path, target_dir, sample_repo):
    cfg = load_project(target_dir(f"name: demo\nrepo: {sample_repo.as_posix()}\n"))
    runs = tmp_path / "runs"
    run = runs / "20260101-000000-demo"
    run.mkdir(parents=True)
    fs = []
    for title, marker in [("Fixed one", "FIXED"), ("Still there", "STILL"), ("Now broken", "BROKEN"), ("Accepted risk", "STILL"), ("Wrongly resolved", "STILL")]:
        c = candidate(title=title, reproducer={"script": f"# {marker} $THREADSCAN_NONCE", "files": []})
        v = Verifier(ScriptedExecutor(lambda cc, m, n: proof(n) if m == "unpatched" else clean()), Policy()).verify_one(c)
        fs.append(finding_dict(c, v))
    meta = {"run_id": run.name, "project": "demo", "mode": "full", "dry_run": False}
    write_outputs(run, meta, fs, [], build_summary(1, [], len(fs), fs, [], 0, 0, {}, None))
    StatusTracker(run, run.name, "demo", "full", None, False).phase("done")
    store = TriageStore(runs / "triage.json")
    ids = {f["title"]: f["id"] for f in fs}
    store.update(ids["Accepted risk"], {"status": "risk_accepted"})
    store.update(ids["Wrongly resolved"], {"status": "resolved"})
    return cfg, runs, store, ids


def executor():
    def run(cand, mode, nonce):
        assert mode == "unpatched"
        if "FIXED" in cand.script:
            return clean()
        if "STILL" in cand.script:
            return proof(nonce)
        return RunResult(1, "compile error", "", 1.0)
    return ScriptedExecutor(run)


def test_recheck_applies_evidence_to_triage(setup, tmp_path):
    cfg, runs, store, ids = setup
    ex = executor()
    out = recheck(cfg, runs, tmp_path / "work", ex, store, commit="abcdef1234567890", log=lambda *_: None)
    by = {r["title"]: r for r in out["results"]}
    assert out["summary"] == {"fixed": 1, "still_present": 2, "unverified": 1}
    assert "Accepted risk" not in by  # skipped by triage
    assert len(ex.calls) == 4
    t = store.load()
    fixed = t[ids["Fixed one"]]
    assert fixed["status"] == "resolved" and fixed["history"][-1]["by"] == "threadscan recheck"
    assert "abcdef123456" in fixed["history"][-1]["reason"]
    assert t[ids["Wrongly resolved"]]["status"] == "open" and by["Wrongly resolved"]["triage_change"] == "resolved -> open"
    assert ids["Still there"] not in t  # open stays open, nothing to record
    assert ids["Now broken"] not in t and by["Now broken"]["outcome"] == "unverified" and by["Now broken"]["reason"]
    saved = json.loads((tmp_path / "work" / "recheck.json").read_text())
    assert saved["source_run"] == "20260101-000000-demo" and saved["results"][0]["evidence"]["nonce"]


def test_recheck_all_includes_accepted_and_second_run_is_idempotent(setup, tmp_path):
    cfg, runs, store, ids = setup
    recheck(cfg, runs, tmp_path / "w1", executor(), store, log=lambda *_: None)
    out = recheck(cfg, runs, tmp_path / "w2", executor(), store, include_all=True, log=lambda *_: None)
    by = {r["title"]: r for r in out["results"]}
    assert by["Accepted risk"]["outcome"] == "still_present" and by["Accepted risk"]["triage_change"] is None
    assert by["Fixed one"]["triage_change"] is None  # already resolved by the first re-check
    assert len(store.load()[ids["Fixed one"]]["history"]) == 1


def test_no_source_run(tmp_path, target_dir, sample_repo):
    cfg = load_project(target_dir(f"name: demo\nrepo: {sample_repo.as_posix()}\n"))
    assert pick_source_run(tmp_path / "runs", "demo", None) is None
    with pytest.raises(RuntimeError):
        recheck(cfg, tmp_path / "runs", tmp_path / "w", executor(), TriageStore(tmp_path / "t.json"), log=lambda *_: None)


def test_list_rechecks(setup, tmp_path):
    cfg, runs, store, _ = setup
    recheck(cfg, runs, runs / "rechecks" / "20260102-000000-demo", executor(), store, log=lambda *_: None)
    rows = list_rechecks(runs)
    assert rows[0]["id"] == "20260102-000000-demo" and rows[0]["summary"]["fixed"] == 1
