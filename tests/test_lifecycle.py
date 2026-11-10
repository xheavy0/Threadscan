"""Issue lifecycle across runs, OWASP mapping and triage state."""

import json

import pytest
from helpers import clean, proof, raw_candidate
from test_pipeline import FakeBackend

from threadscan import history
from threadscan.config import load_project
from threadscan.orchestrator import ScanOptions, run_scan
from threadscan.owasp import categorize, cwe_number
from threadscan.status import write_json
from threadscan.triage import TriageError, TriageStore


# ------------------------------------------------------------------ OWASP


@pytest.mark.parametrize("cwe,code", [("CWE-918", "A10"), ("CWE-89", "A03"), ("cwe_79", "A03"), ("CWE-639", "A01"), ("CWE-306", "A07"),
                                      ("CWE-502", "A08"), ("CWE-327", "A02"), ("CWE-611", "A05"), ("CWE-532", "A09"), ("CWE-434", "A04")])
def test_owasp_mapping(cwe, code):
    assert categorize(cwe)["id"] == code


def test_owasp_unmapped_and_malformed():
    assert categorize("CWE-99999") is None
    assert categorize("") is None and categorize(None) is None and categorize("n/a") is None
    assert cwe_number("CWE-79: Cross-site Scripting") == 79


# ------------------------------------------------------------------ matching


def f(id_, file="a/B.java", line=10, cwe="CWE-89", title="SQL injection in search", component="auth"):
    return {"id": id_, "file": file, "line": line, "cwe": cwe, "title": title, "component": component, "severity": "high", "location": f"{file}:{line}"}


def test_match_by_id_then_by_file_cwe_and_nearby_line():
    prev = [f("TS-1"), f("TS-2", file="c/D.java", cwe="CWE-79", title="XSS")]
    cur = [f("TS-1"), f("TS-9", file="c/D.java", line=14, cwe="CWE-79", title="Stored XSS in the comment renderer")]
    assert history.match_findings(prev, cur) == {"TS-1": "TS-1", "TS-9": "TS-2"}


def test_no_match_across_files_cwes_or_far_lines():
    prev = [f("TS-1")]
    for cur in ([f("TS-2", file="x/Y.java")], [f("TS-2", cwe="CWE-78")], [f("TS-2", line=40)]):
        assert history.match_findings(prev, cur) == {}


def test_plan_sorts_previous_issues_into_recheck_and_not_rescanned():
    prev = [f("TS-1"), f("TS-2", file="b.py", component="auth"), f("TS-3", file="c.py", component="storage")]
    cur = [f("TS-1"), f("TS-4", file="new.py")]
    lp = history.plan("run-1", prev, cur, scanned_components={"auth"})
    assert lp.new == ["TS-4"]
    assert [p["id"] for p in lp.recheck] == ["TS-2"]  # its component was scanned again
    assert [p["id"] for p in lp.not_rescanned] == ["TS-3"]  # never called resolved


# ------------------------------------------------------------------ triage


def test_triage_store_validates_and_keeps_history(tmp_path):
    store = TriageStore(tmp_path / "triage.json")
    e = store.update("TS-0123456789", {"status": "in_progress", "assignee": " nino "})
    assert e["status"] == "in_progress" and e["assignee"] == "nino" and len(e["history"]) == 1
    e = store.update("TS-0123456789", {"status": "in_progress"})  # no change, no history entry
    assert len(e["history"]) == 1
    e = store.update("TS-0123456789", {"note": "fix lands in 2.4"})
    assert e["history"][-1]["changes"][0] == {"field": "note", "from": "", "to": "(edited)"}
    assert json.loads((tmp_path / "triage.json").read_text())["TS-0123456789"]["note"] == "fix lands in 2.4"
    for bad_id, body in [("../x", {}), ("TS-XYZ", {}), ("TS-0123456789", {"status": "done"}), ("TS-0123456789", {"note": "x" * 5000}),
                         ("TS-0123456789", {"owner": "me"}), ("TS-0123456789", ["status"]), ("TS-0123456789", {"assignee": 5})]:
        with pytest.raises(TriageError):
            store.update(bad_id, body)


# ------------------------------------------------------------------ pipeline: resolved only after re-check


@pytest.fixture
def cfg(target_dir, sample_repo):
    d = target_dir(f"""
        name: demo
        repo: {sample_repo.as_posix()}
        components:
          auto:
            - root: backend/src/main/java/com/x
              depth: 1
        """)
    return load_project(d)


AUTH = "backend/src/main/java/com/x/auth"


def run(cfg, tmp_path, findings, executor_rules):
    class B(FakeBackend):
        def executor(self, run_dir):
            class Ex:
                def run(self, cand, mode, nonce):
                    return executor_rules(cand, mode, nonce)
            return Ex()

    return run_scan(cfg, ScanOptions(mode="full", runs_dir=tmp_path / "runs"), backend=B({AUTH: {"findings": findings, "seed_triage": [], "notes": ""}}), log=lambda *_: None)


def honest(c, m, n):
    return proof(n) if m == "unpatched" else clean()


def test_lifecycle_never_calls_an_unverified_absence_resolved(cfg, tmp_path):
    a = raw_candidate(title="Issue A", file="backend/src/main/java/com/x/auth/Login.java", line=1, cwe="CWE-306")
    b = raw_candidate(title="Issue B", file="backend/src/main/java/com/x/auth/Session.java", line=5, cwe="CWE-384",
                      reproducer={"script": "# FIXED-LATER $THREADSCAN_NONCE", "files": []})
    c = raw_candidate(title="Issue C", file="backend/src/main/java/com/x/auth/Mfa.java", line=3, cwe="CWE-287",
                      reproducer={"script": "# STILL-THERE $THREADSCAN_NONCE", "files": []})
    d = raw_candidate(title="Issue D", file="backend/src/main/java/com/x/auth/Token.java", line=8, cwe="CWE-613",
                      reproducer={"script": "# BROKEN-NOW $THREADSCAN_NONCE", "files": []})
    first = run(cfg, tmp_path, [a, b, c, d], honest)
    lc1 = json.loads((first / "lifecycle.json").read_text())
    assert lc1["previous_run"] is None and len(lc1["new"]) == 4

    import time
    time.sleep(1.1)  # run ids carry a timestamp

    def second_rules(cand, mode, nonce):
        if "FIXED-LATER" in cand.script:
            return clean()  # exits 0 without the proof: really fixed
        if "STILL-THERE" in cand.script:
            return proof(nonce)  # agent missed it, reproducer still works
        if "BROKEN-NOW" in cand.script:
            return clean(exit_code=1, out="cannot compile")  # cannot tell
        return honest(cand, mode, nonce)

    e = raw_candidate(title="Issue E", file="backend/src/main/java/com/x/auth/Reset.java", line=2, cwe="CWE-640")
    second = run(cfg, tmp_path, [a, e], second_rules)  # agent reports A again and a new E only
    lc = json.loads((second / "lifecycle.json").read_text())
    assert lc["previous_run"] == first.name
    titles = lambda xs: sorted(x["title"] for x in xs)
    assert titles(lc["resolved"]) == ["Issue B"] and lc["resolved"][0]["evidence"]["exit_code"] == 0
    assert titles(lc["unverified"]) == ["Issue D"]
    assert len(lc["still_present"]) == 1
    findings = json.loads((second / "findings.json").read_text())
    carried = [x for x in findings if x.get("carried_over_from")]
    assert [x["title"] for x in carried] == ["Issue C"] and carried[0]["verification"]["status"] == "re-verified"
    assert {x["title"] for x in findings} == {"Issue A", "Issue C", "Issue E"}
    new_titles = {x["title"] for x in findings if x["id"] in lc["new"]}
    assert new_titles == {"Issue E"}
    md = (second / "report.md").read_text()
    assert "## Changes since" in md and "Issue B" in md and "not counted as resolved" in md
    assert "OWASP Top 10:2021: A07" in md
    hist = history.project_history(tmp_path / "runs", "demo")
    assert [r["verified"] for r in hist] == [4, 3] and hist[-1]["resolved"] == 1 and hist[-1]["new"] == 1
