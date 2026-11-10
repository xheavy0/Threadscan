"""The verification gate: a candidate is kept only when its reproducer demonstrably works."""

import pytest
from helpers import ScriptedExecutor, candidate, clean, proof

from vulnscan.verify import (
    PATCH_FAILED_EXIT,
    PATCH_FAILED_MARKER,
    Policy,
    RunResult,
    Verifier,
    classify_patched,
    classify_unpatched,
    decide,
    has_proof,
)

STRICT = Policy(require_patch_differential=True)
LENIENT = Policy(require_patch_differential=False)


def honest(cand, mode, nonce):
    """A real reproducer: proof before the patch, none after."""
    return proof(nonce) if mode == "unpatched" else clean()


def test_proof_line_must_match_this_runs_nonce_exactly():
    assert has_proof("x\nVULNSCAN-PROOF:abc\n", "abc")
    assert has_proof("  VULNSCAN-PROOF:abc  \r\n", "abc")
    assert not has_proof("VULNSCAN-PROOF:abc", "abd")  # output copied from another run
    assert not has_proof("echo VULNSCAN-PROOF:abc", "abc")  # not on its own line
    assert not has_proof("VULNSCAN-PROOF:abcdef", "abc")
    assert not has_proof("", "abc")


def test_honest_reproducer_with_working_patch_is_kept():
    v = Verifier(ScriptedExecutor(honest), STRICT).verify_one(candidate())
    assert v.kept and v.reason == "verified" and v.reproduced and v.patch_check == "fixed"
    assert v.unpatched["proof_line_seen"] and not v.patched["proof_line_seen"]


def test_unconditional_echo_is_dropped_by_the_differential_check():
    ex = ScriptedExecutor(lambda c, m, n: proof(n))  # prints proof whatever happens
    v = Verifier(ex, STRICT).verify_one(candidate())
    assert not v.kept and v.reason == "patch_did_not_fix" and v.patch_check == "not_fixed"


def test_each_run_gets_a_fresh_nonce():
    ex = ScriptedExecutor(honest)
    Verifier(ex, STRICT).verify_one(candidate())
    (_, m1, n1), (_, m2, n2) = ex.calls
    assert (m1, m2) == ("unpatched", "patched") and n1 != n2 and len(n1) == 32


def test_replayed_proof_from_agent_session_does_not_count():
    ex = ScriptedExecutor(lambda c, m, n: proof("nonce-the-agent-saw"))
    v = Verifier(ex, STRICT).verify_one(candidate())
    assert not v.kept and v.reason == "not_reproduced"
    assert len(ex.calls) == 1  # no patched run once the unpatched run fails


@pytest.mark.parametrize(
    "result,reason",
    [
        (RunResult(0, "all good, nothing found\n", "", 1.0), "not_reproduced"),
        (RunResult(1, "compile error\n", "", 1.0), "reproducer_error"),
        (RunResult(None, "", "", 900.0, timed_out=True), "timeout"),
        (RunResult(None, "", "", 0.0, infra_error="docker: no such image"), "infra_error"),
    ],
)
def test_unproven_unpatched_runs_are_dropped(result, reason):
    v = Verifier(ScriptedExecutor(lambda c, m, n: result), STRICT).verify_one(candidate())
    assert not v.kept and v.reason == reason and not v.reproduced


def test_nonzero_exit_with_proof_is_still_an_error():
    v = Verifier(ScriptedExecutor(lambda c, m, n: proof(n, exit_code=2)), STRICT).verify_one(candidate())
    assert not v.kept and v.reason == "reproducer_error"


def test_patch_that_does_not_apply():
    def beh(c, m, n):
        return proof(n) if m == "unpatched" else RunResult(PATCH_FAILED_EXIT, PATCH_FAILED_MARKER + "\n", "error: patch failed", 0.5)

    v = Verifier(ScriptedExecutor(beh), STRICT).verify_one(candidate())
    assert not v.kept and v.reason == "patch_failed_to_apply"


def test_patch_that_breaks_the_build_is_inconclusive_not_fixed():
    def beh(c, m, n):
        return proof(n) if m == "unpatched" else clean(exit_code=1, out="BUILD FAILURE\n")

    v = Verifier(ScriptedExecutor(beh), STRICT).verify_one(candidate())
    assert not v.kept and v.reason == "patched_run_inconclusive"


def test_missing_patch_dropped_under_strict_policy_kept_under_lenient():
    c = candidate(patch="")
    strict = Verifier(ScriptedExecutor(honest), STRICT).verify_one(c)
    assert not strict.kept and strict.reason == "patch_missing" and strict.reproduced
    lenient = Verifier(ScriptedExecutor(honest), LENIENT).verify_one(c)
    assert lenient.kept and lenient.patch_check == "no_patch" and lenient.notes


def test_lenient_policy_still_requires_reproduction():
    v = Verifier(ScriptedExecutor(lambda c, m, n: clean()), LENIENT).verify_one(candidate())
    assert not v.kept and v.reason == "not_reproduced"


def test_lenient_policy_keeps_reproduced_issue_with_bad_patch_and_says_so():
    v = Verifier(ScriptedExecutor(lambda c, m, n: proof(n)), LENIENT).verify_one(candidate())
    assert v.kept and v.patch_check == "not_fixed" and "not_fixed" in v.notes[0]


def test_executor_exception_becomes_infra_error_not_a_crash():
    def boom(c, m, n):
        raise OSError("docker went away")

    v = Verifier(ScriptedExecutor(boom), STRICT).verify_one(candidate())
    assert not v.kept and v.reason == "infra_error" and "docker went away" in v.unpatched["infra_error"]


def test_evidence_is_redacted_and_truncated(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-SECRETSECRETSECRET")

    def beh(c, m, n):
        if m == "unpatched":
            return RunResult(0, "x" * 20000 + "\nkey=sk-ant-api03-SECRETSECRETSECRET\nVULNSCAN-PROOF:" + n + "\n", "", 1)
        return clean()

    v = Verifier(ScriptedExecutor(beh), STRICT).verify_one(candidate())
    assert v.kept
    assert "SECRETSECRET" not in v.unpatched["stdout_tail"]
    assert len(v.unpatched["stdout_tail"]) <= 6000


def test_verify_all_runs_with_bounded_concurrency_and_keeps_order():
    cands = [candidate(title=f"issue {i}") for i in range(5)]
    events = []
    verifier = Verifier(ScriptedExecutor(honest), STRICT, concurrency=2, on_event=lambda k, c, v: events.append(k))
    verdicts = verifier.verify_all(cands)
    assert [v.candidate_id for v in verdicts] == [c.id for c in cands]
    assert all(v.kept for v in verdicts)
    assert events.count("start") == 5 and events.count("done") == 5


def test_decide_requires_a_patched_run_when_there_is_a_patch():
    with pytest.raises(ValueError):
        decide(candidate(), proof("n"), "n", None, None, STRICT)


def test_classifiers():
    assert classify_unpatched(proof("n"), "n") == "reproduced"
    assert classify_patched(clean(), "n") == "fixed"
    assert classify_patched(proof("n"), "n") == "not_fixed"
    assert classify_patched(RunResult(None, "", "", 1, timed_out=True), "n") == "inconclusive"
    # exit 97 without the driver's marker is just a failing reproducer
    assert classify_patched(RunResult(PATCH_FAILED_EXIT, "", "", 1), "n") == "inconclusive"
