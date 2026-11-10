"""The verification gate.

The agent's own account of its testing is never trusted. For every candidate the
host starts a *fresh* container from the scan image with no network at all and runs
the reproducer itself:

1. **Unpatched run.** The gate generates a random nonce and passes it as
   ``$VULNSCAN_NONCE``. The reproducer must exit 0 and print the line
   ``VULNSCAN-PROOF:<nonce>`` if, and only if, it demonstrated the issue. A new
   nonce per run means output copied from the agent's session cannot pass.
2. **Patched run** (differential check). A second fresh container applies the
   candidate's patch, then runs the same reproducer with a different nonce. It must
   exit 0 *without* the proof line. A reproducer that prints the proof
   unconditionally fails here, so this is what separates a demonstration from an
   ``echo``.

A candidate is kept only if (1) holds and, under the default policy
(``require_patch_differential: true``), (2) holds too. Everything else is dropped
with a reason and counted; it never appears in the report as a finding.
"""

from __future__ import annotations

import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Callable, Protocol

from vulnscan.candidates import PROOF_PREFIX, Candidate
from vulnscan.redact import redact

PATCH_FAILED_EXIT = 97
PATCH_FAILED_MARKER = "VULNSCAN-PATCH-FAILED"

# Drop reasons, in the order the gate can reach them.
DROP_REASONS = {
    "invalid_candidate": "agent output did not meet the candidate schema",
    "duplicate": "same issue as another candidate",
    "infra_error": "the verification container could not be run",
    "timeout": "reproducer timed out",
    "reproducer_error": "reproducer exited non-zero on the unpatched code",
    "not_reproduced": "reproducer ran but did not print the proof line",
    "patch_missing": "no patch, so the differential check could not run",
    "patch_failed_to_apply": "patch did not apply",
    "patch_did_not_fix": "proof line still printed with the patch applied",
    "patched_run_inconclusive": "patched run failed or timed out, so the fix is unproven",
    "agent_error": "the component's agent run failed before reporting",
}


@dataclass
class RunResult:
    exit_code: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    infra_error: str | None = None

    def evidence(self, nonce: str, tail: int = 6000) -> dict:
        out = redact(self.stdout)
        err = redact(self.stderr)
        return {
            "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 2),
            "timed_out": self.timed_out,
            "infra_error": self.infra_error,
            "nonce": nonce,
            "proof_line_seen": has_proof(self.stdout, nonce),
            "stdout_tail": out[-tail:],
            "stderr_tail": err[-tail // 2 :],
        }


@dataclass
class Policy:
    require_patch_differential: bool = True


@dataclass
class Verdict:
    candidate_id: str
    kept: bool
    reason: str  # "verified" or a key of DROP_REASONS
    reproduced: bool
    patch_check: str  # fixed | not_fixed | patch_failed | inconclusive | no_patch | not_run
    unpatched: dict | None = None
    patched: dict | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class Executor(Protocol):
    def run(self, candidate: Candidate, mode: str, nonce: str) -> RunResult:
        """Run the candidate's reproducer; ``mode`` is 'unpatched' or 'patched'."""


def has_proof(stdout: str, nonce: str) -> bool:
    want = f"{PROOF_PREFIX}{nonce}"
    return any(line.strip() == want for line in stdout.splitlines())


def classify_unpatched(r: RunResult, nonce: str) -> str:
    """Return 'reproduced' or a drop reason."""
    if r.infra_error:
        return "infra_error"
    if r.timed_out:
        return "timeout"
    if r.exit_code != 0:
        return "reproducer_error"
    if not has_proof(r.stdout, nonce):
        return "not_reproduced"
    return "reproduced"


def classify_patched(r: RunResult, nonce: str) -> str:
    """Return fixed | not_fixed | patch_failed | inconclusive."""
    if r.infra_error or r.timed_out:
        return "inconclusive"
    if r.exit_code == PATCH_FAILED_EXIT and PATCH_FAILED_MARKER in r.stdout + r.stderr:
        return "patch_failed"
    if has_proof(r.stdout, nonce):
        return "not_fixed"
    if r.exit_code == 0:
        return "fixed"
    return "inconclusive"


_PATCH_DROP = {"not_fixed": "patch_did_not_fix", "patch_failed": "patch_failed_to_apply", "inconclusive": "patched_run_inconclusive"}


def decide(
    cand: Candidate,
    unpatched: RunResult,
    u_nonce: str,
    patched: RunResult | None,
    p_nonce: str | None,
    policy: Policy,
) -> Verdict:
    """Pure decision function: the whole gate policy in one place."""
    u_state = classify_unpatched(unpatched, u_nonce)
    v = Verdict(cand.id, False, u_state, u_state == "reproduced", "not_run", unpatched=unpatched.evidence(u_nonce))
    if u_state != "reproduced":
        return v
    if not cand.patch:
        v.patch_check = "no_patch"
        if policy.require_patch_differential:
            v.reason = "patch_missing"
            return v
        v.kept, v.reason = True, "verified"
        v.notes.append("kept without a differential check (require_patch_differential is off)")
        return v
    if patched is None or p_nonce is None:
        raise ValueError("a candidate with a patch needs a patched run")
    p_state = classify_patched(patched, p_nonce)
    v.patch_check = p_state
    v.patched = patched.evidence(p_nonce)
    if p_state == "fixed":
        v.kept, v.reason = True, "verified"
    elif policy.require_patch_differential:
        v.reason = _PATCH_DROP[p_state]
    else:
        v.kept, v.reason = True, "verified"
        v.notes.append(f"patch check result '{p_state}'; kept because require_patch_differential is off")
    return v


def new_nonce() -> str:
    return secrets.token_hex(16)


class Verifier:
    def __init__(
        self,
        executor: Executor,
        policy: Policy,
        concurrency: int = 1,
        on_event: Callable[[str, Candidate, Verdict | None], None] | None = None,
    ):
        self.executor = executor
        self.policy = policy
        self.concurrency = max(1, concurrency)
        self.on_event = on_event or (lambda *_: None)

    def verify_one(self, cand: Candidate) -> Verdict:
        self.on_event("start", cand, None)
        u_nonce = new_nonce()
        try:
            unpatched = self.executor.run(cand, "unpatched", u_nonce)
        except Exception as exc:  # the gate must never crash the run
            unpatched = RunResult(None, "", "", 0.0, infra_error=f"{type(exc).__name__}: {exc}")
        patched = p_nonce = None
        if classify_unpatched(unpatched, u_nonce) == "reproduced" and cand.patch:
            p_nonce = new_nonce()
            try:
                patched = self.executor.run(cand, "patched", p_nonce)
            except Exception as exc:
                patched = RunResult(None, "", "", 0.0, infra_error=f"{type(exc).__name__}: {exc}")
        verdict = decide(cand, unpatched, u_nonce, patched, p_nonce, self.policy)
        self.on_event("done", cand, verdict)
        return verdict

    def verify_all(self, cands: list[Candidate]) -> list[Verdict]:
        if not cands:
            return []
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            return list(pool.map(self.verify_one, cands))


def timed(fn: Callable[[], tuple[int | None, str, str, bool]]) -> RunResult:
    """Helper for executors: run ``fn`` and wrap its (exit, out, err, timed_out) with timing."""
    start = time.monotonic()
    code, out, err, to = fn()
    return RunResult(code, out, err, time.monotonic() - start, timed_out=to)
