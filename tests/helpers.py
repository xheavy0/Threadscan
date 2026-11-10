from threadscan.candidates import validate_candidate
from threadscan.verify import RunResult

PATCH = """--- a/app/Login.java
+++ b/app/Login.java
@@ -1 +1 @@
-class Login { boolean check() { return true; } }
+class Login { boolean check() { return verify(); } }
"""

SCRIPT = """set -e
out=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:4000/api/admin)
if [ "$out" = 200 ]; then echo "THREADSCAN-PROOF:$THREADSCAN_NONCE"; fi
"""


def raw_candidate(**over):
    raw = {
        "title": "Admin API reachable without a session",
        "severity": "critical",
        "severity_rationale": "auth bypass is Critical per threat model",
        "cwe": "CWE-306",
        "file": "app/Login.java",
        "line": 1,
        "description": "check() always returns true.",
        "impact": "Anyone can call admin endpoints.",
        "reproducer": {"script": SCRIPT, "files": [{"path": "app/LoginTest.java", "content": "class LoginTest {}"}], "timeout_seconds": 60},
        "patch": PATCH,
        "self_test": "ran it, saw 200",
        "seed_ids": ["codeql-abc"],
    }
    raw.update(over)
    return raw


def candidate(component="auth", **over):
    c, errs = validate_candidate(raw_candidate(**over), component)
    assert c is not None, errs
    return c


def proof(nonce: str, exit_code: int = 0, extra: str = "") -> RunResult:
    return RunResult(exit_code, f"building...\n{extra}THREADSCAN-PROOF:{nonce}\n", "", 1.0)


def clean(exit_code: int = 0, out: str = "tests passed\n") -> RunResult:
    return RunResult(exit_code, out, "", 1.0)


class ScriptedExecutor:
    """Fake executor: ``behaviour(candidate, mode, nonce) -> RunResult``."""

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.calls = []

    def run(self, cand, mode, nonce):
        self.calls.append((cand.id, mode, nonce))
        return self.behaviour(cand, mode, nonce)
