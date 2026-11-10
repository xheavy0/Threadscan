"""``threadscan doctor``: preflight checks, and a cheap end-to-end smoke test with ``--live``.

Static checks need nothing but this machine. ``--live`` exercises every piece a real scan
uses, at the cost of a few cents of usage:

1. the API gateway starts and is reachable from the internal scan network;
2. the internal network has no other way out (a request to the internet must fail);
3. the credential is accepted upstream (``GET /v1/models`` through the gateway);
4. a scan image built with the real overlay runs Claude Code headless through the gateway
   and returns structured output (this is what confirms the subscription token works
   through ``ANTHROPIC_BASE_URL``);
5. the verification driver runs a reproducer with ``--network none`` and the proof line
   comes back, while the network stays unreachable.

Results go to the terminal and to ``runs/doctor-<time>/doctor.json``. Secrets are never
printed: only whether a variable is set and what kind of value it looks like.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from threadscan import docker_ops as dk
from threadscan.candidates import CANDIDATE_SCHEMA
from threadscan.config import ConfigError, ProjectConfig
from threadscan.status import write_json

PKG_DIR = Path(__file__).resolve().parent
DOCKER_DIR = PKG_DIR.parent / "docker"
DOCTOR_IMAGE = "threadscan/doctor-scan:latest"
GIB = 1024 ** 3


@dataclass
class Check:
    name: str
    status: str  # ok | warn | fail | skip
    detail: str = ""
    hint: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "", hint: str = "") -> Check:
        c = Check(name, status, detail, hint)
        self.checks.append(c)
        return c

    @property
    def failed(self) -> bool:
        return any(c.status == "fail" for c in self.checks)

    def to_dict(self) -> dict:
        return {"ok": not self.failed, "checks": [asdict(c) for c in self.checks]}


Runner = Callable[[list[str], float | None], tuple[int | None, str, str]]


def default_runner(args: list[str], timeout: float | None = None) -> tuple[int | None, str, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                           env={**os.environ, "DOCKER_BUILDKIT": "1"})
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return None, "", f"{args[0]}: not found"
    except subprocess.TimeoutExpired:
        return None, "", f"timed out after {timeout}s"


def describe_credential(auth: str, value: str | None) -> tuple[str, str, str]:
    """(status, detail, hint) without ever revealing the value."""
    env = dk.CREDENTIAL_ENV[auth]
    if not value:
        hint = ("run `claude setup-token` and set CLAUDE_CODE_OAUTH_TOKEN in this shell"
                if auth == "subscription" else "set ANTHROPIC_API_KEY in this shell")
        return "fail", f"{env} is not set", hint
    expected = "sk-ant-oat" if auth == "subscription" else "sk-ant-api"
    if not value.startswith(expected):
        return "warn", f"{env} is set but does not look like an {'OAuth token' if auth == 'subscription' else 'API key'} ({len(value)} chars)", \
            f"expected a value starting with {expected}…"
    return "ok", f"{env} is set ({len(value)} chars)", ""


def static_checks(report: Report, cfg: ProjectConfig | None, auth: str, run: Runner = default_runner,
                  env: dict | None = None, cwd: Path | None = None) -> dict:
    """Return facts later steps need (docker_ok)."""
    env = os.environ if env is None else env
    facts = {"docker_ok": False}
    v = sys.version_info
    report.add("Python", "ok" if v >= (3, 10) else "fail", f"{v.major}.{v.minor}.{v.micro}", "Python 3.10 or newer is required")

    code, out, _ = run(["git", "--version"], 20)
    report.add("git", "ok" if code == 0 else "fail", out.strip() or "not found", "" if code == 0 else "install git")

    docker_ready = _docker_checks(report, run, facts)

    free = shutil.disk_usage(cwd or Path.cwd()).free / GIB
    report.add("Free disk", "ok" if free >= 20 else "warn", f"{free:.0f} GiB free here",
               "" if free >= 20 else "images for a Java/Node target need 10–20 GiB")

    st, detail, hint = describe_credential(auth, env.get(dk.CREDENTIAL_ENV[auth]))
    report.add(f"Credential ({auth})", st, detail, hint)

    if cfg is not None:
        repo_ok = cfg.repo_is_url or Path(cfg.repo).is_dir()
        report.add("Target config", "ok", f"{cfg.name}: model {cfg.scan.model}, concurrency {cfg.scan.concurrency}")
        report.add("Target repo", "ok" if repo_ok else "fail", cfg.repo, "" if repo_ok else "fix `repo` in project.yaml or pass --repo")

    if docker_ready and facts["docker_ok"]:
        net = "threadscan-doctor-" + secrets.token_hex(3)
        code, _, err = run(["docker", "network", "create", "--driver", "bridge", "--internal", net], 30)
        run(["docker", "network", "rm", net], 30)
        report.add("Internal network", "ok" if code == 0 else "fail", "created and removed an --internal network" if code == 0 else err.strip()[-200:],
                   "" if code == 0 else "Docker must allow user-defined bridge networks")
        facts["docker_ok"] = code == 0
    return facts


def _docker_checks(report: Report, run: Runner, facts: dict) -> bool:
    code, out, err = run(["docker", "version", "--format", "{{.Server.Version}}"], 30)
    if code is None and "not found" in err:
        report.add("Docker CLI", "fail", "docker is not on PATH", "install Docker Desktop (Windows/macOS) or Docker Engine (Linux)")
        return False
    if code != 0:
        report.add("Docker daemon", "fail", (err.strip().splitlines() or ["not reachable"])[-1][:200], "start Docker Desktop / the docker service")
        return False
    report.add("Docker daemon", "ok", f"server {out.strip()}")
    code, out, _ = run(["docker", "info", "--format", "{{.OSType}}|{{.MemTotal}}|{{.NCPU}}"], 30)
    facts["docker_ok"] = True
    if code == 0 and out.count("|") == 2:
        ostype, mem, ncpu = out.strip().split("|")
        report.add("Docker engine type", "ok" if ostype == "linux" else "fail", ostype,
                   "" if ostype == "linux" else "switch Docker Desktop to Linux containers")
        try:
            mem_gib = int(mem) / GIB
            report.add("Docker memory", "ok" if mem_gib >= 8 else "warn", f"{mem_gib:.1f} GiB, {ncpu} CPUs",
                       "" if mem_gib >= 8 else "scans use up to 6 GiB and verification up to 5 GiB; give Docker 8 GiB or lower scan.memory")
        except ValueError:
            pass
        facts["docker_ok"] = ostype == "linux"
    code, out, _ = run(["docker", "buildx", "version"], 20)
    report.add("BuildKit (buildx)", "ok" if code == 0 else "warn", out.strip()[:80] or "not available",
               "" if code == 0 else "the Dockerfiles use BuildKit syntax; update Docker")
    return True


PROBE = r"""
import json, urllib.request, urllib.error
r = {}
try:
    q = urllib.request.Request("http://threadscan-gw:8080/v1/models", headers={"anthropic-version": "2023-06-01", "x-api-key": "placeholder"})
    with urllib.request.urlopen(q, timeout=30) as resp:
        r["gateway"] = resp.status
except urllib.error.HTTPError as e:
    r["gateway"] = e.code
    r["body"] = e.read(300).decode("utf-8", "replace")
except Exception as e:
    r["gateway"] = "error: " + type(e).__name__ + ": " + str(e)[:120]
try:
    urllib.request.urlopen("https://example.com", timeout=8)
    r["internet"] = "reachable"
except Exception as e:
    r["internet"] = "blocked (" + type(e).__name__ + ")"
print("PROBE " + json.dumps(r))
"""

REPRO = 'if curl -s -m 5 https://example.com >/dev/null 2>&1; then echo NETWORK-REACHABLE; fi\necho "THREADSCAN-PROOF:$THREADSCAN_NONCE"\n'


def doctor_task(model: str) -> dict:
    return {
        "project": "doctor",
        "component": {"name": "doctor", "slug": "doctor"},
        "workdir": "/tmp",
        "model": model,
        "effort": "low",
        "max_turns": 3,
        "max_budget_usd": 0.2,
        "system_prompt": "This is a Threadscan connectivity check, not a security review. Do not use any tools. "
                         "Reply only with the structured output: `findings` and `seed_triage` must be empty lists and `notes` must be exactly doctor-ok.",
        "user_prompt": "Run the connectivity check now.",
        "seed_ids": [],
        "schema": CANDIDATE_SCHEMA,
    }


def parse_probe(stdout: str) -> dict | None:
    for line in stdout.splitlines():
        if line.startswith("PROBE "):
            try:
                return json.loads(line[6:])
            except ValueError:
                return None
    return None


def judge_probe(report: Report, probe: dict | None, auth: str) -> None:
    if probe is None:
        report.add("Gateway from scan network", "fail", "the probe container printed nothing", "see gateway.log in the doctor run directory")
        return
    g = probe.get("gateway")
    if isinstance(g, int):
        report.add("Gateway from scan network", "ok", f"reachable (HTTP {g})")
        if g == 200:
            report.add("Credential accepted upstream", "ok", "GET /v1/models returned 200 through the gateway")
        elif g in (401, 403):
            hint = ("the token may lack access to /v1/models; the agent check below is the one that matters"
                    if auth == "subscription" else "the API key was refused: check it in the Claude Console")
            report.add("Credential accepted upstream", "warn" if auth == "subscription" else "fail", f"HTTP {g}: {probe.get('body', '')[:160]}", hint)
        else:
            report.add("Credential accepted upstream", "warn", f"HTTP {g}: {probe.get('body', '')[:160]}")
    else:
        report.add("Gateway from scan network", "fail", str(g), "the internal network or the gateway alias is broken")
    net = probe.get("internet", "")
    report.add("Scan network isolation", "ok" if net.startswith("blocked") else "fail", f"internet from the scan network: {net}",
               "" if net.startswith("blocked") else "the scan network can reach the internet; do not run scans until this is fixed")


def judge_agent(report: Report, out_dir: Path, gw_stats: dict | None) -> None:
    try:
        data = json.loads((out_dir / "candidates.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None
    if not data:
        report.add("Claude Code through the gateway", "fail", "the agent wrote no output", "see agent container log in the doctor run directory")
    elif data.get("error"):
        report.add("Claude Code through the gateway", "fail", str(data["error"])[:300],
                   "if this is an authentication error in subscription mode, Claude Code may not send its OAuth token to a custom base URL")
    else:
        notes = ((data.get("structured") or {}).get("notes") or "").strip()
        res = data.get("result") or {}
        ok = notes == "doctor-ok" and not res.get("is_error")
        cost = res.get("total_cost_usd")
        report.add("Claude Code through the gateway", "ok" if ok else "warn",
                   f"structured output via {data.get('parse')}, notes={notes!r}, turns={res.get('num_turns')}, cost={'n/a' if cost is None else f'${cost:.4f}'}")
    if gw_stats:
        denied = gw_stats.get("denied_paths") or {}
        report.add("Gateway refusals", "ok" if not denied else "warn",
                   "none" if not denied else ", ".join(f"{k} ×{v}" for k, v in denied.items()),
                   "" if not denied else "Claude Code asked for paths the gateway does not allow; add them only if they are needed and safe")


def judge_verify(report: Report, stdout: str, nonce: str) -> None:
    proof = any(line.strip() == f"THREADSCAN-PROOF:{nonce}" for line in stdout.splitlines())
    leaked = "NETWORK-REACHABLE" in stdout
    report.add("Verification driver", "ok" if proof else "fail", "proof line returned from a --network none container" if proof else "no proof line")
    report.add("Verification isolation", "fail" if leaked else "ok", "the reproducer reached the internet" if leaked else "no network inside the verification container")


def live_checks(report: Report, cfg: ProjectConfig | None, auth: str, model: str, run_dir: Path, run: Runner = default_runner) -> None:
    gw_image = cfg.gateway_image if cfg else "python:3.13-slim"
    tag = secrets.token_hex(3)
    internal, egress, gw = f"threadscan-doctor-{tag}-scan", f"threadscan-doctor-{tag}-egress", f"threadscan-doctor-{tag}-gw"
    containers, networks = [], []
    try:
        code, _, err = run(["docker", "image", "inspect", gw_image], 30)
        if code != 0:
            code, _, err = run(["docker", "pull", gw_image], 600)
        if code != 0:
            report.add("Gateway image", "fail", err.strip()[-200:], f"docker pull {gw_image}")
            return
        report.add("Gateway image", "ok", gw_image)
        for net, internal_flag in ((internal, True), (egress, False)):
            code, _, err = run(["docker", "network", "create", "--driver", "bridge", *(["--internal"] if internal_flag else []), net], 30)
            if code != 0:
                report.add("Networks", "fail", err.strip()[-200:])
                return
            networks.append(net)
        gw_log = run_dir / "gateway"
        dk.make_writable(gw_log)
        code, _, err = run(dk.gateway_run_args(gw, egress, gw_image, PKG_DIR / "gateway.py", gw_log, 50, auth), 60)
        if code != 0:
            report.add("Gateway start", "fail", err.strip()[-300:])
            return
        containers.append(gw)
        run(["docker", "network", "connect", "--alias", dk.GATEWAY_ALIAS, internal, gw], 30)
        time.sleep(2)
        report.add("Gateway start", "ok", f"listening as {dk.GATEWAY_ALIAS} on the scan network ({auth})")

        code, out, err = run(["docker", "run", "--rm", "--network", internal, *dk.HARDENING, gw_image, "python", "-c", PROBE], 90)
        judge_probe(report, parse_probe(out), auth)

        ctx = run_dir / "overlay-context"
        ctx.mkdir(parents=True, exist_ok=True)
        shutil.copy(PKG_DIR / "agent_runner.py", ctx / "agent_runner.py")
        (ctx / "verify_driver.sh").write_text((DOCKER_DIR / "verify_driver.sh").read_text(encoding="utf-8").replace("\r\n", "\n"), encoding="utf-8", newline="\n")
        code, out, err = run(dk.build_args(DOCKER_DIR / "overlay.Dockerfile", ctx, DOCTOR_IMAGE, {"BASE_IMAGE": gw_image, "TARGET_USER": "root"}), 1200)
        (run_dir / "overlay-build.log").write_text(out + "\n" + err, encoding="utf-8")
        if code != 0:
            report.add("Scan overlay build", "fail", (err.strip().splitlines() or ["?"])[-1][:300], "see overlay-build.log in the doctor run directory")
            return
        report.add("Scan overlay build", "ok", f"{DOCTOR_IMAGE} (Python, Claude Agent SDK, driver)")

        task_dir, out_dir = run_dir / "agent", run_dir / "agent" / "out"
        write_json(task_dir / "task.json", doctor_task(model))
        dk.make_writable(out_dir)
        code, out, err = run(dk.scan_run_args(f"threadscan-doctor-{tag}-agent", internal, DOCTOR_IMAGE, task_dir, out_dir, "2g", 1.0, 512, auth), 600)
        (run_dir / "agent-container.log").write_text(out + "\n" + err, encoding="utf-8")
        stats = None
        try:
            stats = json.loads((gw_log / "stats.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        judge_agent(report, out_dir, stats)

        cand = run_dir / "verify" / "in"
        (cand / "files").mkdir(parents=True, exist_ok=True)
        (cand / "reproducer.sh").write_text(REPRO, encoding="utf-8", newline="\n")
        (cand / "patch.diff").write_text("", encoding="utf-8")
        nonce = secrets.token_hex(16)
        code, out, err = run(dk.verify_run_args(f"threadscan-doctor-{tag}-verify", DOCTOR_IMAGE, cand, "unpatched", nonce, "/tmp", "1g", 1.0), 120)
        judge_verify(report, out, nonce)
    finally:
        if containers:
            _, logs_out, logs_err = run(["docker", "logs", gw], 30)
            (run_dir / "gateway" / "gateway.log").write_text(logs_out + logs_err, encoding="utf-8")
        for c in containers:
            run(["docker", "rm", "-f", c], 30)
        for n in networks:
            run(["docker", "network", "rm", n], 30)


SYMBOL = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL", "skip": "SKIP"}


def render(report: Report) -> str:
    lines = []
    for c in report.checks:
        lines.append(f"[{SYMBOL[c.status]}] {c.name}: {c.detail}")
        if c.hint and c.status != "ok":
            lines.append(f"       -> {c.hint}")
    lines.append("")
    lines.append("All checks passed." if not report.failed else "Some checks failed: fix the FAIL lines before scanning.")
    return "\n".join(lines)


def run_doctor(cfg: ProjectConfig | None, auth: str, live: bool, model: str, runs_dir: Path, run: Runner = default_runner) -> tuple[Report, Path]:
    report = Report()
    run_dir = (runs_dir / time.strftime("doctor-%Y%m%d-%H%M%S")).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    facts = static_checks(report, cfg, auth, run)
    if live:
        cred_ok = not any(c.name.startswith("Credential") and c.status == "fail" for c in report.checks)
        if not facts["docker_ok"]:
            report.add("Live checks", "skip", "Docker is not ready")
        elif not cred_ok:
            report.add("Live checks", "skip", "no credential for the chosen auth mode")
        else:
            live_checks(report, cfg, auth, model, run_dir, run)
    write_json(run_dir / "doctor.json", {"auth": auth, "live": live, "model": model, **report.to_dict()})
    return report, run_dir


__all__ = ["Check", "Report", "run_doctor", "render", "static_checks", "describe_credential", "judge_probe", "judge_agent",
           "judge_verify", "parse_probe", "doctor_task", "ConfigError"]
