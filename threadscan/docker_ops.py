"""Docker plumbing. Argument lists are built by pure functions (``*_args``) so the
dry run can print them and tests can assert the isolation flags; ``Docker`` runs them.

Network layout of a scan (one run):

    [scan container] --(internal network, no route out)--> [gateway] --(egress network)--> api.anthropic.com:443

* The scan container sits only on an ``--internal`` network. It holds a placeholder
  API key and talks plain HTTP to the gateway by name.
* The gateway (``gateway.py``) holds the real key, accepts only the Anthropic
  Messages API paths and forwards them over TLS to a fixed upstream. It is on its own
  per-run bridge network, not Docker's default bridge, and publishes no host port.
* Verification containers get ``--network none``: no gateway, no API, nothing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

GATEWAY_ALIAS = "threadscan-gw"
GATEWAY_PORT = 8080
PLACEHOLDER_KEY = "sk-placeholder-the-gateway-injects-the-real-key"
IN_DIR = "/threadscan/in"
OUT_DIR = "/threadscan/out"
AGENT_PY = "/opt/threadscan/venv/bin/python"
AGENT_RUNNER = "/opt/threadscan/agent_runner.py"
VERIFY_DRIVER = "/opt/threadscan/verify_driver.sh"

HARDENING = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
# Claude Code: no telemetry, no auto-update, no error reporting; only the API calls.
AGENT_ENV = {
    "ANTHROPIC_BASE_URL": f"http://{GATEWAY_ALIAS}:{GATEWAY_PORT}",
    "ANTHROPIC_API_KEY": PLACEHOLDER_KEY,
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_AUTOUPDATER": "1",
    "DISABLE_BUG_COMMAND": "1",
}


def _mount(src: Path | str, dst: str, readonly: bool) -> list[str]:
    spec = f"type=bind,src={src},dst={dst}"
    return ["--mount", spec + (",readonly" if readonly else "")]


def _env(env: dict[str, str]) -> list[str]:
    out = []
    for k, v in env.items():
        out += ["-e", f"{k}={v}"]
    return out


def build_args(dockerfile: Path, context: Path, tag: str, build_args: dict[str, str] | None = None) -> list[str]:
    args = ["docker", "build", "--progress=plain", "-f", str(dockerfile), "-t", tag]
    for k, v in (build_args or {}).items():
        args += ["--build-arg", f"{k}={v}"]
    return args + [str(context)]


def gateway_run_args(name: str, network: str, image: str, gateway_py: Path, log_dir: Path, max_requests: int) -> list[str]:
    return [
        "docker", "run", "-d", "--rm", "--name", name, "--network", network,
        *HARDENING, "--read-only", "--pids-limit", "128", "--memory", "256m", "--user", "65534:65534",
        # No value: docker copies ANTHROPIC_API_KEY from this process's environment,
        # so the key never appears on a command line or in the dry-run plan.
        "-e", "ANTHROPIC_API_KEY",
        *_mount(gateway_py, "/gw/gateway.py", True),
        *_mount(log_dir, "/gw/log", False),
        image, "python", "-u", "/gw/gateway.py",
        "--listen", f"0.0.0.0:{GATEWAY_PORT}", "--stats", "/gw/log/stats.json", "--max-requests", str(max_requests),
    ]


def scan_run_args(
    name: str, network: str, image: str, task_dir: Path, out_dir: Path, memory: str, cpus: float, pids: int
) -> list[str]:
    return [
        "docker", "run", "--rm", "--name", name, "--network", network,
        *HARDENING, "--pids-limit", str(pids), "--memory", memory, "--cpus", str(cpus),
        *_env(AGENT_ENV),
        *_mount(task_dir, IN_DIR, True),
        *_mount(out_dir, OUT_DIR, False),
        image, AGENT_PY, AGENT_RUNNER, f"{IN_DIR}/task.json", OUT_DIR,
    ]


def verify_run_args(
    name: str, image: str, cand_dir: Path, mode: str, nonce: str, workdir: str, memory: str, cpus: float
) -> list[str]:
    return [
        "docker", "run", "--rm", "--name", name, "--network", "none",
        *HARDENING, "--pids-limit", "2048", "--memory", memory, "--cpus", str(cpus),
        "-e", f"THREADSCAN_NONCE={nonce}", "-e", f"THREADSCAN_MODE={mode}", "-e", f"THREADSCAN_WORKDIR={workdir}",
        *_mount(cand_dir, IN_DIR, True),
        "--entrypoint", "/bin/sh",
        image, VERIFY_DRIVER,
    ]


@dataclass
class Proc:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float


class DockerError(RuntimeError):
    pass


class Docker:
    def __init__(self, exe: str = "docker"):
        self.exe = exe

    @staticmethod
    def available() -> tuple[bool, str]:
        if not shutil.which("docker"):
            return False, "docker CLI not found on PATH"
        p = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True)
        if p.returncode != 0:
            return False, "docker daemon not reachable: " + (p.stderr.strip().splitlines() or ["?"])[-1]
        return True, f"docker server {p.stdout.strip()}"

    def call(self, args: list[str], timeout: float | None = None, kill_name: str | None = None, log: Path | None = None) -> Proc:
        start = time.monotonic()
        env = {**os.environ, "DOCKER_BUILDKIT": "1"}
        try:
            p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, env=env)
            proc = Proc(p.returncode, p.stdout, p.stderr, False, time.monotonic() - start)
        except subprocess.TimeoutExpired as exc:
            if kill_name:
                subprocess.run(["docker", "kill", kill_name], capture_output=True)
            out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            proc = Proc(None, out, err, True, time.monotonic() - start)
        if log is not None:
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(f"$ {' '.join(args)}\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n", encoding="utf-8")
        return proc

    def check(self, args: list[str], what: str, **kw) -> Proc:
        p = self.call(args, **kw)
        if p.exit_code != 0:
            raise DockerError(f"{what} failed (exit {p.exit_code}): {p.stderr.strip()[-2000:]}")
        return p

    def image_user(self, tag: str) -> str:
        p = self.check(["docker", "image", "inspect", "-f", "{{.Config.User}}", tag], "image inspect")
        return p.stdout.strip() or "root"

    def network_create(self, name: str, internal: bool) -> None:
        args = ["docker", "network", "create", "--driver", "bridge"]
        if internal:
            args.append("--internal")
        self.check(args + [name], f"network create {name}")

    def network_connect(self, network: str, container: str, alias: str) -> None:
        self.check(["docker", "network", "connect", "--alias", alias, network, container], "network connect")

    def cleanup(self, containers: list[str], networks: list[str]) -> None:
        for c in containers:
            subprocess.run(["docker", "rm", "-f", c], capture_output=True)
        for n in networks:
            subprocess.run(["docker", "network", "rm", n], capture_output=True)

    def logs(self, container: str) -> str:
        p = self.call(["docker", "logs", container])
        return p.stdout + p.stderr


def make_writable(path: Path) -> None:
    """Bind-mounted output dirs must be writable by the container's (non-root) user on Linux hosts."""
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(path, 0o777)
