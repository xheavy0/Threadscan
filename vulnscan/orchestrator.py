"""The scan pipeline: plan -> build -> scan (fan-out) -> verify (gate) -> report."""

from __future__ import annotations

import json
import os
import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from vulnscan import docker_ops as dk
from vulnscan.candidates import Candidate, dedupe, validate_candidate
from vulnscan.components import Component, select_components, split_components
from vulnscan.config import ProjectConfig, SeedSpec
from vulnscan.prompts import build_task
from vulnscan.repo import changed_files, diff_text, head_commit, list_files, read_repo_file, resolve_repo
from vulnscan.report import Dropped, build_summary, finding_dict, write_outputs
from vulnscan.seeds import Seed, assign_seeds, load_seed_file
from vulnscan.status import StatusTracker, write_json
from vulnscan.verify import Executor, Policy, RunResult, Verifier

PKG_DIR = Path(__file__).resolve().parent
DOCKER_DIR = PKG_DIR.parent / "docker"


@dataclass
class ScanOptions:
    mode: str = "diff"  # diff | full
    base: str | None = None  # defaults to project.yaml diff_base
    max_components: int | None = None
    only: list[str] = field(default_factory=list)
    concurrency: int | None = None
    dry_run: bool = False
    runs_dir: Path = Path("runs")
    cache_dir: Path = Path(".cache")
    extra_seeds: list[SeedSpec] = field(default_factory=list)
    offline: bool = False


class Backend(Protocol):
    def prepare(self, run_dir: Path) -> None: ...
    def scan_component(self, comp: Component, task_dir: Path, out_dir: Path) -> None: ...
    def executor(self, run_dir: Path) -> Executor: ...
    def gateway_stats(self) -> dict | None: ...
    def close(self) -> None: ...


# --------------------------------------------------------------------------- docker


class DockerExecutor:
    """Runs a reproducer in a fresh offline container (``--network none``)."""

    def __init__(self, docker: dk.Docker, image: str, run_dir: Path, cfg: ProjectConfig, run_id: str):
        self.docker, self.image, self.run_dir, self.cfg, self.run_id = docker, image, run_dir, cfg, run_id

    def _prepare(self, c: Candidate) -> Path:
        d = self.run_dir / "verify" / c.id / "in"
        if d.exists():
            shutil.rmtree(d)
        (d / "files").mkdir(parents=True)
        (d / "reproducer.sh").write_text(c.script.replace("\r\n", "\n"), encoding="utf-8", newline="\n")
        (d / "patch.diff").write_text(c.patch.replace("\r\n", "\n"), encoding="utf-8", newline="\n")
        root = (d / "files").resolve()
        for f in c.files:
            dest = (root / f.path).resolve()
            if not dest.is_relative_to(root):  # validate_candidate already refuses these
                raise ValueError(f"unsafe reproducer file path {f.path}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(f.content, encoding="utf-8", newline="\n")
        return d

    def run(self, c: Candidate, mode: str, nonce: str) -> RunResult:
        d = self._prepare(c) if mode == "unpatched" else self.run_dir / "verify" / c.id / "in"
        v = self.cfg.verification
        timeout = min(c.timeout_seconds or v.timeout_seconds, v.timeout_seconds)
        name = f"vulnscan-{self.run_id}-{c.id.lower()}-{mode}"[:120]
        args = dk.verify_run_args(name, self.image, d, mode, nonce, self.cfg.workdir, v.memory, v.cpus)
        p = self.docker.call(args, timeout=timeout + 60, kill_name=name, log=self.run_dir / "verify" / c.id / f"{mode}.log")
        infra = None
        if p.exit_code == 125:
            infra = "docker could not start the container: " + p.stderr.strip()[-500:]
        return RunResult(p.exit_code, p.stdout, p.stderr, p.duration_s, timed_out=p.timed_out, infra_error=infra)


class DockerBackend:
    def __init__(self, cfg: ProjectConfig, repo: Path, run_id: str, agent_sdk_spec: str = "claude-agent-sdk"):
        self.cfg, self.repo, self.run_id = cfg, repo, run_id
        self.docker = dk.Docker()
        self.agent_sdk_spec = agent_sdk_spec
        self.target_image = f"vulnscan/{cfg.name}-target:latest"
        self.scan_image = f"vulnscan/{cfg.name}-scan:latest"
        self.internal_net = f"vulnscan-{run_id}-scan"
        self.egress_net = f"vulnscan-{run_id}-egress"
        self.gateway = f"vulnscan-{run_id}-gw"
        self.run_dir: Path | None = None
        self.containers: list[str] = []
        self.networks: list[str] = []

    def prepare(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        logs = run_dir / "logs"
        # Builds run one at a time and with network on: this is where dependencies are fetched.
        self.docker.check(dk.build_args(self.cfg.dockerfile, self.repo, self.target_image), "target image build", log=logs / "build-target.log")
        user = self.docker.image_user(self.target_image)
        ctx = run_dir / "overlay-context"
        ctx.mkdir(parents=True, exist_ok=True)
        shutil.copy(PKG_DIR / "agent_runner.py", ctx / "agent_runner.py")
        (ctx / "verify_driver.sh").write_text((DOCKER_DIR / "verify_driver.sh").read_text(encoding="utf-8").replace("\r\n", "\n"), encoding="utf-8", newline="\n")
        self.docker.check(
            dk.build_args(DOCKER_DIR / "overlay.Dockerfile", ctx, self.scan_image, {"BASE_IMAGE": self.target_image, "TARGET_USER": user, "AGENT_SDK_SPEC": self.agent_sdk_spec}),
            "scan overlay build",
            log=logs / "build-overlay.log",
        )
        # Networks: the scan network has no route out; the gateway alone bridges to the egress network.
        self.docker.network_create(self.internal_net, internal=True)
        self.networks.append(self.internal_net)
        self.docker.network_create(self.egress_net, internal=False)
        self.networks.append(self.egress_net)
        gw_log = run_dir / "gateway"
        dk.make_writable(gw_log)
        self.docker.check(
            dk.gateway_run_args(self.gateway, self.egress_net, self.cfg.gateway_image, PKG_DIR / "gateway.py", gw_log, self.cfg.scan.max_requests),
            "gateway start",
        )
        self.containers.append(self.gateway)
        self.docker.network_connect(self.internal_net, self.gateway, dk.GATEWAY_ALIAS)

    def scan_component(self, comp: Component, task_dir: Path, out_dir: Path) -> None:
        dk.make_writable(out_dir)
        s = self.cfg.scan
        name = f"vulnscan-{self.run_id}-{comp.slug}"[:120]
        args = dk.scan_run_args(name, self.internal_net, self.scan_image, task_dir, out_dir, s.memory, s.cpus, s.pids_limit)
        p = self.docker.call(args, timeout=s.timeout_minutes * 60, kill_name=name, log=out_dir.parent / "container.log")
        if p.timed_out:
            raise TimeoutError(f"component scan exceeded {s.timeout_minutes} minutes")
        if p.exit_code not in (0, 1):  # 1 = agent_runner wrote an error into candidates.json
            raise RuntimeError(f"scan container exited {p.exit_code}: {p.stderr.strip()[-800:]}")

    def executor(self, run_dir: Path) -> Executor:
        return DockerExecutor(self.docker, self.scan_image, run_dir, self.cfg, self.run_id)

    def gateway_stats(self) -> dict | None:
        if self.run_dir is None:
            return None
        p = self.run_dir / "gateway" / "stats.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None

    def close(self) -> None:
        if self.run_dir is not None and self.gateway in self.containers:
            (self.run_dir / "gateway" / "gateway.log").write_text(self.docker.logs(self.gateway), encoding="utf-8")
        self.docker.cleanup(self.containers, self.networks)


# --------------------------------------------------------------------------- pipeline


def _plan_commands(cfg: ProjectConfig, repo: Path, run_dir: Path, run_id: str, comps: list[Component]) -> dict:
    """The exact docker commands a real run would execute (secrets are never in them)."""
    target, scan = f"vulnscan/{cfg.name}-target:latest", f"vulnscan/{cfg.name}-scan:latest"
    net = f"vulnscan-{run_id}-scan"
    s, v = cfg.scan, cfg.verification
    return {
        "build_target": dk.build_args(cfg.dockerfile, repo, target),
        "build_overlay": dk.build_args(DOCKER_DIR / "overlay.Dockerfile", run_dir / "overlay-context", scan, {"BASE_IMAGE": target, "TARGET_USER": "<from image config>", "AGENT_SDK_SPEC": "claude-agent-sdk"}),
        "networks": [["docker", "network", "create", "--driver", "bridge", "--internal", net], ["docker", "network", "create", "--driver", "bridge", f"vulnscan-{run_id}-egress"]],
        "gateway": dk.gateway_run_args(f"vulnscan-{run_id}-gw", f"vulnscan-{run_id}-egress", cfg.gateway_image, PKG_DIR / "gateway.py", run_dir / "gateway", s.max_requests),
        "scan": [
            dk.scan_run_args(f"vulnscan-{run_id}-{c.slug}", net, scan, run_dir / "components" / c.slug, run_dir / "components" / c.slug / "out", s.memory, s.cpus, s.pids_limit)
            for c in comps
        ],
        "verify_template": dk.verify_run_args(f"vulnscan-{run_id}-<id>-<mode>", scan, run_dir / "verify" / "<id>" / "in", "<unpatched|patched>", "<random nonce>", cfg.workdir, v.memory, v.cpus),
    }


def _component_result(comp: Component, state: str, raw: dict | None, error: str | None) -> dict:
    res = (raw or {}).get("result") or {}
    usage = res.get("usage") or None
    return {
        "name": comp.name,
        "state": state,
        "error": error,
        "cost_usd": res.get("total_cost_usd"),
        "input_tokens": (usage or {}).get("input_tokens") if usage else None,
        "output_tokens": (usage or {}).get("output_tokens") if usage else None,
        "turns": res.get("num_turns"),
        "subtype": res.get("subtype"),
    }


def run_scan(cfg: ProjectConfig, opts: ScanOptions, backend: Backend | None = None, log=print) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_id = f"{stamp}-{cfg.name}"
    run_dir = (opts.runs_dir / run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=False)
    base = opts.base or cfg.diff_base
    status = StatusTracker(run_dir, run_id, cfg.name, opts.mode, base if opts.mode == "diff" else None, opts.dry_run)
    if opts.concurrency:
        cfg.scan.concurrency = opts.concurrency

    try:
        # ---------------------------------------------------------------- plan
        repo = resolve_repo(cfg, opts.cache_dir.resolve(), offline=opts.offline)
        files = list_files(repo)
        comps_all = split_components(files, cfg.components)
        changed = changed_files(repo, base) if opts.mode == "diff" else None
        comps = select_components(comps_all, changed, opts.max_components, opts.only or None)
        log(f"{len(files)} files, {len(comps_all)} components; selected {len(comps)}" + (f" ({len(changed)} files changed since {base})" if changed is not None else ""))

        seeds: list[Seed] = []
        for spec in cfg.seeds + opts.extra_seeds:
            if spec.path.is_file():
                seeds += load_seed_file(spec.tool, spec.path)
            else:
                log(f"warning: seed file {spec.path} not found, skipped")
        seeds_by_comp, _unassigned = assign_seeds(seeds, comps)
        known = read_repo_file(repo, cfg.known_issues) if cfg.known_issues else None

        for c in comps:
            cdir = run_dir / "components" / c.slug
            diff = diff_text(repo, base, c.changed_files) if changed is not None else ""
            write_json(cdir / "task.json", build_task(cfg, c, changed is not None, diff, seeds_by_comp.get(c.name, []), known))
        status.set_components([c.to_dict() for c in comps])
        meta = {
            "run_id": run_id, "project": cfg.name, "mode": opts.mode, "base": base if opts.mode == "diff" else None,
            "commit": head_commit(repo), "model": cfg.scan.model, "dry_run": opts.dry_run,
            "concurrency": cfg.scan.concurrency, "repo": str(repo) if not cfg.repo_is_url else cfg.repo,
        }
        write_json(run_dir / "plan.json", {"meta": meta, "components": [c.to_dict() for c in comps], "seeds": len(seeds), "commands": _plan_commands(cfg, repo, run_dir, run_id, comps)})

        seeds_assigned = sum(len(v) for v in seeds_by_comp.values())
        if opts.dry_run:
            meta["not_exercised"] = [
                "docker build of the target and the scan overlay",
                "the API gateway and the internal scan network",
                "the per-component agents (no API calls, no tokens, no cost)",
                "the verification gate's container runs",
            ]
            results = [_component_result(c, "planned", None, None) for c in comps]
            summary = build_summary(len(comps), results, 0, [], [], len(seeds), seeds_assigned, {}, None)
            write_outputs(run_dir, meta, [], [], summary)
            status.phase("done", "dry run: plan, tasks and an empty report written")
            return run_dir

        # ---------------------------------------------------------------- build
        if backend is None:
            ok, why = dk.Docker.available()
            if not ok:
                raise RuntimeError(f"Docker is required for a real scan ({why}); use --dry-run to plan only")
            if not os.environ.get("ANTHROPIC_API_KEY"):
                raise RuntimeError("ANTHROPIC_API_KEY is not set; export it in this shell (never put it in a file in the repo)")
            backend = DockerBackend(cfg, repo, run_id)
        status.phase("building", "building the target image and the scan overlay")
        try:
            backend.prepare(run_dir)

            # ------------------------------------------------------------ scan
            status.phase("scanning", f"{len(comps)} components, {cfg.scan.concurrency} at a time")
            raw_by_comp: dict[str, dict | None] = {}
            results: list[dict] = []

            def scan_one(c: Component) -> dict:
                cdir = run_dir / "components" / c.slug
                status.component(c.name, state="running", started=time.time())
                raw, err, state = None, None, "done"
                try:
                    backend.scan_component(c, cdir, cdir / "out")
                    out = cdir / "out" / "candidates.json"
                    raw = json.loads(out.read_text(encoding="utf-8")) if out.is_file() else None
                    if raw is None:
                        err, state = "agent wrote no candidates.json", "error"
                    elif raw.get("error"):
                        err, state = raw["error"], "error"
                    elif raw.get("structured") is None:
                        err, state = "agent finished without structured output", "error"
                except Exception as exc:
                    err, state = f"{type(exc).__name__}: {exc}", "error"
                raw_by_comp[c.name] = raw
                n = len(((raw or {}).get("structured") or {}).get("findings") or [])
                r = _component_result(c, state, raw, err)
                status.component(c.name, state=state, finished=time.time(), candidates=n, error=err, cost_usd=r["cost_usd"], turns=r["turns"])
                log(f"[{state}] {c.name}: {n} candidates" + (f" ({err})" if err else ""))
                return r

            with ThreadPoolExecutor(max_workers=cfg.scan.concurrency) as pool:
                results = list(pool.map(scan_one, comps))
            costs = [r["cost_usd"] for r in results if r["cost_usd"] is not None]
            status.cost(round(sum(costs), 4) if costs else None, sum(r["input_tokens"] or 0 for r in results), sum(r["output_tokens"] or 0 for r in results))

            # ------------------------------------------------------------ collect
            dropped: list[Dropped] = []
            cands: list[Candidate] = []
            triage: dict[str, int] = {}
            for c in comps:
                raw = raw_by_comp.get(c.name)
                if raw is None or raw.get("structured") is None:
                    continue
                structured = raw["structured"]
                for t in structured.get("seed_triage") or []:
                    if isinstance(t, dict) and isinstance(t.get("verdict"), str):
                        triage[t["verdict"]] = triage.get(t["verdict"], 0) + 1
                for item in structured.get("findings") or []:
                    cand, errs = validate_candidate(item, c.name)
                    if cand is None:
                        title = item.get("title", "") if isinstance(item, dict) else ""
                        dropped.append(Dropped(c.name, "invalid_candidate", str(title)[:200], None, errs))
                    else:
                        cands.append(cand)
            total_candidates = len(cands) + sum(1 for d in dropped if d.reason == "invalid_candidate")
            cands.sort(key=lambda x: (x.severity != "critical", x.severity != "high", x.component, x.file, x.line))
            cands, dups = dedupe(cands)
            dropped += [Dropped(d.component, "duplicate", d.title, d.id) for d in dups]

            # ------------------------------------------------------------ verify
            status.phase("verifying", f"re-running {len(cands)} reproducers offline")
            status.set_verification([{"id": c.id, "title": c.title, "component": c.component, "severity": c.severity, "state": "queued"} for c in cands])
            status.counts(candidates=total_candidates)

            def on_event(kind, cand, verdict):
                if kind == "start":
                    status.verification(cand.id, state="running")
                else:
                    status.verification(cand.id, state="kept" if verdict.kept else "dropped", reason=verdict.reason, patch_check=verdict.patch_check)

            verifier = Verifier(backend.executor(run_dir), Policy(cfg.verification.require_patch_differential), cfg.verification.concurrency, on_event)
            verdicts = verifier.verify_all(cands)
            findings = []
            for cand, v in zip(cands, verdicts):
                write_json(run_dir / "verify" / cand.id / "verdict.json", v.to_dict())
                if v.kept:
                    findings.append(finding_dict(cand, v))
                else:
                    dropped.append(Dropped(cand.component, v.reason, cand.title, cand.id, v.notes))
            for r in results:
                if r["state"] == "error":
                    dropped.append(Dropped(r["name"], "agent_error", "", None, [r["error"] or ""]))
        finally:
            gw = backend.gateway_stats()
            backend.close()

        # ---------------------------------------------------------------- report
        status.phase("reporting")
        by_reason: dict[str, int] = {}
        for d in dropped:
            by_reason[d.reason] = by_reason.get(d.reason, 0) + 1
        # agent_error rows describe components, not candidates: keep them out of the candidate count.
        cand_dropped = [d for d in dropped if d.reason != "agent_error"]
        summary = build_summary(len(comps), results, total_candidates, findings, cand_dropped, len(seeds), seeds_assigned, triage, gw)
        summary["agent_errors"] = by_reason.get("agent_error", 0)
        write_outputs(run_dir, meta, findings, dropped, summary)
        status.counts(verified=len(findings), dropped=len(cand_dropped), by_reason={k: v for k, v in by_reason.items() if k != "agent_error"})
        status.phase("done", f"{len(findings)} verified, {len(cand_dropped)} dropped")
        return run_dir
    except Exception as exc:
        status.phase("failed", f"{type(exc).__name__}: {exc}")
        raise
