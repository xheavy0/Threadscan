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

from threadscan import docker_ops as dk
from threadscan.candidates import Candidate, dedupe, validate_candidate
from threadscan.components import Component, select_components, split_components
from threadscan.config import ProjectConfig, SeedSpec
from threadscan.prompts import build_task
from threadscan.repo import changed_files, diff_text, head_commit, list_files, read_repo_file, resolve_repo
from threadscan.report import Dropped, build_summary, finding_dict, write_outputs
from threadscan.seeds import Seed, assign_seeds, load_seed_file
from threadscan.status import StatusTracker, write_json
from threadscan import history
from threadscan.exporters import write_exports
from threadscan.triage import TriageStore
from threadscan.verify import DROP_REASONS, Executor, Policy, RunResult, Verdict, Verifier, classify_unpatched, new_nonce

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
    auth: str | None = None  # overrides project.yaml scan.auth
    allow_full: bool = False  # a full scan on a subscription needs this


class Backend(Protocol):
    def prepare(self, run_dir: Path) -> None: ...
    def scan_component(self, comp: Component, task_dir: Path, out_dir: Path) -> None: ...
    def executor(self, run_dir: Path) -> Executor: ...
    def gateway_stats(self) -> dict | None: ...
    def close(self) -> None: ...
    # Optional: True once the API answered 429 (with a subscription: the plan's usage limit).
    # def limit_reached(self) -> bool: ...


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
        name = f"threadscan-{self.run_id}-{c.id.lower()}-{mode}"[:120]
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
        self.target_image = f"threadscan/{cfg.name}-target:latest"
        self.scan_image = f"threadscan/{cfg.name}-scan:latest"
        self.internal_net = f"threadscan-{run_id}-scan"
        self.egress_net = f"threadscan-{run_id}-egress"
        self.gateway = f"threadscan-{run_id}-gw"
        self.run_dir: Path | None = None
        self.containers: list[str] = []
        self.networks: list[str] = []

    def prepare(self, run_dir: Path) -> None:
        self.build_images(run_dir)
        self.start_gateway(run_dir)

    def build_images(self, run_dir: Path) -> None:
        """Target image from the current code, then the scan overlay. Network on, one at a time."""
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

    def start_gateway(self, run_dir: Path) -> None:
        # Networks: the scan network has no route out; the gateway alone bridges to the egress network.
        self.docker.network_create(self.internal_net, internal=True)
        self.networks.append(self.internal_net)
        self.docker.network_create(self.egress_net, internal=False)
        self.networks.append(self.egress_net)
        gw_log = run_dir / "gateway"
        dk.make_writable(gw_log)
        self.docker.check(
            dk.gateway_run_args(self.gateway, self.egress_net, self.cfg.gateway_image, PKG_DIR / "gateway.py", gw_log, self.cfg.scan.max_requests, self.cfg.scan.auth),
            "gateway start",
        )
        self.containers.append(self.gateway)
        self.docker.network_connect(self.internal_net, self.gateway, dk.GATEWAY_ALIAS)

    def scan_component(self, comp: Component, task_dir: Path, out_dir: Path) -> None:
        dk.make_writable(out_dir)
        s = self.cfg.scan
        name = f"threadscan-{self.run_id}-{comp.slug}"[:120]
        args = dk.scan_run_args(name, self.internal_net, self.scan_image, task_dir, out_dir, s.memory, s.cpus, s.pids_limit, s.auth)
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
        try:
            return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None
        except ValueError:  # caught mid-write; the next read sees it
            return None

    def limit_reached(self) -> bool:
        stats = self.gateway_stats()
        return bool(stats and stats.get("limit_hit_at"))

    def close(self) -> None:
        if self.run_dir is not None and self.gateway in self.containers:
            (self.run_dir / "gateway" / "gateway.log").write_text(self.docker.logs(self.gateway), encoding="utf-8")
        self.docker.cleanup(self.containers, self.networks)


# --------------------------------------------------------------------------- pipeline


def _plan_commands(cfg: ProjectConfig, repo: Path, run_dir: Path, run_id: str, comps: list[Component]) -> dict:
    """The exact docker commands a real run would execute (secrets are never in them)."""
    target, scan = f"threadscan/{cfg.name}-target:latest", f"threadscan/{cfg.name}-scan:latest"
    net = f"threadscan-{run_id}-scan"
    s, v = cfg.scan, cfg.verification
    return {
        "build_target": dk.build_args(cfg.dockerfile, repo, target),
        "build_overlay": dk.build_args(DOCKER_DIR / "overlay.Dockerfile", run_dir / "overlay-context", scan, {"BASE_IMAGE": target, "TARGET_USER": "<from image config>", "AGENT_SDK_SPEC": "claude-agent-sdk"}),
        "networks": [["docker", "network", "create", "--driver", "bridge", "--internal", net], ["docker", "network", "create", "--driver", "bridge", f"threadscan-{run_id}-egress"]],
        "gateway": dk.gateway_run_args(f"threadscan-{run_id}-gw", f"threadscan-{run_id}-egress", cfg.gateway_image, PKG_DIR / "gateway.py", run_dir / "gateway", s.max_requests, s.auth),
        "scan": [
            dk.scan_run_args(f"threadscan-{run_id}-{c.slug}", net, scan, run_dir / "components" / c.slug, run_dir / "components" / c.slug / "out", s.memory, s.cpus, s.pids_limit, s.auth)
            for c in comps
        ],
        "verify_template": dk.verify_run_args(f"threadscan-{run_id}-<id>-<mode>", scan, run_dir / "verify" / "<id>" / "in", "<unpatched|patched>", "<random nonce>", cfg.workdir, v.memory, v.cpus),
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


CREDENTIAL_HELP = {
    "api_key": "ANTHROPIC_API_KEY is not set; export it in this shell (never put it in a file in the repo)",
    "subscription": "CLAUDE_CODE_OAUTH_TOKEN is not set; run `claude setup-token` and set the token in this shell "
    "(never put it in a file in the repo)",
}


def resume_command(cfg: ProjectConfig, mode: str, base: str | None, names: list[str]) -> str:
    sel = "--full" if mode == "full" else f"--since {base}"
    only = " ".join(f'--only "{n}"' for n in names)
    return f'threadscan scan "{cfg.target_dir}" {sel} {only}'.strip()


def check_full_scan_guard(cfg: ProjectConfig, opts: ScanOptions) -> None:
    """On a subscription, an unbounded full scan would drain the plan's limits: require intent."""
    if cfg.scan.auth == "subscription" and opts.mode == "full" and not opts.dry_run:
        if not (opts.max_components or opts.only or opts.allow_full):
            raise RuntimeError(
                "a full scan on a subscription can use up its 5-hour and weekly limits; "
                "pass --max-components N or --only NAME, or --allow-full if you mean it"
            )


def lifecycle_phase(
    cfg: ProjectConfig, runs_dir: Path, run_id: str, run_dir: Path, findings: list[dict], results: list[dict], executor_factory, status, log
) -> dict:
    """Compare with the previous completed run. Never infer "resolved" from absence: re-run the
    old reproducer on the current code first (see threadscan/history.py)."""
    prev = history.previous_run(runs_dir, cfg.name, run_id)
    if prev is None:
        lc = {"previous_run": None, "new": [f["id"] for f in findings], "existing": {}, "resolved": [],
              "still_present": [], "unverified": [], "not_rescanned": []}
        write_json(run_dir / "lifecycle.json", lc)
        return lc
    scanned = {r["name"] for r in results if r["state"] == "done"}
    lp = history.plan(prev["run_id"], prev["findings"], findings, scanned)
    resolved, still, unverified = [], [], []
    if lp.recheck:
        status.phase("verifying", f"re-checking {len(lp.recheck)} issues from {prev['run_id']} that were not reported again")
        executor = executor_factory()
        for f in lp.recheck:
            try:
                cand = history.candidate_from_finding(f)
            except (KeyError, TypeError):
                unverified.append({**history.brief(f), "reason": "the previous finding record is incomplete"})
                continue
            nonce = new_nonce()
            try:
                rr = executor.run(cand, "unpatched", nonce)
            except Exception as exc:  # a re-check must never crash the run
                rr = RunResult(None, "", "", 0.0, infra_error=f"{type(exc).__name__}: {exc}")
            state = classify_unpatched(rr, nonce)
            ev = rr.evidence(nonce)
            if state == "reproduced":
                note = f"carried over from {prev['run_id']}: not reported again by the agent, but its reproducer still demonstrates the issue"
                v = Verdict(cand.id, True, "verified", True, "not_rerun", unpatched=ev, notes=[note])
                fd = finding_dict(cand, v)
                fd["verification"]["status"] = "re-verified"
                fd["carried_over_from"] = prev["run_id"]
                findings.append(fd)
                still.append(cand.id)
                log(f"[still present] {cand.title}")
            elif state == "not_reproduced":
                resolved.append({**history.brief(f), "evidence": ev})
                log(f"[resolved] {f['title']}")
            else:
                unverified.append({**history.brief(f), "reason": DROP_REASONS.get(state, state), "evidence": ev})
    lc = {
        "previous_run": prev["run_id"], "new": lp.new, "existing": lp.matches, "resolved": resolved,
        "still_present": still, "unverified": unverified, "not_rescanned": [history.brief(f) for f in lp.not_rescanned],
    }
    write_json(run_dir / "lifecycle.json", lc)
    return lc


def policy_snapshot(cfg: ProjectConfig) -> dict:
    """What this run was told: shown read-only on the dashboard's Policies view."""
    s, v = cfg.scan, cfg.verification
    return {
        "threat_model": cfg.threat_model_text,
        "threat_model_path": str(cfg.threat_model) if cfg.threat_model else None,
        "known_issues": cfg.known_issues,
        "diff_base": cfg.diff_base,
        "workdir": cfg.workdir,
        "scan": {"auth": s.auth, "model": s.model, "effort": s.effort, "concurrency": s.concurrency, "max_turns": s.max_turns,
                 "max_budget_usd": s.max_budget_usd, "timeout_minutes": s.timeout_minutes, "memory": s.memory, "cpus": s.cpus,
                 "max_requests": s.max_requests},
        "verification": {"require_patch_differential": v.require_patch_differential, "timeout_seconds": v.timeout_seconds,
                         "concurrency": v.concurrency, "memory": v.memory, "cpus": v.cpus},
        "components": {"explicit": [{"name": e.name, "priority": e.priority, "paths": e.paths} for e in cfg.components.explicit],
                       "auto": [{"root": a.root, "depth": a.depth} for a in cfg.components.auto], "exclude_count": len(cfg.components.exclude)},
        "seeds": [{"tool": sp.tool, "path": str(sp.path)} for sp in cfg.seeds],
    }


def lifecycle_counts(lc: dict | None) -> dict | None:
    if not lc:
        return None
    return {"previous_run": lc.get("previous_run"), **{k: len(lc.get(k) or []) for k in ("new", "existing", "resolved", "still_present", "unverified", "not_rescanned")}}


def run_scan(cfg: ProjectConfig, opts: ScanOptions, backend: Backend | None = None, log=print) -> Path:
    if opts.auth:
        cfg.scan.auth = opts.auth
        if opts.auth == "subscription" and not cfg.scan.concurrency_explicit:
            cfg.scan.concurrency = 1
    if opts.concurrency:
        cfg.scan.concurrency = opts.concurrency
    check_full_scan_guard(cfg, opts)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_id = f"{stamp}-{cfg.name}"
    run_dir = (opts.runs_dir / run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=False)
    base = opts.base or cfg.diff_base
    status = StatusTracker(run_dir, run_id, cfg.name, opts.mode, base if opts.mode == "diff" else None, opts.dry_run, cfg.scan.auth)

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
        seeds_by_comp, unassigned_seeds = assign_seeds(seeds, comps)
        seed_component = {s.id: name for name, lst in seeds_by_comp.items() for s in lst}

        def write_seeds(verdicts: dict) -> None:
            """Seeds with the component they were given to and the agent's verdict (if any)."""
            rows = [{**s.to_dict(), "component": seed_component.get(s.id), "verdict": (verdicts.get(s.id) or {}).get("verdict"),
                     "reason": (verdicts.get(s.id) or {}).get("reason")} for s in seeds]
            write_json(run_dir / "seeds.json", {"seeds": rows, "unassigned": len(unassigned_seeds)})
        known = read_repo_file(repo, cfg.known_issues) if cfg.known_issues else None

        for c in comps:
            cdir = run_dir / "components" / c.slug
            diff = diff_text(repo, base, c.changed_files) if changed is not None else ""
            write_json(cdir / "task.json", build_task(cfg, c, changed is not None, diff, seeds_by_comp.get(c.name, []), known))
        status.set_components([c.to_dict() for c in comps])
        meta = {
            "run_id": run_id, "project": cfg.name, "mode": opts.mode, "base": base if opts.mode == "diff" else None,
            "commit": head_commit(repo), "model": cfg.scan.model, "dry_run": opts.dry_run, "auth": cfg.scan.auth,
            "concurrency": cfg.scan.concurrency, "repo": str(repo) if not cfg.repo_is_url else cfg.repo,
        }
        write_json(run_dir / "plan.json", {"meta": meta, "policy": policy_snapshot(cfg), "components": [c.to_dict() for c in comps], "seeds": len(seeds),
                                           "commands": _plan_commands(cfg, repo, run_dir, run_id, comps)})
        write_seeds({})

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
            write_exports(run_dir)
            status.phase("done", "dry run: plan, tasks and an empty report written")
            return run_dir

        # ---------------------------------------------------------------- build
        if backend is None:
            if not os.environ.get(dk.CREDENTIAL_ENV[cfg.scan.auth]):
                raise RuntimeError(CREDENTIAL_HELP[cfg.scan.auth])
            ok, why = dk.Docker.available()
            if not ok:
                raise RuntimeError(f"Docker is required for a real scan ({why}); use --dry-run to plan only")
            backend = DockerBackend(cfg, repo, run_id)
        status.phase("building", "building the target image and the scan overlay")
        try:
            backend.prepare(run_dir)

            # ------------------------------------------------------------ scan
            status.phase("scanning", f"{len(comps)} components, {cfg.scan.concurrency} at a time")
            raw_by_comp: dict[str, dict | None] = {}
            results: list[dict] = []

            def limit_hit() -> bool:
                if cfg.scan.auth != "subscription":
                    return False
                probe = getattr(backend, "limit_reached", None)
                return bool(probe and probe())

            def scan_one(c: Component) -> dict:
                cdir = run_dir / "components" / c.slug
                if limit_hit():
                    err = "not started: the subscription's usage limit was reached"
                    status.component(c.name, state="skipped", error=err)
                    log(f"[skipped] {c.name}: usage limit reached")
                    return _component_result(c, "skipped", None, err)
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
                if state == "error" and limit_hit():
                    err = f"usage limit reached during this component ({err})"
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
            seed_verdicts: dict[str, dict] = {}
            for c in comps:
                raw = raw_by_comp.get(c.name)
                if raw is None or raw.get("structured") is None:
                    continue
                structured = raw["structured"]
                for t in structured.get("seed_triage") or []:
                    if isinstance(t, dict) and isinstance(t.get("verdict"), str):
                        triage[t["verdict"]] = triage.get(t["verdict"], 0) + 1
                        if isinstance(t.get("seed_id"), str) and seed_component.get(t["seed_id"]) == c.name:
                            seed_verdicts[t["seed_id"]] = {"verdict": t["verdict"], "reason": str(t.get("reason", ""))[:500]}
                for item in structured.get("findings") or []:
                    cand, errs = validate_candidate(item, c.name)
                    if cand is None:
                        title = item.get("title", "") if isinstance(item, dict) else ""
                        dropped.append(Dropped(c.name, "invalid_candidate", str(title)[:200], None, errs))
                    else:
                        cands.append(cand)
            write_seeds(seed_verdicts)
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
            skipped = [r["name"] for r in results if r["state"] == "skipped"]
            lifecycle = lifecycle_phase(cfg, opts.runs_dir.resolve(), run_id, run_dir, findings, results, lambda: backend.executor(run_dir), status, log)
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
        summary["components_skipped"] = skipped
        summary["lifecycle"] = lifecycle_counts(lifecycle)
        summary["limit_reached"] = bool(skipped) or bool(gw and gw.get("limit_hit_at"))
        if skipped:
            summary["resume_command"] = resume_command(cfg, opts.mode, base, skipped)
        write_outputs(run_dir, meta, findings, dropped, summary, lifecycle)
        write_exports(run_dir, TriageStore(opts.runs_dir.resolve() / "triage.json").load())
        status.counts(verified=len(findings), dropped=len(cand_dropped), by_reason={k: v for k, v in by_reason.items() if k != "agent_error"})
        done_msg = f"{len(findings)} verified, {len(cand_dropped)} dropped"
        if skipped:
            done_msg += f"; usage limit reached, {len(skipped)} components not scanned (resume command in the report)"
            log("usage limit reached; resume later with:\n  " + summary["resume_command"])
        status.phase("done", done_msg)
        return run_dir
    except Exception as exc:
        status.phase("failed", f"{type(exc).__name__}: {exc}")
        raise
