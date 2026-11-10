"""Command line: ``threadscan validate | components | scan | dashboard``."""

from __future__ import annotations

import argparse
import sys
import threading
from pathlib import Path

from threadscan.config import AUTH_MODES, SEED_TOOLS, ConfigError, SeedSpec, load_project


def _seed_arg(value: str) -> SeedSpec:
    tool, sep, path = value.partition("=")
    if not sep or tool not in SEED_TOOLS or not path:
        raise argparse.ArgumentTypeError(f"use TOOL=PATH with TOOL one of {', '.join(SEED_TOOLS)}")
    return SeedSpec(tool, Path(path).resolve())


def _add_target_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("target", type=Path, help="target config dir, e.g. targets/aegis")
    p.add_argument("--repo", help="override project.yaml repo (local path or git URL[#branch])")


def _add_selection_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--full", action="store_true", help="scan every component (expensive); default is diff mode")
    g.add_argument("--since", metavar="REF", help="diff mode base ref (default: project.yaml diff_base)")
    p.add_argument("--max-components", type=int, metavar="N", help="scan at most N components")
    p.add_argument("--only", action="append", default=[], metavar="NAME", help="scan only this component (repeatable)")


def cmd_validate(a) -> int:
    cfg = load_project(a.target, a.repo)
    print(f"ok: {cfg.name}")
    print(f"  repo        {cfg.repo}{'#' + cfg.branch if cfg.branch else ''}")
    print(f"  dockerfile  {cfg.dockerfile}")
    print(f"  workdir     {cfg.workdir}")
    print(f"  threat      {cfg.threat_model or '(none)'} ({len(cfg.threat_model_text)} chars)")
    print(f"  diff_base   {cfg.diff_base}")
    print(f"  auth        {cfg.scan.auth}")
    print(f"  scan        model={cfg.scan.model} effort={cfg.scan.effort} concurrency={cfg.scan.concurrency} budget/component=${cfg.scan.max_budget_usd}")
    print(f"  verify      concurrency={cfg.verification.concurrency} timeout={cfg.verification.timeout_seconds}s differential={cfg.verification.require_patch_differential}")
    print(f"  components  {len(cfg.components.explicit)} explicit, {len(cfg.components.auto)} auto roots")
    print(f"  seeds       {len(cfg.seeds)}")
    return 0


def cmd_components(a) -> int:
    from threadscan.components import select_components, split_components
    from threadscan.repo import changed_files, list_files, resolve_repo

    cfg = load_project(a.target, a.repo)
    repo = resolve_repo(cfg, Path(a.cache_dir).resolve(), offline=a.offline)
    comps = split_components(list_files(repo), cfg.components)
    changed = None if a.full else changed_files(repo, a.since or cfg.diff_base)
    selected = select_components(comps, changed, a.max_components, a.only or None)
    print(f"{len(comps)} components in {repo}; {len(selected)} selected" + ("" if changed is None else f" ({len(changed)} files changed since {a.since or cfg.diff_base})"))
    for c in selected:
        extra = f"  changed={len(c.changed_files)}" if changed is not None else ""
        print(f"  {c.name:<60} {c.kind:<8} files={len(c.files)}{extra}")
    return 0


def cmd_scan(a) -> int:
    from threadscan.orchestrator import ScanOptions, run_scan

    cfg = load_project(a.target, a.repo)
    opts = ScanOptions(
        mode="full" if a.full else "diff",
        base=a.since,
        max_components=a.max_components,
        only=a.only,
        concurrency=a.concurrency,
        dry_run=a.dry_run,
        runs_dir=Path(a.runs_dir),
        cache_dir=Path(a.cache_dir),
        extra_seeds=a.seed,
        offline=a.offline,
        auth=a.auth,
        allow_full=a.allow_full,
    )
    if a.dashboard:
        from threadscan.dashboard import serve

        threading.Thread(target=serve, args=(Path(a.runs_dir), a.port), daemon=True).start()
    run_dir = run_scan(cfg, opts)
    print(f"report: {run_dir / 'report.md'}")
    print(f"summary: {run_dir / 'summary.json'}")
    if a.dashboard:
        print("dashboard still running; press Ctrl+C to exit")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
    return 0


def cmd_dashboard(a) -> int:
    from threadscan.dashboard import serve

    serve(Path(a.runs_dir), a.port)
    return 0


def cmd_doctor(a) -> int:
    from threadscan.doctor import render, run_doctor

    cfg = load_project(a.target, a.repo) if a.target else None
    auth = a.auth or (cfg.scan.auth if cfg else "subscription")
    print(f"threadscan doctor: auth={auth}" + (f", target={cfg.name}" if cfg else "") + (", live checks on (uses a few cents of usage)" if a.live else ""))
    if a.live:
        print("building a small scan image and running one tiny agent; this takes a few minutes the first time")
    report, run_dir = run_doctor(cfg, auth, a.live, a.model, Path(a.runs_dir))
    print(render(report))
    print(f"details: {run_dir}")
    return 1 if report.failed else 0


def do_recheck(cfg, runs_dir: Path, cache_dir: Path, offline: bool = False, run_id: str | None = None, include_all: bool = False) -> dict:
    import time

    from threadscan import docker_ops as dk
    from threadscan.orchestrator import DockerBackend
    from threadscan.recheck import pick_source_run, recheck
    from threadscan.repo import head_commit, resolve_repo
    from threadscan.triage import TriageStore

    runs_dir = runs_dir.resolve()
    source = pick_source_run(runs_dir, cfg.name, run_id)
    if source is None:
        raise RuntimeError(f"no finished run of {cfg.name} in {runs_dir}" + (f" with id {run_id}" if run_id else ""))
    ok, why = dk.Docker.available()
    if not ok:
        raise RuntimeError(f"Docker is required for a re-check ({why})")
    repo = resolve_repo(cfg, cache_dir.resolve(), offline=offline)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    work = runs_dir / "rechecks" / f"{stamp}-{cfg.name}"
    work.mkdir(parents=True, exist_ok=False)
    print(f"re-checking {len(source['findings'])} issues from {source['run_id']} against the current code (no API usage)")
    backend = DockerBackend(cfg, repo, f"recheck-{stamp}")
    backend.build_images(work)
    out = recheck(cfg, runs_dir, work, backend.executor(work), TriageStore(runs_dir / "triage.json"), run_id, include_all, head_commit(repo))
    s = out["summary"]
    print(f"fixed {s['fixed']} · still present {s['still_present']} · unverified {s['unverified']}  ->  {work / 'recheck.json'}")
    return out


def cmd_recheck(a) -> int:
    cfg = load_project(a.target, a.repo)
    do_recheck(cfg, Path(a.runs_dir), Path(a.cache_dir), a.offline, a.run, a.all)
    return 0


def cmd_watch(a) -> int:
    from threadscan.orchestrator import ScanOptions, run_scan
    from threadscan.repo import head_commit, resolve_repo
    from threadscan.watch import parse_interval, watch_loop, watch_once

    interval = parse_interval(a.interval)
    cfg = load_project(a.target, a.repo)
    runs_dir, cache_dir = Path(a.runs_dir), Path(a.cache_dir)
    state = runs_dir / ".watch" / f"{cfg.name}.json"

    def head() -> str | None:
        return head_commit(resolve_repo(load_project(a.target, a.repo), cache_dir.resolve()))

    def scan(last: str | None) -> Path:
        c = load_project(a.target, a.repo)  # pick up config edits between rounds
        return run_scan(c, ScanOptions(mode="diff", base=last or c.diff_base, runs_dir=runs_dir, cache_dir=cache_dir, concurrency=a.concurrency))

    recheck_fn = (lambda: do_recheck(load_project(a.target, a.repo), runs_dir, cache_dir)) if a.recheck else None
    print(f"watching {cfg.name} every {interval // 60} min (Ctrl+C to stop); state in {state}")
    try:
        watch_loop(interval, lambda: watch_once(state, head, scan, recheck_fn, initial=a.initial), max_rounds=1 if a.once else None)
    except KeyboardInterrupt:
        print("stopped")
    return 0


def cmd_init(a) -> int:
    from threadscan.init import scaffold

    out, det = scaffold(Path(a.repo_path), Path(a.targets_dir), a.name)
    cfg = load_project(out)
    print(f"created {out}")
    print("  detected: " + (", ".join(f"{s.kind} ({s.dir or 'root'})" for s in det.stacks) or "no known build manifest"))
    print(f"  component roots: {', '.join(r or '(repo root)' for r, _ in det.roots) or 'none, add some'}")
    print(f"  name {cfg.name}, auth {cfg.scan.auth}")
    print("next: review the TODOs in Dockerfile and threat_model.md, then")
    print(f"  threadscan components {out} --full")
    print(f"  threadscan doctor {out} --live")
    return 0


def cmd_seeds(a) -> int:
    from threadscan.repo import resolve_repo
    from threadscan.seeds_fetch import fetch_all

    cfg = load_project(a.target, a.repo)
    repo = resolve_repo(cfg, Path(a.cache_dir).resolve(), offline=a.offline)
    tools = set(a.tool or ["codeql", "gitleaks", "osv"])
    outcomes = fetch_all(cfg.target_dir, repo, tools, a.github, a.ref)
    for o in outcomes:
        print(f"[{o.status:<7}] {o.tool:<8} {o.detail}" + (f"  ->  {o.path}" if o.path else ""))
    configured = {s.path.resolve() for s in cfg.seeds}
    missing = [o for o in outcomes if o.path and o.path.resolve() not in configured]
    if missing:
        print("add these to project.yaml so scans use them:")
        print("seeds:")
        for o in missing:
            print(f"  - tool: {o.tool}\n    path: seeds/{o.path.name}")
    return 1 if any(o.status == "failed" for o in outcomes) else 0


def cmd_prune(a) -> int:
    from threadscan.prune import apply_prune, plan_prune

    runs_dir = Path(a.runs_dir)
    delete, kept = plan_prune(runs_dir, a.keep, a.project)
    total = sum(i.size() for i in delete)
    for it in delete:
        print(f"delete  {it.kind:<8} {it.project:<16} {it.path.name}")
    print(f"{len(delete)} to delete ({total / 1024 / 1024:.1f} MiB), {len(kept)} kept; triage.json and .watch/ are never touched")
    if not delete:
        return 0
    if not a.yes:
        print("dry run: nothing deleted. Run again with --yes to delete.")
        return 0
    print(f"deleted {apply_prune(runs_dir, delete)} directories")
    return 0


def cmd_export(a) -> int:
    from threadscan.exporters import FORMATS, export
    from threadscan.triage import TriageStore

    runs_dir = Path(a.runs_dir)
    run_dir = Path(a.run) if Path(a.run).is_dir() else runs_dir / a.run
    if not (run_dir / "findings.json").is_file():
        print(f"error: {run_dir} is not a finished run (no findings.json)", file=sys.stderr)
        return 2
    triage = TriageStore((run_dir.parent if Path(a.run).is_dir() else runs_dir) / "triage.json").load()
    for fmt in (list(FORMATS) if a.format == "all" else [a.format]):
        name, _, content = export(run_dir, fmt, triage)
        out = Path(a.out) / name if a.out else run_dir / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8", newline="" if fmt == "csv" else "\n")
        print(f"{fmt:<6} {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="threadscan", description="AI vulnerability scanner with a verification gate")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("validate", help="check a target config")
    _add_target_args(p)
    p.set_defaults(fn=cmd_validate)

    p = sub.add_parser("components", help="show how the target splits into components")
    _add_target_args(p)
    _add_selection_args(p)
    p.add_argument("--cache-dir", default=".cache")
    p.add_argument("--offline", action="store_true", help="do not fetch a remote repo")
    p.set_defaults(fn=cmd_components)

    p = sub.add_parser("scan", help="build, scan, verify, report")
    _add_target_args(p)
    _add_selection_args(p)
    p.add_argument("--concurrency", type=int, metavar="N", help="agents in parallel (default: project.yaml, which defaults to 2)")
    p.add_argument("--dry-run", action="store_true", help="plan only: no build, no agents, no API calls")
    p.add_argument("--auth", choices=AUTH_MODES, help="api_key (ANTHROPIC_API_KEY) or subscription (CLAUDE_CODE_OAUTH_TOKEN from `claude setup-token`); default: project.yaml")
    p.add_argument("--allow-full", action="store_true", help="allow an unbounded --full scan on a subscription")
    p.add_argument("--seed", action="append", default=[], type=_seed_arg, metavar="TOOL=PATH", help=f"extra seed file ({', '.join(SEED_TOOLS)})")
    p.add_argument("--runs-dir", default="runs")
    p.add_argument("--cache-dir", default=".cache")
    p.add_argument("--offline", action="store_true", help="do not fetch a remote repo")
    p.add_argument("--dashboard", action="store_true", help="also serve the dashboard while scanning")
    p.add_argument("--port", type=int, default=8765)
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("dashboard", help="serve the local dashboard (progress and findings)")
    p.add_argument("--runs-dir", default="runs")
    p.add_argument("--port", type=int, default=8765)
    p.set_defaults(fn=cmd_dashboard)

    p = sub.add_parser("recheck", help="re-run the reproducers of open issues on the current code (no agents, no API usage)")
    _add_target_args(p)
    p.add_argument("--run", help="run id to re-check (default: the latest finished run of the target)")
    p.add_argument("--all", action="store_true", help="also re-check issues triaged as risk accepted or false positive")
    p.add_argument("--runs-dir", default="runs")
    p.add_argument("--cache-dir", default=".cache")
    p.add_argument("--offline", action="store_true", help="do not fetch a remote repo")
    p.set_defaults(fn=cmd_recheck)

    p = sub.add_parser("watch", help="scan new commits as they land (diff scans, one at a time)")
    _add_target_args(p)
    p.add_argument("--interval", default="15m", help="how often to check, e.g. 15m, 1h (minimum 60s)")
    p.add_argument("--initial", action="store_true", help="scan right away against diff_base instead of only recording a baseline")
    p.add_argument("--recheck", action="store_true", help="after each scan, re-run the reproducers of open issues")
    p.add_argument("--once", action="store_true", help="check once and exit (for a scheduler)")
    p.add_argument("--concurrency", type=int, metavar="N")
    p.add_argument("--runs-dir", default="runs")
    p.add_argument("--cache-dir", default=".cache")
    p.set_defaults(fn=cmd_watch)

    p = sub.add_parser("prune", help="delete old runs, keeping the newest N per target and each target's comparison baseline")
    p.add_argument("--keep", type=int, default=10, help="finished runs to keep per target (default 10)")
    p.add_argument("--project", help="only this target")
    p.add_argument("--yes", action="store_true", help="actually delete (default: only list)")
    p.add_argument("--runs-dir", default="runs")
    p.set_defaults(fn=cmd_prune)

    p = sub.add_parser("init", help="scaffold targets/<name>/ for a repository (detects the stack; never touches the repo)")
    p.add_argument("repo_path", help="path to the repository to scan")
    p.add_argument("--name", help="target name (default: the repository folder name)")
    p.add_argument("--targets-dir", default="targets")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("seeds", help="fetch seed input: CodeQL SARIF from GitHub code scanning, gitleaks, osv-scanner")
    _add_target_args(p)
    p.add_argument("--tool", action="append", choices=["codeql", "gitleaks", "osv"], help="only these tools (repeatable; default: all)")
    p.add_argument("--github", help="owner/repo for CodeQL (default: from the repo's origin remote)")
    p.add_argument("--ref", help="git ref for CodeQL analyses, e.g. refs/heads/main (default: the checkout's branch)")
    p.add_argument("--cache-dir", default=".cache")
    p.add_argument("--offline", action="store_true", help="do not fetch a remote repo")
    p.set_defaults(fn=cmd_seeds)

    p = sub.add_parser("export", help="export a run's verified issues: SARIF, CSV, JSON or a self-contained HTML report")
    p.add_argument("run", help="run directory, or a run id inside --runs-dir")
    p.add_argument("--format", choices=["sarif", "csv", "json", "html", "patches", "all"], default="all")
    p.add_argument("--out", help="directory to write to (default: the run directory)")
    p.add_argument("--runs-dir", default="runs")
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("doctor", help="check this machine is ready to scan; --live runs a cheap end-to-end test")
    p.add_argument("target", type=Path, nargs="?", help="optional target config dir, e.g. targets/aegis")
    p.add_argument("--repo", help="override project.yaml repo")
    p.add_argument("--live", action="store_true", help="also start the gateway, build a small scan image and run one tiny agent")
    p.add_argument("--auth", choices=AUTH_MODES, help="default: the target's scan.auth, else subscription")
    p.add_argument("--model", default="claude-haiku-5-5", help="model for the live agent check (default: claude-haiku-5-5, the cheapest)")
    p.add_argument("--runs-dir", default="runs")
    p.set_defaults(fn=cmd_doctor)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "concurrency", None) is not None and not 1 <= args.concurrency <= 16:
        print("error: --concurrency must be between 1 and 16", file=sys.stderr)
        return 2
    if getattr(args, "max_components", None) is not None and args.max_components < 1:
        print("error: --max-components must be at least 1", file=sys.stderr)
        return 2
    try:
        return args.fn(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
