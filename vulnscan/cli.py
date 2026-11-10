"""Command line: ``vulnscan validate | components | scan | dashboard``."""

from __future__ import annotations

import argparse
import sys
import threading
from pathlib import Path

from vulnscan.config import SEED_TOOLS, ConfigError, SeedSpec, load_project


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
    print(f"  scan        model={cfg.scan.model} effort={cfg.scan.effort} concurrency={cfg.scan.concurrency} budget/component=${cfg.scan.max_budget_usd}")
    print(f"  verify      concurrency={cfg.verification.concurrency} timeout={cfg.verification.timeout_seconds}s differential={cfg.verification.require_patch_differential}")
    print(f"  components  {len(cfg.components.explicit)} explicit, {len(cfg.components.auto)} auto roots")
    print(f"  seeds       {len(cfg.seeds)}")
    return 0


def cmd_components(a) -> int:
    from vulnscan.components import select_components, split_components
    from vulnscan.repo import changed_files, list_files, resolve_repo

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
    from vulnscan.orchestrator import ScanOptions, run_scan

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
    )
    if a.dashboard:
        from vulnscan.dashboard import serve

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
    from vulnscan.dashboard import serve

    serve(Path(a.runs_dir), a.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="vulnscan", description="AI vulnerability scanner with a verification gate")
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
