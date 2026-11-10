"""``threadscan recheck``: re-verify known issues against the current code, without agents.

For each open issue of the latest finished run (or ``--run``), its own reproducer runs again
in a fresh offline container built from the current code. No API is called, so this costs
nothing but Docker time. The result is evidence, applied to triage automatically:

* exits 0 without the proof line  -> **fixed**: triage set to Resolved (unless already),
  with the run's evidence and the commit in the Activity log;
* still prints the proof line     -> **still present**: an issue marked Resolved is re-opened;
* cannot run (error, timeout)     -> **unverified**: triage untouched, reported.

Issues triaged as risk accepted or false positive are skipped unless ``--all``.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable

from threadscan import history
from threadscan.config import ProjectConfig
from threadscan.status import write_json
from threadscan.triage import TriageStore
from threadscan.verify import DROP_REASONS, Executor, RunResult, classify_unpatched, new_nonce

SKIP_STATUSES = {"risk_accepted", "false_positive"}
BY = "threadscan recheck"


def pick_source_run(runs_dir: Path, project: str, run_id: str | None) -> dict | None:
    runs = history.completed_runs(runs_dir, project)
    if run_id:
        runs = [r for r in runs if r["run_id"] == run_id]
    if not runs:
        return None
    r = runs[-1]
    r["findings"] = json.loads((r["dir"] / "findings.json").read_text(encoding="utf-8")) if (r["dir"] / "findings.json").is_file() else []
    return r


def recheck(
    cfg: ProjectConfig,
    runs_dir: Path,
    work_dir: Path,
    executor: Executor,
    store: TriageStore,
    run_id: str | None = None,
    include_all: bool = False,
    commit: str | None = None,
    log: Callable[[str], None] = print,
) -> dict:
    source = pick_source_run(runs_dir, cfg.name, run_id)
    if source is None:
        raise RuntimeError(f"no finished run of {cfg.name} to re-check" + (f" with id {run_id}" if run_id else ""))
    triage = store.load()
    results = []
    for f in source["findings"]:
        status = (triage.get(f["id"]) or {}).get("status", "open")
        if status in SKIP_STATUSES and not include_all:
            continue
        try:
            cand = history.candidate_from_finding(f)
        except (KeyError, TypeError):
            results.append({**history.brief(f), "outcome": "unverified", "reason": "finding record incomplete", "triage_change": None})
            continue
        nonce = new_nonce()
        try:
            rr = executor.run(cand, "unpatched", nonce)
        except Exception as exc:  # never crash the whole re-check on one issue
            rr = RunResult(None, "", "", 0.0, infra_error=f"{type(exc).__name__}: {exc}")
        state = classify_unpatched(rr, nonce)
        where = f" on {commit[:12]}" if commit else ""
        change = None
        if state == "not_reproduced":
            outcome = "fixed"
            if status != "resolved":
                store.update(f["id"], {"status": "resolved"}, by=BY, reason=f"the reproducer no longer reproduces{where}")
                change = f"{status} -> resolved"
        elif state == "reproduced":
            outcome = "still_present"
            if status == "resolved":
                store.update(f["id"], {"status": "open"}, by=BY, reason=f"re-opened: the reproducer still reproduces{where}")
                change = "resolved -> open"
        else:
            outcome = "unverified"
        results.append({**history.brief(f), "outcome": outcome, "reason": None if outcome != "unverified" else DROP_REASONS.get(state, state),
                        "triage_change": change, "evidence": rr.evidence(nonce)})
        log(f"[{outcome}] {f['title']}" + (f" ({change})" if change else ""))
    summary = {k: sum(1 for r in results if r["outcome"] == k) for k in ("fixed", "still_present", "unverified")}
    out = {"project": cfg.name, "source_run": source["run_id"], "commit": commit, "at": time.time(), "summary": summary, "results": results}
    write_json(work_dir / "recheck.json", out)
    return out


def list_rechecks(runs_dir: Path, limit: int = 30) -> list[dict]:
    base = runs_dir / "rechecks"
    rows = []
    if base.is_dir():
        for d in base.iterdir():
            p = d / "recheck.json"
            if p.is_file():
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                except ValueError:
                    continue
                rows.append({k: data.get(k) for k in ("project", "source_run", "commit", "at", "summary")} | {"id": d.name})
    rows.sort(key=lambda r: r.get("at") or 0, reverse=True)
    return rows[:limit]
