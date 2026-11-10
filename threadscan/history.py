"""Issue lifecycle across runs: new, existing, resolved, still present.

"Resolved" is never inferred from absence. When an issue from the previous run is not
reported again in a component that was scanned, the scanner re-runs that issue's old
reproducer against the current code (offline, same gate rules):

* it no longer prints the proof line and exits 0  -> resolved (with evidence);
* it still prints the proof line                   -> still present: carried into this
                                                      run's findings with fresh evidence;
* it cannot run (error, timeout)                   -> unverified: listed, never "resolved".

Issues in components this run did not scan are "not rescanned" and keep their last state.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from threadscan.candidates import Candidate, ReproFile
from threadscan.owasp import cwe_number

LINE_TOLERANCE = 10


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def completed_runs(runs_dir: Path, project: str) -> list[dict]:
    """Finished, non-dry runs of a project, oldest first: ``{run_id, dir, status}``."""
    out = []
    if not runs_dir.is_dir():
        return out
    for d in runs_dir.iterdir():
        st = _load(d / "status.json") if d.is_dir() else None
        if st and st.get("project") == project and st.get("phase") == "done" and not st.get("dry_run"):
            out.append({"run_id": st.get("run_id") or d.name, "dir": d, "status": st})
    out.sort(key=lambda r: r["status"].get("started") or 0)
    return out


def previous_run(runs_dir: Path, project: str, current_run_id: str) -> dict | None:
    """The latest completed run of the project before the current one, with its findings."""
    prior = [r for r in completed_runs(runs_dir, project) if r["run_id"] != current_run_id]
    if not prior:
        return None
    r = prior[-1]
    r["findings"] = _load(r["dir"] / "findings.json") or []
    return r


def _norm_title(t: str) -> str:
    return re.sub(r"\W+", "", (t or "").lower())


def same_issue(prev: dict, cur: dict) -> bool:
    """Same file, same CWE (or same title when either lacks one), lines close together.
    Agents reword titles between runs, so IDs alone are not enough."""
    if prev.get("file") != cur.get("file"):
        return False
    if abs((prev.get("line") or 0) - (cur.get("line") or 0)) > LINE_TOLERANCE:
        return False
    a, b = cwe_number(prev.get("cwe")), cwe_number(cur.get("cwe"))
    if a is not None and b is not None:
        return a == b
    return _norm_title(prev.get("title")) == _norm_title(cur.get("title"))


def match_findings(prev: list[dict], cur: list[dict]) -> dict[str, str]:
    """Map current finding id -> previous finding id. Exact ids first, then ``same_issue``."""
    matches: dict[str, str] = {}
    used: set[str] = set()
    prev_ids = {p["id"] for p in prev}
    for c in cur:
        if c["id"] in prev_ids:
            matches[c["id"]] = c["id"]
            used.add(c["id"])
    for c in cur:
        if c["id"] in matches:
            continue
        for p in prev:
            if p["id"] not in used and same_issue(p, c):
                matches[c["id"]] = p["id"]
                used.add(p["id"])
                break
    return matches


@dataclass
class LifecyclePlan:
    previous_run: str | None
    matches: dict[str, str] = field(default_factory=dict)
    new: list[str] = field(default_factory=list)
    recheck: list[dict] = field(default_factory=list)  # previous findings to re-run
    not_rescanned: list[dict] = field(default_factory=list)


def plan(previous_run_id: str | None, prev: list[dict], cur: list[dict], scanned_components: set[str]) -> LifecyclePlan:
    lp = LifecyclePlan(previous_run_id)
    lp.matches = match_findings(prev, cur)
    lp.new = [c["id"] for c in cur if c["id"] not in lp.matches]
    matched_prev = set(lp.matches.values())
    for p in prev:
        if p["id"] in matched_prev:
            continue
        (lp.recheck if p.get("component") in scanned_components else lp.not_rescanned).append(p)
    return lp


def candidate_from_finding(f: dict) -> Candidate:
    r = f.get("reproducer") or {}
    return Candidate(
        id=f["id"], component=f["component"], title=f["title"], severity=f["severity"],
        severity_rationale=f.get("severity_rationale", ""), cwe=f.get("cwe", ""), file=f["file"], line=f["line"],
        description=f.get("description", ""), impact=f.get("impact", ""), script=r.get("script", ""),
        files=[ReproFile(x["path"], x["content"]) for x in r.get("files") or []],
        timeout_seconds=r.get("timeout_seconds"), patch=f.get("patch", ""),
        self_test=f.get("agent_self_test_claim", ""), seed_ids=f.get("seed_ids") or [],
    )


def brief(f: dict) -> dict:
    return {k: f.get(k) for k in ("id", "title", "severity", "component", "location", "cwe")}


def project_history(runs_dir: Path, project: str, limit: int = 60) -> list[dict]:
    """One row per completed run: verified counts by severity and lifecycle counts."""
    rows = []
    for r in completed_runs(runs_dir, project)[-limit:]:
        findings = _load(r["dir"] / "findings.json") or []
        lc = _load(r["dir"] / "lifecycle.json") or {}
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.get("severity", "info")] = by_sev.get(f.get("severity", "info"), 0) + 1
        st = r["status"]
        rows.append({
            "run_id": r["run_id"], "started": st.get("started"), "mode": st.get("mode"), "auth": st.get("auth"),
            "verified": len(findings), "by_severity": by_sev,
            "new": len(lc.get("new") or []), "resolved": len(lc.get("resolved") or []),
            "still_present": len(lc.get("still_present") or []), "has_lifecycle": bool(lc),
        })
    return rows
