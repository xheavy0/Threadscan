"""Findings JSON, the Markdown report and the run summary.

Only candidates with a ``verified`` verdict become findings. Dropped candidates are
counted by reason and listed in ``dropped.json`` for debugging the scanner; they are
never rendered as findings. Every number in the summary comes from the run itself;
anything the run could not measure is written as "not reported", never estimated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from threadscan.candidates import SEVERITY_RANK, Candidate
from threadscan.status import write_json
from threadscan.verify import DROP_REASONS, Verdict


@dataclass
class Dropped:
    component: str
    reason: str
    title: str = ""
    candidate_id: str | None = None
    detail: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"component": self.component, "reason": self.reason, "title": self.title, "candidate_id": self.candidate_id, "detail": self.detail}


def finding_dict(c: Candidate, v: Verdict) -> dict:
    assert v.kept and v.candidate_id == c.id, "only verified candidates become findings"
    return {
        "id": c.id,
        "title": c.title,
        "severity": c.severity,
        "severity_rationale": c.severity_rationale,
        "cwe": c.cwe,
        "component": c.component,
        "file": c.file,
        "line": c.line,
        "location": f"{c.file}:{c.line}",
        "description": c.description,
        "impact": c.impact,
        "seed_ids": c.seed_ids,
        "reproducer": {
            "script": c.script,
            "files": [{"path": f.path, "content": f.content} for f in c.files],
            "timeout_seconds": c.timeout_seconds,
        },
        "patch": c.patch,
        "verification": {
            "status": v.reason,
            "patch_check": v.patch_check,
            "unpatched_run": v.unpatched,
            "patched_run": v.patched,
            "notes": v.notes,
        },
        "agent_self_test_claim": c.self_test,
    }


def _fence(text: str, lang: str = "") -> str:
    longest = max((len(m) for m in re.findall(r"`+", text or "")), default=0)
    ticks = "`" * max(3, longest + 1)
    body = (text or "").rstrip("\n")
    return f"{ticks}{lang}\n{body}\n{ticks}"


def _usd(v) -> str:
    return "not reported" if v is None else f"${v:,.2f}"


def _cost(v, auth) -> str:
    if auth == "subscription" and v is not None:
        return f"{_usd(v)} at API prices; not billed, counts against your subscription limits"
    return _usd(v)


def _run_evidence(label: str, ev: dict | None) -> list[str]:
    if not ev:
        return [f"- {label}: not run"]
    bits = [f"exit code {ev['exit_code']}", f"{ev['duration_s']} s"]
    bits.append("proof line printed" if ev["proof_line_seen"] else "no proof line")
    if ev.get("timed_out"):
        bits.append("timed out")
    lines = [f"- {label}: " + ", ".join(bits)]
    if ev.get("stdout_tail"):
        lines += ["", f"  stdout (last {len(ev['stdout_tail'])} chars):", "", _fence(ev["stdout_tail"], "text")]
    return lines


def render_markdown(meta: dict, findings: list[dict], summary: dict) -> str:
    out = [f"# threadscan report: {meta['project']}", ""]
    mode = "full scan" if meta["mode"] == "full" else f"diff scan since `{meta.get('base')}`"
    out += [
        f"- Run: `{meta['run_id']}`",
        f"- Mode: {mode}",
        f"- Target commit: `{meta.get('commit') or 'unknown'}`",
        f"- Model: `{meta.get('model')}`",
        "- Auth: " + ("your Claude subscription (Claude Code token)" if meta.get("auth") == "subscription" else "Anthropic API key"),
    ]
    if meta.get("dry_run"):
        out += ["- **Dry run:** no image was built, no agent ran and no reproducer was executed."]
    out += ["", "## Summary", "", "| | |", "|---|---|"]
    rows = [
        ("Components scanned", f"{summary['components_scanned']} of {summary['components_total']} ({summary['components_failed']} failed"
         + (f", {len(summary['components_skipped'])} not started: usage limit" if summary.get("components_skipped") else "") + ")"),
        ("Candidates reported by agents", summary["candidates"]),
        ("Verified findings", summary["verified"]),
        ("Dropped (unproven or invalid)", summary["dropped"]),
        ("Seed findings given to agents", summary["seeds"]["assigned"]),
        ("Tokens in / out", f"{summary['tokens']['input']:,} / {summary['tokens']['output']:,}" if summary["tokens"]["reported"] else "not reported"),
        ("Cost", _cost(summary["cost_usd"], meta.get("auth"))),
    ]
    out += [f"| {k} | {v} |" for k, v in rows]
    if summary["by_severity"]:
        out += ["", "By severity: " + ", ".join(f"{k} {v}" for k, v in summary["by_severity"].items())]

    out += ["", "## Findings", ""]
    if not findings:
        out += ["No verified findings in this run." if not meta.get("dry_run") else "None: this was a dry run.", ""]
    for f in findings:
        v = f["verification"]
        out += [
            f"### [{f['severity'].upper()}] {f['title']}",
            "",
            f"- ID: `{f['id']}`",
            f"- Component: `{f['component']}`",
            f"- Location: `{f['location']}`",
            f"- CWE: {f['cwe'] or 'n/a'}",
            f"- Severity rationale: {f['severity_rationale'] or 'n/a'}",
        ]
        if f["seed_ids"]:
            out.append(f"- Seeds: {', '.join('`' + s + '`' for s in f['seed_ids'])}")
        out += ["", f["description"], "", f"**Impact.** {f['impact']}", "", "**Reproducer**", "", _fence(f["reproducer"]["script"], "bash")]
        for rf in f["reproducer"]["files"]:
            out += ["", f"File `{rf['path']}`:", "", _fence(rf["content"])]
        out += ["", "**Evidence** (the scanner's own runs in fresh offline containers)", ""]
        out += _run_evidence("Unpatched", v["unpatched_run"])
        out += _run_evidence(f"Patched (result: {v['patch_check']})", v["patched_run"])
        for n in v["notes"]:
            out.append(f"- Note: {n}")
        out += ["", "**Proposed patch**", "", _fence(f["patch"], "diff") if f["patch"] else "_none_", ""]

    if summary.get("components_skipped"):
        out += [
            "## Not scanned: usage limit reached",
            "",
            "The subscription's usage limit was reached, so these components were not started:",
            "",
            *[f"- `{n}`" for n in summary["components_skipped"]],
            "",
            "Resume once the limit resets:",
            "",
            _fence(summary.get("resume_command", ""), "bash"),
            "",
        ]
    out += ["## Dropped candidates", ""]
    if summary["dropped"]:
        out += ["These were not proven and are not findings. Counts by reason:", "", "| Reason | Count |", "|---|---|"]
        out += [f"| {DROP_REASONS.get(r, r)} | {n} |" for r, n in sorted(summary["dropped_by_reason"].items())]
        out += ["", "Details for debugging the scanner are in `dropped.json`."]
    else:
        out.append("None.")
    if meta.get("not_exercised"):
        out += ["", "## Not exercised in this run", ""] + [f"- {x}" for x in meta["not_exercised"]]
    return "\n".join(out).rstrip() + "\n"


def build_summary(
    components_total: int,
    component_results: list[dict],
    candidates: int,
    verified: list[dict],
    dropped: list[Dropped],
    seeds_total: int,
    seeds_assigned: int,
    seed_triage: dict[str, int],
    gateway: dict | None,
) -> dict:
    by_reason: dict[str, int] = {}
    for d in dropped:
        by_reason[d.reason] = by_reason.get(d.reason, 0) + 1
    by_sev: dict[str, int] = {}
    for f in sorted(verified, key=lambda f: SEVERITY_RANK[f["severity"]]):
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    costs = [r["cost_usd"] for r in component_results if r.get("cost_usd") is not None]
    tok_in = sum(r.get("input_tokens") or 0 for r in component_results)
    tok_out = sum(r.get("output_tokens") or 0 for r in component_results)
    return {
        "components_total": components_total,
        "components_scanned": sum(1 for r in component_results if r["state"] == "done"),
        "components_failed": sum(1 for r in component_results if r["state"] == "error"),
        "candidates": candidates,
        "verified": len(verified),
        "dropped": len(dropped),
        "dropped_by_reason": by_reason,
        "by_severity": by_sev,
        "seeds": {"loaded": seeds_total, "assigned": seeds_assigned, "triage": seed_triage},
        "tokens": {"input": tok_in, "output": tok_out, "reported": any(r.get("input_tokens") is not None for r in component_results)},
        "cost_usd": round(sum(costs), 4) if costs else None,
        "gateway": gateway,
        "components": component_results,
    }


def write_outputs(run_dir: Path, meta: dict, findings: list[dict], dropped: list[Dropped], summary: dict) -> Path:
    findings = sorted(findings, key=lambda f: (SEVERITY_RANK[f["severity"]], f["component"], f["file"], f["line"]))
    fdir = run_dir / "findings"
    fdir.mkdir(parents=True, exist_ok=True)
    for f in findings:
        write_json(fdir / f"{f['id']}.json", f)
    write_json(run_dir / "findings.json", findings)
    write_json(run_dir / "dropped.json", [d.to_dict() for d in dropped])
    write_json(run_dir / "summary.json", {"meta": meta, **summary})
    report = run_dir / "report.md"
    from threadscan.redact import redact

    report.write_text(redact(render_markdown(meta, findings, summary)), encoding="utf-8")
    return report
