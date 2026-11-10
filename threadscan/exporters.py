"""Exports of a run's verified issues: SARIF 2.1.0, CSV, JSON and a self-contained HTML report.

Only verified findings are exported; dropped candidates never are. Triage state from
``runs/triage.json`` is applied at export time, so an export reflects the current status,
assignee and note. In SARIF, issues triaged as risk accepted or false positive carry an
external suppression, which code-scanning tools (GitHub among them) show as dismissed.

The HTML report needs nothing else to open: styles, fonts and the mark are embedded, there
is no script, every value is escaped, and the whole document passes the secret redactor.
"""

from __future__ import annotations

import base64
import csv
import html
import io
import json
import time
from pathlib import Path

from threadscan import __version__
from threadscan.candidates import SEVERITY_RANK
from threadscan.owasp import categorize, cwe_number
from threadscan.redact import redact, redact_obj
from threadscan.verify import DROP_REASONS

STATIC = Path(__file__).resolve().parent / "static"
SEC_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SUPPRESSED = {"risk_accepted": "accepted risk", "false_positive": "false positive"}
STATUS_LABEL = {"open": "Open", "in_progress": "In progress", "resolved": "Resolved", "risk_accepted": "Risk accepted", "false_positive": "False positive"}
FORMATS = {"sarif": ("findings.sarif", "application/sarif+json"), "csv": ("findings.csv", "text/csv"),
           "json": ("findings-export.json", "application/json"), "html": ("report.html", "text/html"),
           "patches": ("verified-fixes.patch", "text/x-diff")}


def _load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


class RunData:
    """Everything an export needs, read once from a run directory."""

    def __init__(self, run_dir: Path, triage: dict | None = None):
        self.run_dir = run_dir
        summary = _load(run_dir / "summary.json", {})
        self.meta = summary.get("meta") or {}
        self.summary = summary
        self.lifecycle = _load(run_dir / "lifecycle.json", {})
        self.triage = triage or {}
        findings = _load(run_dir / "findings.json", [])
        for f in findings:
            if not f.get("owasp"):
                f["owasp"] = categorize(f.get("cwe"))
            override = self.triage_of(f).get("severity")
            if override and override != f.get("severity"):  # severity adjusted in triage; keep the original
                f["original_severity"], f["severity"] = f.get("severity"), override
        self.findings = sorted(findings, key=lambda f: (SEVERITY_RANK.get(f.get("severity"), 9), f.get("component", ""), f.get("file", ""), f.get("line", 0)))

    def triage_of(self, f: dict) -> dict:
        prev = (self.lifecycle.get("existing") or {}).get(f["id"])
        return self.triage.get(f["id"]) or (self.triage.get(prev) if prev else None) or {"status": "open", "assignee": "", "note": ""}

    def lifecycle_of(self, f: dict) -> str:
        if f.get("carried_over_from"):
            return "re-verified"
        if not self.lifecycle.get("previous_run"):
            return "first scan"
        return "new" if f["id"] in (self.lifecycle.get("new") or []) else "seen before"


# ------------------------------------------------------------------ SARIF


def to_sarif(data: RunData) -> dict:
    rules, results = [], []
    for i, f in enumerate(data.findings):
        sev = f.get("severity", "info")
        tags = ["security", "threadscan", "verified"]
        n = cwe_number(f.get("cwe"))
        if n is not None:
            tags.append(f"external/cwe/cwe-{n}")
        if f.get("owasp"):
            tags.append(f"owasp/{f['owasp']['id'].lower()}")
        v = f.get("verification") or {}
        rules.append({
            "id": f["id"],
            "name": f["id"].replace("-", ""),
            "shortDescription": {"text": f["title"]},
            "fullDescription": {"text": f.get("description", "")[:2000]},
            "help": {
                "text": f"{f.get('impact', '')}\n\nVerified by Threadscan: the reproducer demonstrated this in an offline container"
                        + (" and stopped once the proposed patch was applied." if v.get("patch_check") == "fixed" else "."),
            },
            "properties": {"tags": tags, "security-severity": SEC_SEVERITY.get(sev, "0.0"), "precision": "very-high"},
        })
        t = data.triage_of(f)
        result = {
            "ruleId": f["id"],
            "ruleIndex": i,
            "level": LEVEL.get(sev, "note"),
            "message": {"text": f"{f['title']}. {f.get('impact', '')}".strip()},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"], "uriBaseId": "%SRCROOT%"},
                                                "region": {"startLine": max(1, int(f.get("line") or 1))}}}],
            "partialFingerprints": {"threadscanId/v1": f["id"]},
            "properties": {
                "severity": sev, "component": f.get("component"), "cwe": f.get("cwe"),
                "owasp": f"{f['owasp']['id']} {f['owasp']['name']}" if f.get("owasp") else None,
                "verification": v.get("status"), "patchCheck": v.get("patch_check"),
                "lifecycle": data.lifecycle_of(f), "triageStatus": t.get("status"), "assignee": t.get("assignee") or None,
                "originalSeverity": f.get("original_severity"),
            },
        }
        if t.get("status") in SUPPRESSED:
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": (t.get("note") or SUPPRESSED[t["status"]])[:1000]}]
        results.append(result)
    meta = data.meta
    run = {
        "tool": {"driver": {"name": "Threadscan", "version": __version__, "semanticVersion": __version__, "rules": rules}},
        "automationDetails": {"id": f"threadscan/{meta.get('project', 'target')}/{meta.get('run_id', 'run')}"},
        "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "Root of the scanned repository"}}},
        "invocations": [{"executionSuccessful": True, "properties": {"mode": meta.get("mode"), "base": meta.get("base"), "model": meta.get("model")}}],
        "results": results,
        "properties": {"note": "Only issues whose reproducer passed Threadscan's offline verification gate are included."},
    }
    if meta.get("commit"):
        run["invocations"][0]["properties"]["commit"] = meta["commit"]
    return redact_obj({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]})


# ------------------------------------------------------------------ CSV / JSON

CSV_COLUMNS = ["id", "severity", "title", "component", "file", "line", "cwe", "owasp", "status", "assignee", "lifecycle", "verification", "patch_check"]


def rows(data: RunData) -> list[dict]:
    out = []
    for f in data.findings:
        t, v = data.triage_of(f), f.get("verification") or {}
        out.append({"id": f["id"], "severity": f.get("severity"), "title": f.get("title"), "component": f.get("component"), "file": f.get("file"),
                    "line": f.get("line"), "cwe": f.get("cwe") or "", "owasp": f"{f['owasp']['id']} {f['owasp']['name']}" if f.get("owasp") else "",
                    "status": t.get("status"), "assignee": t.get("assignee") or "", "lifecycle": data.lifecycle_of(f),
                    "verification": v.get("status") or "", "patch_check": v.get("patch_check") or ""})
    return out


def _cell(value) -> str:
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # no spreadsheet formulas


def to_csv(data: RunData) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for r in rows(data):
        w.writerow([_cell(r[c]) for c in CSV_COLUMNS])
    return redact(buf.getvalue())


def to_json(data: RunData) -> str:
    return json.dumps(redact_obj({"run": data.meta, "issues": [{**r, "description": f.get("description"), "impact": f.get("impact"),
                                                                "reproducer": f.get("reproducer"), "patch": f.get("patch")}
                                                               for r, f in zip(rows(data), data.findings)]}), indent=1)


# ------------------------------------------------------------------ patches


def to_patches(data: RunData) -> str:
    """Every patch the gate verified (the reproducer stopped with it applied), in file order.

    Issues triaged as false positive are left out. Comment lines between patches are ignored
    by ``git apply``. Each patch was verified on its own; patches touching the same lines may
    not apply together, so the header says how to apply them one at a time."""
    chosen = [f for f in data.findings
              if f.get("patch") and (f.get("verification") or {}).get("patch_check") == "fixed"
              and data.triage_of(f).get("status") != "false_positive"]
    chosen.sort(key=lambda f: (f.get("file", ""), f.get("line", 0), f["id"]))
    meta = data.meta
    out = [
        f"# Threadscan verified fixes for {meta.get('project')} (run {meta.get('run_id')}, commit {(meta.get('commit') or 'unknown')[:12]})",
        f"# {len(chosen)} patch(es). Each one stopped its issue's reproducer when applied on its own.",
        "# Check first:  git apply --check verified-fixes.patch",
        "# Apply all:    git apply verified-fixes.patch",
        "# If two patches overlap, apply them one at a time from the per-issue blocks below.",
        "",
    ]
    for f in chosen:
        t = data.triage_of(f)
        out += [
            f"# ---- {f['id']} [{f.get('severity')}] {f.get('title')}".replace("\n", " "),
            f"# {f.get('location')} · component {f.get('component')} · triage {t.get('status')}",
            f.get("patch", "").rstrip("\n"),
            "",
        ]
    return redact("\n".join(out) + "\n")


# ------------------------------------------------------------------ HTML

def _font_face(family: str, file: str, weight: str) -> str:
    p = STATIC / "fonts" / file
    if not p.is_file():
        return ""
    b64 = base64.b64encode(p.read_bytes()).decode()
    return f"@font-face{{font-family:'{family}';src:url(data:font/woff2;base64,{b64}) format('woff2');font-weight:{weight};font-display:swap}}"


CSS = """
:root{--text:#1d2433;--text2:#3b4458;--muted:#6b7385;--line:#e4e7ec;--bg2:#f7f8fa;--bg3:#f1f3f6;--primary:#1b5cff;--psoft:#eaf0ff;
--cfg:#d1242f;--cbg:#ffe4e6;--hfg:#c2410c;--hbg:#ffedd5;--mfg:#a16207;--mbg:#fef3c7;--lfg:#475467;--lbg:#eef1f5;--ok:#12804a;--okbg:#e6f6ec;--warn:#a15c00;--warnbg:#fff4e0}
*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--text);font:14px/1.55 'DM Sans','Segoe UI',system-ui,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:36px 32px 64px}
h1,h2,h3{font-family:'Poppins','DM Sans',sans-serif;font-weight:500;margin:0;color:var(--text)}
h1{font-size:28px;letter-spacing:-.01em}h2{font-size:20px;margin:34px 0 12px}h3{font-size:17px;line-height:1.35}
code,pre,.mono{font-family:'JetBrains Mono',Consolas,monospace}
.head{display:flex;gap:16px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:18px}
.head svg{width:44px;height:44px;flex-shrink:0}.sub{color:var(--muted);font-size:13.5px;margin-top:3px}
.meta{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-top:20px}
.meta div{background:#fff;padding:12px 14px}.meta dt{font-size:12px;color:var(--muted)}.meta dd{margin:2px 0 0;word-break:break-word}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px}
.kpi{border:1px solid var(--line);border-radius:12px;padding:14px 16px}.kpi b{display:block;font:500 28px 'Poppins',sans-serif}.kpi span{color:var(--muted);font-size:13px}
.sevc{display:inline-flex;width:22px;height:22px;border-radius:50%;align-items:center;justify-content:center;font-size:11px;font-weight:700;vertical-align:middle}
.critical{background:var(--cbg);color:var(--cfg)}.high{background:var(--hbg);color:var(--hfg)}.medium{background:var(--mbg);color:var(--mfg)}.low,.info{background:var(--lbg);color:var(--lfg)}
.counts span{margin-right:12px;white-space:nowrap}
table{width:100%;border-collapse:collapse;font-size:13.5px}th{text-align:left;color:var(--muted);font-weight:500;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}td.mono{font-size:12px;word-break:break-all;width:42%}
.issue{border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:14px 0;break-inside:avoid-page}
.issue .top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;color:var(--muted);font-size:13px}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12.5px;font-weight:500;background:var(--bg3);color:var(--text2)}
.pill.ok{background:var(--okbg);color:var(--ok)}.pill.warn{background:var(--warnbg);color:var(--warn)}.pill.bad{background:var(--cbg);color:var(--cfg)}.pill.blue{background:var(--psoft);color:var(--primary)}
.facts{display:grid;grid-template-columns:repeat(3,1fr);gap:8px 16px;margin:12px 0;font-size:13px}.facts dt{color:var(--muted);font-size:12px}.facts dd{margin:0;word-break:break-word}
h4{font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:16px 0 6px}
p{margin:0 0 6px;white-space:pre-wrap;color:var(--text2)}
pre{background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:12px;line-height:1.55;white-space:pre-wrap;word-break:break-all;margin:0}
.add{color:var(--ok)}.del{color:var(--cfg)}.hunk{color:var(--primary)}.dmeta{color:var(--muted)}
.ev{display:grid;grid-template-columns:1fr 1fr;gap:10px}.ev>div{border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.note{border-left:3px solid var(--primary);background:var(--psoft);padding:10px 14px;border-radius:0 10px 10px 0;color:var(--text2);font-size:13.5px;margin-top:14px}
.foot{margin-top:40px;color:var(--muted);font-size:12.5px;border-top:1px solid var(--line);padding-top:14px}
@media print{.wrap{padding:0}.issue{break-inside:avoid}h2{break-after:avoid}a{color:inherit;text-decoration:none}}
@media (max-width:720px){.meta,.kpis{grid-template-columns:1fr 1fr}.facts,.ev{grid-template-columns:1fr}.wrap{padding:20px 16px}}
"""

SEV_LETTER = {"critical": "C", "high": "H", "medium": "M", "low": "L", "info": "I"}


def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _diff_html(text: str) -> str:
    out = []
    for line in (text or "").split("\n"):
        cls = "hunk" if line.startswith("@@") else "dmeta" if line.startswith(("+++", "---")) else "add" if line.startswith("+") else "del" if line.startswith("-") else ""
        out.append(f'<span class="{cls}">{_e(line)}</span>' if cls else _e(line))
    return "\n".join(out)


def _evidence(label: str, ev: dict | None, want_proof: bool) -> str:
    if not ev:
        return f"<div><b>{_e(label)}</b> <span class='pill'>not run</span></div>"
    good = (ev.get("proof_line_seen") and ev.get("exit_code") == 0) if want_proof else (not ev.get("proof_line_seen") and ev.get("exit_code") == 0)
    tail = ev.get("stdout_tail") or ""
    return (f"<div><b>{_e(label)}</b> <span class='pill {'ok' if good else 'warn'}'>{'proof printed' if ev.get('proof_line_seen') else 'no proof'}</span>"
            f"<div class='sub mono'>exit {_e(ev.get('exit_code'))} · {_e(ev.get('duration_s'))}s{' · timed out' if ev.get('timed_out') else ''}</div>"
            + (f"<pre style='margin-top:8px'>{_e(tail[-2500:])}</pre>" if tail else "") + "</div>")


def to_html(data: RunData) -> str:
    meta, s = data.meta, data.summary
    mark = (STATIC / "threadscan.svg").read_text(encoding="utf-8") if (STATIC / "threadscan.svg").is_file() else ""
    mark = mark[mark.find("<svg"):] if "<svg" in mark else ""
    fonts = "".join([_font_face("DM Sans", "dm-sans-latin-wght-normal.woff2", "100 1000"), _font_face("Poppins", "poppins-latin-500-normal.woff2", "500"),
                     _font_face("JetBrains Mono", "jetbrains-mono-latin-400-normal.woff2", "400")])
    sev_counts = {sv: sum(1 for f in data.findings if f.get("severity") == sv) for sv in SEVERITY_RANK}
    open_n = sum(1 for f in data.findings if data.triage_of(f).get("status") not in ("resolved", "risk_accepted", "false_positive"))
    lc = data.lifecycle or {}
    mode = "Full scan" if meta.get("mode") == "full" else f"Diff since {meta.get('base')}"
    cost = s.get("cost_usd")
    cost_txt = "—" if cost is None else f"${cost:,.2f}"
    cost_label = "Usage at API prices (not billed)" if meta.get("auth") == "subscription" else "Cost" if cost is not None else "Cost not reported"
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>",
             f"<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:\">",
             f"<title>Threadscan report: {_e(meta.get('project'))}</title><style>{fonts}{CSS}</style></head><body><div class='wrap'>",
             f"<div class='head'>{mark}<div><h1>Security report: {_e(meta.get('project'))}</h1>",
             f"<div class='sub'>Threadscan {_e(__version__)} · run <span class='mono'>{_e(meta.get('run_id'))}</span> · generated {_e(time.strftime('%Y-%m-%d %H:%M'))}</div></div></div>",
             "<dl class='meta'>"]
    for k, v in [("Scope", mode), ("Commit", (meta.get("commit") or "unknown")[:12]), ("Model", meta.get("model")),
                 ("Components scanned", f"{s.get('components_scanned', 0)} of {s.get('components_total', 0)}")]:
        parts.append(f"<div><dt>{_e(k)}</dt><dd>{_e(v)}</dd></div>")
    parts.append("</dl><div class='kpis'>")
    for k, v in [("Verified issues", len(data.findings)), ("Open after triage", open_n), ("Dropped as unproven", s.get("dropped", 0)), (cost_label, cost_txt)]:
        parts.append(f"<div class='kpi'><b>{_e(v)}</b><span>{_e(k)}</span></div>")
    parts.append("</div>")
    parts.append("<div class='note'>Every issue below was demonstrated by a reproducer that Threadscan re-ran itself in a fresh container "
                 "with no network: it showed the problem on the scanned code and, where a fix is marked verified, stopped showing it "
                 "once the proposed patch was applied. Candidates that could not be demonstrated are not listed, only counted.</div>")
    parts.append("<h2>Summary</h2><p class='counts'>" + "".join(
        f"<span><span class='sevc {sv}'>{SEV_LETTER[sv]}</span> {n} {sv}</span>" for sv, n in sev_counts.items() if n) + ("" if data.findings else "No verified issues.") + "</p>")
    if lc.get("previous_run"):
        parts.append(f"<p>Compared with <span class='mono'>{_e(lc['previous_run'])}</span>: {len(lc.get('new') or [])} new, "
                     f"{len(lc.get('resolved') or [])} resolved (old reproducer no longer reproduces), {len(lc.get('still_present') or [])} re-verified, "
                     f"{len(lc.get('unverified') or [])} could not be re-checked.</p>")
    if data.findings:
        parts.append("<table><thead><tr><th>Severity</th><th>Issue</th><th>Location</th><th>OWASP</th><th>Status</th></tr></thead><tbody>")
        for f in data.findings:
            t = data.triage_of(f)
            parts.append(f"<tr><td><span class='sevc {_e(f.get('severity'))}'>{SEV_LETTER.get(f.get('severity'), '?')}</span></td>"
                         f"<td><a href='#{_e(f['id'])}'>{_e(f['title'])}</a></td><td class='mono'>{_e(f.get('location'))}</td>"
                         f"<td>{_e(f['owasp']['id']) if f.get('owasp') else '—'}</td><td>{_e(STATUS_LABEL.get(t.get('status'), t.get('status')))}</td></tr>")
        parts.append("</tbody></table><h2>Issues</h2>")
    for f in data.findings:
        t, v, r = data.triage_of(f), f.get("verification") or {}, f.get("reproducer") or {}
        parts.append(f"<section class='issue' id='{_e(f['id'])}'><div class='top'><span class='sevc {_e(f.get('severity'))}'>{SEV_LETTER.get(f.get('severity'), '?')}</span>"
                     f"<span>{_e(str(f.get('severity', '')).capitalize())}"
                     + (f" (adjusted from {_e(f['original_severity'])})" if f.get("original_severity") else "") + f"</span><span class='mono'>{_e(f['id'])}</span>"
                     f"<span class='pill blue'>{_e(STATUS_LABEL.get(t.get('status'), t.get('status')))}</span>"
                     + (f"<span class='pill'>{_e(t.get('assignee'))}</span>" if t.get("assignee") else "") + "</div>"
                     f"<h3 style='margin-top:8px'>{_e(f['title'])}</h3><dl class='facts'>")
        for k, val in [("Location", f.get("location")), ("Component", f.get("component")), ("CWE", f.get("cwe") or "—"),
                       ("OWASP Top 10:2021", f"{f['owasp']['id']} {f['owasp']['name']}" if f.get("owasp") else "not mapped"),
                       ("Verification", f"{v.get('status')} · patch {v.get('patch_check')}"), ("Lifecycle", data.lifecycle_of(f))]:
            parts.append(f"<div><dt>{_e(k)}</dt><dd class='{'mono' if k == 'Location' else ''}'>{_e(val)}</dd></div>")
        parts.append("</dl>")
        for k, val in [("Description", f.get("description")), ("Impact", f.get("impact")), ("Severity rationale", f.get("severity_rationale"))]:
            if val:
                parts.append(f"<h4>{_e(k)}</h4><p>{_e(val)}</p>")
        if t.get("note"):
            parts.append(f"<h4>Triage note</h4><p>{_e(t['note'])}</p>")
        parts.append("<h4>Evidence from Threadscan's own runs</h4><div class='ev'>" + _evidence("Unpatched code", v.get("unpatched_run"), True)
                     + _evidence("With the patch", v.get("patched_run"), False) + "</div>")
        parts.append(f"<h4>Reproducer</h4><pre>{_e(r.get('script'))}</pre>")
        for rf in r.get("files") or []:
            parts.append(f"<div class='sub mono' style='margin:8px 0 4px'>{_e(rf.get('path'))}</div><pre>{_e(rf.get('content'))}</pre>")
        if f.get("patch"):
            parts.append(f"<h4>Proposed patch</h4><pre>{_diff_html(f['patch'])}</pre>")
        parts.append("</section>")
    reasons = s.get("dropped_by_reason") or {}
    if reasons:
        parts.append("<h2>Dropped candidates</h2><p>Not proven, so not reported as issues. Counts by reason:</p><table><tbody>")
        for k, n in sorted(reasons.items()):
            parts.append(f"<tr><td>{_e(DROP_REASONS.get(k, k))}</td><td>{_e(n)}</td></tr>")
        parts.append("</tbody></table>")
    parts.append("<div class='foot'>Generated by Threadscan from model-generated analysis; findings were verified by re-running their reproducers, "
                 "but severity ratings and descriptions are the model's and should be reviewed. Confidential: describes vulnerabilities in private code.</div>")
    parts.append("</div></body></html>")
    return redact("".join(parts))


def export(run_dir: Path, fmt: str, triage: dict | None = None) -> tuple[str, str, str]:
    """(filename, media type, content) for one format."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt}; use one of {', '.join(FORMATS)}")
    data = RunData(run_dir, triage)
    name, ctype = FORMATS[fmt]
    content = {"sarif": lambda: json.dumps(to_sarif(data), indent=1), "csv": lambda: to_csv(data), "json": lambda: to_json(data), "html": lambda: to_html(data),
               "patches": lambda: to_patches(data)}[fmt]()
    return name, ctype, content


def write_exports(run_dir: Path, triage: dict | None = None, formats: tuple[str, ...] = ("sarif", "html", "patches")) -> list[Path]:
    out = []
    for fmt in formats:
        name, _, content = export(run_dir, fmt, triage)
        p = run_dir / name
        p.write_text(content, encoding="utf-8", newline="\n" if fmt != "csv" else "")
        out.append(p)
    return out
