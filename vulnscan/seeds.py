"""Existing scanner output used as optional seed input for triage.

Seeds are hints, never findings: a seed reaches the report only if the agent turns
it into a candidate and that candidate passes the verification gate.

Supported: SARIF (CodeQL or any SARIF 2.1 producer), gitleaks JSON report, and
osv-scanner JSON. Secret values in gitleaks reports (``Secret``, ``Match``) are
dropped on load and never passed to the agent or written to the run directory.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from vulnscan.components import Component


@dataclass
class Seed:
    id: str
    tool: str
    rule: str
    file: str
    line: int | None
    message: str
    severity: str

    def to_dict(self) -> dict:
        return asdict(self)


def _seed_id(tool: str, rule: str, file: str, line: int | None, extra: str = "") -> str:
    h = hashlib.sha256(f"{tool}|{rule}|{file}|{line}|{extra}".encode()).hexdigest()[:10]
    return f"{tool}-{h}"


def _norm_path(uri: str) -> str:
    if uri.startswith("file:"):
        uri = unquote(urlparse(uri).path)
    uri = uri.replace("\\", "/")
    while uri.startswith("./"):
        uri = uri[2:]
    return uri.lstrip("/")


def _clip(text: str, n: int = 400) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def parse_sarif(data: dict, tool: str = "sarif") -> list[Seed]:
    seeds = []
    for run in data.get("runs") or []:
        driver = ((run.get("tool") or {}).get("driver")) or {}
        tool_name = tool if tool != "sarif" else (driver.get("name") or "sarif").lower()
        rule_sev = {}
        for rule in driver.get("rules") or []:
            props = rule.get("properties") or {}
            if "security-severity" in props:
                rule_sev[rule.get("id")] = str(props["security-severity"])
        for res in run.get("results") or []:
            rule = res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown"
            msg = (res.get("message") or {}).get("text") or ""
            locs = res.get("locations") or []
            phys = (locs[0].get("physicalLocation") or {}) if locs else {}
            file = _norm_path(((phys.get("artifactLocation") or {}).get("uri")) or "")
            line = (phys.get("region") or {}).get("startLine")
            sev = rule_sev.get(rule) or res.get("level") or "warning"
            seeds.append(Seed(_seed_id(tool_name, rule, file, line, msg), tool_name, rule, file, line, _clip(msg), str(sev)))
    return seeds


def parse_gitleaks(data: list) -> list[Seed]:
    seeds = []
    for item in data or []:
        rule = item.get("RuleID") or "unknown"
        file = _norm_path(item.get("File") or "")
        line = item.get("StartLine")
        # Deliberately ignore item["Secret"] and item["Match"].
        desc = item.get("Description") or rule
        fp = item.get("Fingerprint") or ""
        seeds.append(Seed(_seed_id("gitleaks", rule, file, line, fp), "gitleaks", rule, file, line, _clip(f"{desc} (secret value withheld)"), "high"))
    return seeds


def parse_osv(data: dict) -> list[Seed]:
    seeds = []
    for result in data.get("results") or []:
        file = _norm_path(((result.get("source") or {}).get("path")) or "")
        for pkg in result.get("packages") or []:
            p = pkg.get("package") or {}
            name = f"{p.get('ecosystem', '?')}:{p.get('name', '?')}@{p.get('version', '?')}"
            for vuln in pkg.get("vulnerabilities") or []:
                vid = vuln.get("id") or "unknown"
                summary = vuln.get("summary") or ""
                seeds.append(Seed(_seed_id("osv", vid, file, None, name), "osv", vid, file, None, _clip(f"{name}: {summary}"), "unknown"))
    return seeds


def load_seed_file(tool: str, path: Path) -> list[Seed]:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if tool in ("codeql", "sarif"):
        return parse_sarif(data, tool)
    if tool == "gitleaks":
        return parse_gitleaks(data)
    if tool == "osv":
        return parse_osv(data)
    raise ValueError(f"unknown seed tool {tool}")


def assign_seeds(seeds: list[Seed], components: list[Component]) -> tuple[dict[str, list[Seed]], list[Seed]]:
    """Map seeds to the component owning their file; return (by component name, unassigned)."""
    owner = {f: c.name for c in components for f in c.files}
    by_comp: dict[str, list[Seed]] = {}
    unassigned = []
    for s in seeds:
        name = owner.get(s.file)
        if name is None:
            unassigned.append(s)
        else:
            by_comp.setdefault(name, []).append(s)
    return by_comp, unassigned
