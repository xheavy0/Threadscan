import json

from vulnscan.components import Component
from vulnscan.seeds import assign_seeds, load_seed_file, parse_gitleaks, parse_osv, parse_sarif

SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "java/ssrf", "properties": {"security-severity": "9.1"}}]}},
        "results": [
            {"ruleId": "java/ssrf", "level": "error", "message": {"text": "Potential   SSRF\nhere"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "./backend/Net.java"}, "region": {"startLine": 42}}}]},
            {"ruleId": "js/xss", "message": {"text": "xss"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///src/app/View.tsx"}, "region": {"startLine": 3}}}]},
        ],
    }],
}
GITLEAKS = [{"RuleID": "generic-api-key", "File": "deploy/.env.example", "StartLine": 4, "Description": "Generic API Key", "Secret": "hunter2-supersecret", "Match": "KEY=hunter2-supersecret", "Fingerprint": "deploy/.env.example:generic-api-key:4"}]
OSV = {"results": [{"source": {"path": "package-lock.json", "type": "lockfile"}, "packages": [{"package": {"name": "undici", "version": "6.0.0", "ecosystem": "npm"}, "vulnerabilities": [{"id": "GHSA-xxxx", "summary": "request smuggling"}]}]}]}


def test_sarif():
    seeds = parse_sarif(SARIF, "codeql")
    assert [s.file for s in seeds] == ["backend/Net.java", "src/app/View.tsx"]
    assert seeds[0].line == 42 and seeds[0].severity == "9.1" and seeds[0].message == "Potential SSRF here"
    assert seeds[1].severity == "warning"
    assert seeds[0].id.startswith("codeql-") and seeds[0].id != seeds[1].id


def test_generic_sarif_takes_driver_name():
    assert parse_sarif(SARIF, "sarif")[0].tool == "codeql"


def test_gitleaks_never_keeps_the_secret():
    seeds = parse_gitleaks(GITLEAKS)
    blob = json.dumps([s.to_dict() for s in seeds])
    assert "hunter2" not in blob
    assert seeds[0].file == "deploy/.env.example" and seeds[0].line == 4 and "withheld" in seeds[0].message


def test_osv():
    seeds = parse_osv(OSV)
    assert seeds[0].rule == "GHSA-xxxx" and seeds[0].file == "package-lock.json" and "npm:undici@6.0.0" in seeds[0].message


def test_load_seed_file_handles_bom(tmp_path):
    p = tmp_path / "x.sarif"
    p.write_text("﻿" + json.dumps(SARIF), encoding="utf-8")
    assert len(load_seed_file("codeql", p)) == 2


def test_assign_seeds_by_file():
    comps = [Component("net", "explicit", files=["backend/Net.java"]), Component("ui", "auto", files=["src/app/View.tsx"])]
    by, unassigned = assign_seeds(parse_sarif(SARIF) + parse_gitleaks(GITLEAKS), comps)
    assert [s.file for s in by["net"]] == ["backend/Net.java"]
    assert [s.file for s in by["ui"]] == ["src/app/View.tsx"]
    assert [s.tool for s in unassigned] == ["gitleaks"]
