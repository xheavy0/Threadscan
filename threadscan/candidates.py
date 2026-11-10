"""Candidate findings as reported by an agent, before verification.

A candidate is a claim. It becomes a finding only after the verification gate
(``verify.py``) has re-run its reproducer in a fresh, offline container.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
NONCE_VAR = "THREADSCAN_NONCE"
PROOF_PREFIX = "THREADSCAN-PROOF:"

MAX_SCRIPT_BYTES = 64_000
MAX_FILES = 20
MAX_FILES_BYTES = 400_000
MAX_PATCH_BYTES = 200_000

# JSON schema handed to the Agent SDK as ``output_format``.
CANDIDATE_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings", "seed_triage", "notes"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "title", "severity", "severity_rationale", "cwe", "file", "line",
                    "description", "impact", "reproducer", "patch", "self_test",
                ],
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": list(SEVERITIES)},
                    "severity_rationale": {"type": "string"},
                    "cwe": {"type": "string"},
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "description": {"type": "string"},
                    "impact": {"type": "string"},
                    "seed_ids": {"type": "array", "items": {"type": "string"}},
                    "reproducer": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["script", "files"],
                        "properties": {
                            "script": {"type": "string"},
                            "files": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "required": ["path", "content"],
                                    "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                                },
                            },
                            "timeout_seconds": {"type": "integer"},
                        },
                    },
                    "patch": {"type": "string"},
                    "self_test": {"type": "string"},
                },
            },
        },
        "seed_triage": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["seed_id", "verdict", "reason"],
                "properties": {
                    "seed_id": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "unsure", "not_reviewed"]},
                    "reason": {"type": "string"},
                },
            },
        },
        "notes": {"type": "string"},
    },
}


@dataclass
class ReproFile:
    path: str
    content: str


@dataclass
class Candidate:
    id: str
    component: str
    title: str
    severity: str
    severity_rationale: str
    cwe: str
    file: str
    line: int
    description: str
    impact: str
    script: str
    files: list[ReproFile] = field(default_factory=list)
    timeout_seconds: int | None = None
    patch: str = ""
    self_test: str = ""
    seed_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def safe_relpath(path: str) -> bool:
    if not isinstance(path, str) or not path or "\0" in path:
        return False
    p = path.replace("\\", "/")
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        return False
    parts = PurePosixPath(p).parts
    return ".." not in parts and ".git" not in parts and len(parts) > 0


def candidate_id(component: str, file: str, title: str) -> str:
    norm = re.sub(r"\s+", " ", title.strip().lower())
    return "TS-" + hashlib.sha256(f"{component}|{file}|{norm}".encode()).hexdigest()[:10]


def _s(raw: dict, key: str) -> str:
    v = raw.get(key)
    return v.strip() if isinstance(v, str) else ""


def validate_candidate(raw: object, component: str) -> tuple[Candidate | None, list[str]]:
    """Return (candidate, []) or (None, problems). Never repairs a bad claim."""
    if not isinstance(raw, dict):
        return None, ["candidate is not an object"]
    errors = []
    for key in ("title", "severity", "file", "description", "impact"):
        if not _s(raw, key):
            errors.append(f"missing {key}")
    sev = _s(raw, "severity").lower()
    if sev and sev not in SEVERITIES:
        errors.append(f"severity '{sev}' not one of {SEVERITIES}")
    file = _s(raw, "file").replace("\\", "/")
    if file and not safe_relpath(file):
        errors.append("file must be a path relative to the repo root")
    line = raw.get("line")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        errors.append("line must be a positive integer")

    repro = raw.get("reproducer")
    script, files, timeout = "", [], None
    if not isinstance(repro, dict):
        errors.append("missing reproducer")
    else:
        script = repro.get("script") if isinstance(repro.get("script"), str) else ""
        if not script.strip():
            errors.append("reproducer.script is empty")
        elif len(script.encode()) > MAX_SCRIPT_BYTES:
            errors.append("reproducer.script too large")
        elif NONCE_VAR not in script:
            errors.append(f"reproducer.script never references ${NONCE_VAR}, so it cannot print a proof line")
        raw_files = repro.get("files") or []
        if not isinstance(raw_files, list) or len(raw_files) > MAX_FILES:
            errors.append(f"reproducer.files must be a list of at most {MAX_FILES}")
            raw_files = []
        total = 0
        for f in raw_files:
            if not isinstance(f, dict) or not safe_relpath(f.get("path", "")) or not isinstance(f.get("content"), str):
                errors.append(f"reproducer.files entry has an unsafe or missing path: {f.get('path') if isinstance(f, dict) else f!r}")
                continue
            total += len(f["content"].encode())
            files.append(ReproFile(f["path"].replace("\\", "/"), f["content"]))
        if total > MAX_FILES_BYTES:
            errors.append("reproducer.files too large")
        t = repro.get("timeout_seconds")
        if isinstance(t, int) and not isinstance(t, bool) and t > 0:
            timeout = t

    patch = raw.get("patch") if isinstance(raw.get("patch"), str) else ""
    if len(patch.encode()) > MAX_PATCH_BYTES:
        errors.append("patch too large")
    if errors:
        return None, errors

    seed_ids = [s for s in raw.get("seed_ids") or [] if isinstance(s, str)]
    title = _s(raw, "title")
    return (
        Candidate(
            id=candidate_id(component, file, title),
            component=component,
            title=title,
            severity=sev,
            severity_rationale=_s(raw, "severity_rationale"),
            cwe=_s(raw, "cwe"),
            file=file,
            line=line,
            description=_s(raw, "description"),
            impact=_s(raw, "impact"),
            script=script,
            files=files,
            timeout_seconds=timeout,
            patch=patch.strip("\n") + "\n" if patch.strip() else "",
            self_test=_s(raw, "self_test"),
            seed_ids=seed_ids,
        ),
        [],
    )


def is_duplicate(a: Candidate, b: Candidate) -> bool:
    if a.file != b.file or abs(a.line - b.line) > 5:
        return False
    if a.cwe and b.cwe:
        return a.cwe.upper() == b.cwe.upper()
    return re.sub(r"\W+", "", a.title.lower()) == re.sub(r"\W+", "", b.title.lower())


def dedupe(cands: list[Candidate]) -> tuple[list[Candidate], list[Candidate]]:
    """Keep the first of each duplicate group (input should be sorted by preference)."""
    kept: list[Candidate] = []
    dups: list[Candidate] = []
    for c in cands:
        if any(c.id == k.id or is_duplicate(c, k) for k in kept):
            dups.append(c)
        else:
            kept.append(c)
    return kept, dups
