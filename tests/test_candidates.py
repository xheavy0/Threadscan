import pytest
from helpers import candidate, raw_candidate

from vulnscan.candidates import CANDIDATE_SCHEMA, dedupe, safe_relpath, validate_candidate


def test_valid_candidate():
    c = candidate()
    assert c.id.startswith("VS-") and c.severity == "critical" and c.line == 1
    assert c.files[0].path == "app/LoginTest.java"
    assert c.patch.endswith("\n")


def test_id_is_stable_and_depends_on_component_file_title():
    assert candidate().id == candidate().id
    assert candidate().id != candidate(title="other").id
    assert candidate().id != candidate(component="other").id


@pytest.mark.parametrize(
    "over,needle",
    [
        ({"title": ""}, "title"),
        ({"severity": "catastrophic"}, "severity"),
        ({"file": "/etc/passwd"}, "relative"),
        ({"file": "../x.java"}, "relative"),
        ({"line": 0}, "line"),
        ({"line": "12"}, "line"),
        ({"line": True}, "line"),
        ({"reproducer": None}, "reproducer"),
        ({"reproducer": {"script": "", "files": []}}, "empty"),
        ({"reproducer": {"script": "echo proof", "files": []}}, "VULNSCAN_NONCE"),
        ({"reproducer": {"script": "echo $VULNSCAN_NONCE", "files": [{"path": "../../etc/x", "content": ""}]}}, "unsafe"),
        ({"reproducer": {"script": "echo $VULNSCAN_NONCE", "files": [{"path": "C:/x", "content": ""}]}}, "unsafe"),
        ({"reproducer": {"script": "echo $VULNSCAN_NONCE", "files": [{"path": ".git/hooks/pre-commit", "content": ""}]}}, "unsafe"),
        ({"patch": "x" * 300_000}, "patch too large"),
    ],
)
def test_invalid_candidates_are_rejected_not_repaired(over, needle):
    c, errs = validate_candidate(raw_candidate(**over), "auth")
    assert c is None
    assert any(needle in e for e in errs), errs


def test_non_object():
    assert validate_candidate(["x"], "a")[0] is None


def test_safe_relpath():
    assert safe_relpath("src/a/b.ts")
    for bad in ["", "/abs", "a/../../b", "C:\\x", "a\0b", ".git/config"]:
        assert not safe_relpath(bad), bad


def test_dedupe_same_cwe_nearby_lines():
    a = candidate(line=10)
    b = candidate(line=13, title="Different wording, same bug")
    c = candidate(line=40, title="Far away")
    d = candidate(line=11, cwe="CWE-79", title="Other class")
    kept, dups = dedupe([a, b, c, d])
    assert [x.id for x in kept] == [a.id, c.id, d.id]
    assert [x.id for x in dups] == [b.id]


def test_dedupe_without_cwe_uses_title():
    a = candidate(cwe="", title="SQL injection in search")
    b = candidate(cwe="", title="SQL Injection in search!", line=2)
    kept, dups = dedupe([a, b])
    assert len(kept) == 1 and len(dups) == 1


def test_schema_requires_reproducer_and_patch():
    item = CANDIDATE_SCHEMA["properties"]["findings"]["items"]
    assert {"reproducer", "patch", "file", "line", "severity"} <= set(item["required"])
    assert item["properties"]["severity"]["enum"] == ["critical", "high", "medium", "low", "info"]
