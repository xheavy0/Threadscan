from pathlib import Path

import pytest

from threadscan.config import DEFAULT_EXCLUDES, ConfigError, load_project, parse_repo_spec


def test_minimal_config_gets_safe_defaults(target_dir, tmp_path):
    d = target_dir("name: demo\nrepo: ../repo\n")
    cfg = load_project(d)
    assert cfg.name == "demo"
    assert cfg.repo == str((d / "../repo").resolve())
    assert cfg.scan.concurrency == 2  # the owner's machine runs hot
    assert cfg.verification.concurrency == 1
    assert cfg.verification.require_patch_differential is True
    assert cfg.workdir == "/src"
    assert cfg.diff_base == "HEAD~1"
    assert cfg.threat_model_text.startswith("# TM")
    assert cfg.components.exclude[: len(DEFAULT_EXCLUDES)] == DEFAULT_EXCLUDES


def test_full_config(target_dir):
    d = target_dir(
        """
        name: aegis
        repo: https://github.com/example/app.git#develop
        workdir: /work/app
        diff_base: origin/main
        components:
          exclude: ["docs/**"]
          auto:
            - root: backend/src
              depth: 2
          explicit:
            - name: auth
              priority: 5
              paths: ["backend/**/auth/**"]
          leftover: null
        scan:
          concurrency: 4
          effort: medium
          max_budget_usd: 2.5
          memory: 8g
        verification:
          timeout_seconds: 120
          require_patch_differential: false
        seeds:
          - tool: codeql
            path: seeds/x.sarif
        """
    )
    cfg = load_project(d)
    assert cfg.repo_is_url and cfg.repo == "https://github.com/example/app.git" and cfg.branch == "develop"
    assert cfg.components.auto[0].root == "backend/src" and cfg.components.auto[0].depth == 2
    assert cfg.components.explicit[0].priority == 5
    assert cfg.components.leftover is None
    assert "docs/**" in cfg.components.exclude
    assert (cfg.scan.concurrency, cfg.scan.effort, cfg.scan.max_budget_usd, cfg.scan.memory) == (4, "medium", 2.5, "8g")
    assert cfg.verification.require_patch_differential is False
    assert cfg.seeds[0].tool == "codeql" and cfg.seeds[0].path == d / "seeds/x.sarif"


def test_unknown_keys_are_errors_not_ignored(target_dir):
    d = target_dir("name: demo\nrepo: ../r\nscan:\n  concurrancy: 8\n")
    with pytest.raises(ConfigError) as exc:
        load_project(d)
    assert any("concurrancy" in p for p in exc.value.problems)


def test_all_problems_reported_at_once(target_dir):
    d = target_dir(
        """
        name: Bad Name
        repo: ../r
        workdir: relative/path
        scan:
          concurrency: 99
          effort: turbo
          memory: lots
          max_turns: true
        verification:
          timeout_seconds: 1
        components:
          include: ["../outside/**"]
          explicit:
            - name: a
              paths: []
            - name: a
              paths: ["x/**"]
        seeds:
          - tool: semgrep
            path: x.json
        """
    )
    with pytest.raises(ConfigError) as exc:
        load_project(d)
    text = "\n".join(exc.value.problems)
    for needle in ["name:", "workdir", "concurrency", "effort", "memory", "max_turns", "timeout_seconds", "'..'", "paths", "duplicate", "tool"]:
        assert needle in text, needle


def test_missing_dockerfile_and_threat_model(target_dir):
    d = target_dir("name: demo\nrepo: ../r\ndockerfile: nope/Dockerfile\nthreat_model: missing.md\n")
    with pytest.raises(ConfigError) as exc:
        load_project(d)
    text = "\n".join(exc.value.problems)
    assert "dockerfile" in text and "threat_model" in text


def test_threat_model_is_optional(target_dir):
    d = target_dir("name: demo\nrepo: ../r\n")
    (d / "threat_model.md").unlink()
    cfg = load_project(d)
    assert cfg.threat_model is None and cfg.threat_model_text == ""


@pytest.mark.parametrize("spec", ["ext::sh -c touch% /tmp/pwned", "file:///etc", "ftp://x/y"])
def test_dangerous_git_transports_refused(spec, tmp_path):
    with pytest.raises(ConfigError):
        parse_repo_spec(spec, tmp_path)


@pytest.mark.parametrize("spec", ["https://github.com/a/b", "ssh://git@host/a/b.git", "git@github.com:a/b.git"])
def test_git_urls_accepted(spec, tmp_path):
    repo, branch = parse_repo_spec(spec + "#main", tmp_path)
    assert repo == spec and branch == "main"


def test_repo_override(target_dir, tmp_path):
    d = target_dir("name: demo\nrepo: ../r\n")
    cfg = load_project(d, repo_override=str(tmp_path / "other"))
    assert cfg.repo == str(tmp_path / "other")


def test_not_yaml(target_dir):
    d = target_dir("name: [unclosed\n")
    with pytest.raises(ConfigError):
        load_project(d)


def test_shipped_aegis_target_parses():
    cfg = load_project(Path(__file__).resolve().parents[1] / "targets" / "aegis")
    assert cfg.name == "aegis"
    assert cfg.scan.auth == "subscription" and cfg.scan.concurrency == 1
    assert cfg.known_issues == "docs/security/open-findings.md"
    assert "Severity" in cfg.threat_model_text
