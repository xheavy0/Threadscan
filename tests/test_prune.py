"""threadscan prune: keeps the newest N, the comparison baseline and live runs; dry run by default."""

import json

import pytest

from threadscan.cli import main
from threadscan.prune import apply_prune, plan_prune


def mk(runs, name, project="demo", started=0.0, phase="done", dry=False):
    d = runs / name
    d.mkdir(parents=True)
    (d / "status.json").write_text(json.dumps({"project": project, "started": started, "phase": phase, "dry_run": dry}))
    (d / "report.md").write_text("x" * 100)
    return d


@pytest.fixture
def runs(tmp_path):
    r = tmp_path / "runs"
    mk(r, "r1", started=1)               # oldest real scan
    mk(r, "r2", started=2, dry=True)
    mk(r, "r3", started=3, dry=True)
    mk(r, "r4", started=4, phase="scanning")  # live
    mk(r, "r5", started=5, phase="failed")
    mk(r, "o1", project="other", started=1)
    (r / "doctor-1").mkdir()
    (r / "doctor-2").mkdir()
    (r / "triage.json").write_text("{}")
    (r / ".watch").mkdir()
    (r / ".watch" / "demo.json").write_text("{}")
    return r


def names(items):
    return sorted(i.path.name for i in items)


def test_plan_keeps_newest_baseline_and_live(runs):
    delete, kept = plan_prune(runs, keep=2)
    # demo finished, newest first: r5 (failed), r3, r2, r1 -> keep r5, r3; r1 kept as the baseline; r4 is live
    assert names(delete) == ["r2"]
    assert {"r1", "r3", "r4", "r5", "o1", "doctor-1", "doctor-2"} <= set(names(kept))
    reasons = {i.path.name: i.reason for i in kept}
    assert "baseline" in reasons["r1"] and reasons["r4"] == "still running"


def test_keep_one_and_project_filter(runs):
    delete, _ = plan_prune(runs, keep=1)
    assert names(delete) == ["doctor-1", "r2", "r3"] or names(delete) == ["doctor-2", "r2", "r3"]
    delete, _ = plan_prune(runs, keep=1, project="other")
    assert delete == []
    with pytest.raises(ValueError):
        plan_prune(runs, keep=0)


def test_cli_is_a_dry_run_unless_yes(runs, capsys):
    assert main(["prune", "--keep", "1", "--runs-dir", str(runs)]) == 0
    assert "dry run" in capsys.readouterr().out and (runs / "r2").exists()
    assert main(["prune", "--keep", "1", "--runs-dir", str(runs), "--yes"]) == 0
    assert not (runs / "r2").exists() and not (runs / "r3").exists()
    assert (runs / "r1").exists() and (runs / "r4").exists() and (runs / "triage.json").exists() and (runs / ".watch" / "demo.json").exists()


def test_apply_never_leaves_the_runs_dir(runs, tmp_path):
    outside = tmp_path / "precious"
    outside.mkdir()
    from threadscan.prune import Item
    assert apply_prune(runs, [Item(outside, "run", "demo", 0)]) == 0 and outside.exists()
