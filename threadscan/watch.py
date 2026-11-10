"""``threadscan watch <target>``: scan new commits as they land, one at a time.

Every interval the target repository is checked (a remote one is fetched first). When HEAD
has moved since the last scanned commit, a diff scan runs with ``--since <last commit>``.

* The first start only records the current commit as the baseline (``--initial`` scans
  right away, against ``diff_base``).
* A failed scan does not advance the baseline, so the same commits are tried again.
* When the subscription's usage limit stops a scan, watching pauses for ``pause_s``
  (default one hour) and the baseline stays put, so the skipped components are covered later.
* ``--recheck`` re-runs the reproducers of open issues after each successful scan.

State lives in ``runs/.watch/<name>.json``.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Callable

INTERVAL_RE = re.compile(r"^(\d+)\s*([smh]?)$")


def parse_interval(text: str) -> int:
    m = INTERVAL_RE.match(text.strip().lower())
    if not m:
        raise ValueError("interval looks like 15m, 1h or 300s")
    n, unit = int(m.group(1)), m.group(2) or "m"
    seconds = n * {"s": 1, "m": 60, "h": 3600}[unit]
    if seconds < 60:
        raise ValueError("interval must be at least 60 seconds")
    return seconds


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1), encoding="utf-8")
    tmp.replace(path)


def watch_once(
    state_path: Path,
    head_fn: Callable[[], str | None],
    scan_fn: Callable[[str | None], Path],
    recheck_fn: Callable[[], dict] | None = None,
    initial: bool = False,
    pause_s: int = 3600,
    now: Callable[[], float] = time.time,
    log: Callable[[str], None] = print,
) -> dict:
    """One check. Returns {"action": baseline|idle|paused|scanned|failed|limit, ...}."""
    state = load_state(state_path)
    t = now()
    if state.get("paused_until", 0) > t:
        return {"action": "paused", "until": state["paused_until"]}
    head = head_fn()
    if not head:
        raise RuntimeError("could not read the target repository's HEAD")
    last = state.get("last_commit")
    if last is None and not initial:
        state.update(last_commit=head, baseline_at=t)
        save_state(state_path, state)
        log(f"baseline set at {head[:12]}; new commits after this will be scanned")
        return {"action": "baseline", "commit": head}
    if last == head:
        state["last_check"] = t
        save_state(state_path, state)
        return {"action": "idle", "commit": head}
    log(f"new commits: {(last or 'diff_base')[:12]} -> {head[:12]}; scanning")
    try:
        run_dir = scan_fn(last)
    except Exception as exc:  # keep the baseline; try the same range next time
        state.update(last_error=f"{type(exc).__name__}: {exc}", last_check=t, failures=state.get("failures", 0) + 1)
        save_state(state_path, state)
        log(f"scan failed: {exc}")
        return {"action": "failed", "error": str(exc)}
    summary = {}
    try:
        summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    state.update(last_run=run_dir.name, last_check=t, failures=0, last_error=None)
    if summary.get("components_skipped"):
        state["paused_until"] = t + pause_s
        save_state(state_path, state)
        log(f"usage limit reached; pausing until {time.strftime('%H:%M', time.localtime(t + pause_s))}, baseline kept at {(last or 'diff_base')[:12]}")
        return {"action": "limit", "run": run_dir.name}
    state["last_commit"] = head
    save_state(state_path, state)
    result = {"action": "scanned", "run": run_dir.name, "verified": summary.get("verified"), "commit": head}
    if recheck_fn is not None:
        try:
            result["recheck"] = recheck_fn().get("summary")
        except Exception as exc:
            log(f"re-check failed: {exc}")
            result["recheck_error"] = str(exc)
    return result


def watch_loop(interval_s: int, once: Callable[[], dict], sleep: Callable[[float], None] = time.sleep,
               log: Callable[[str], None] = print, max_rounds: int | None = None) -> None:
    rounds = 0
    while max_rounds is None or rounds < max_rounds:
        rounds += 1
        try:
            r = once()
            if r["action"] == "scanned":
                log(f"scanned {r['run']}: {r.get('verified', 0)} verified" + (f", re-check {r['recheck']}" if r.get("recheck") else ""))
        except RuntimeError as exc:
            log(f"check failed: {exc}")
        if max_rounds is not None and rounds >= max_rounds:
            break
        sleep(interval_s)
