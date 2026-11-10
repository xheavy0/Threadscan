"""Runs INSIDE the scan container: one headless Claude agent for one component.

Usage: python agent_runner.py /threadscan/in/task.json /threadscan/out

Writes ``progress.json`` while it works (the dashboard reads it), ``transcript.jsonl``
(text and tool calls, for review) and finally ``candidates.json``. This file must
stay importable without the Agent SDK so the host can test ``extract_json``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import re
import sys
import time
import traceback

TOOLS = ["Read", "Grep", "Glob", "Bash"]
DENIED = ["Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "Task", "Agent"]


def extract_json(text: str | None) -> dict | None:
    """Fallback when structured output is missing: a fenced ```json block, else the outermost {...}."""
    if not text:
        return None
    candidates = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        candidates.append(text[start : end + 1])
    for c in candidates:
        try:
            obj = json.loads(c)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "findings" in obj:
            return obj
    return None


def _write_json(path: str, obj) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, default=str)
    os.replace(tmp, path)


def _brief(value, n: int = 160) -> str:
    s = value if isinstance(value, str) else json.dumps(value, default=str)
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."


def build_options(task: dict, options_cls):
    """Construct ClaudeAgentOptions, dropping fields an older SDK does not know."""
    wanted = {
        "tools": TOOLS,
        "allowed_tools": TOOLS,
        "disallowed_tools": DENIED,
        "permission_mode": "dontAsk",
        "system_prompt": task["system_prompt"],
        # Never load settings, hooks or CLAUDE.md from the target repo: it is untrusted input.
        "setting_sources": [],
        "cwd": task["workdir"],
        "model": task["model"],
        "effort": task.get("effort"),
        "max_turns": task["max_turns"],
        "max_budget_usd": task["max_budget_usd"],
        "output_format": {"type": "json_schema", "schema": task["schema"]},
    }
    known = {f.name for f in dataclasses.fields(options_cls)}
    dropped = sorted(k for k in wanted if k not in known)
    return options_cls(**{k: v for k, v in wanted.items() if k in known and v is not None}), dropped


async def run(task_path: str, out_dir: str) -> int:
    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query  # container-only dependency

    with open(task_path, encoding="utf-8") as fh:
        task = json.load(fh)
    progress_path = os.path.join(out_dir, "progress.json")
    transcript = open(os.path.join(out_dir, "transcript.jsonl"), "a", encoding="utf-8")
    progress = {"state": "running", "started": time.time(), "updated": time.time(), "turns": 0, "tool_calls": 0, "last": ""}
    _write_json(progress_path, progress)

    options, dropped = build_options(task, ClaudeAgentOptions)
    if dropped:
        transcript.write(json.dumps({"t": time.time(), "kind": "warning", "text": f"SDK lacks options: {dropped}"}) + "\n")
        if "tools" in dropped or "setting_sources" in dropped or "permission_mode" in dropped:
            raise RuntimeError(f"installed claude-agent-sdk is too old for a safe run (missing {dropped}); upgrade it in the image")

    result = None
    async for msg in query(prompt=task["user_prompt"], options=options):
        kind = type(msg).__name__
        if isinstance(msg, ResultMessage):
            result = msg
            continue
        for block in getattr(msg, "content", None) or []:
            bkind = type(block).__name__
            if bkind == "TextBlock":
                entry = {"t": time.time(), "kind": "text", "text": block.text}
                progress["last"] = _brief(block.text)
            elif bkind == "ToolUseBlock":
                entry = {"t": time.time(), "kind": "tool", "tool": block.name, "input": _brief(block.input, 400)}
                progress["tool_calls"] += 1
                progress["last"] = f"{block.name}: {_brief(block.input, 120)}"
            else:
                continue
            transcript.write(json.dumps(entry, default=str) + "\n")
        if kind == "AssistantMessage":
            progress["turns"] += 1
        progress["updated"] = time.time()
        _write_json(progress_path, progress)
    transcript.close()

    out = {"component": task["component"]["name"], "structured": None, "parse": None, "result": None}
    if result is not None:
        out["result"] = {
            "subtype": result.subtype,
            "is_error": result.is_error,
            "num_turns": result.num_turns,
            "duration_ms": result.duration_ms,
            "total_cost_usd": result.total_cost_usd,
            "usage": result.usage,
            "model_usage": getattr(result, "model_usage", None),
            "stop_reason": getattr(result, "stop_reason", None),
        }
        structured = getattr(result, "structured_output", None)
        if isinstance(structured, dict):
            out["structured"], out["parse"] = structured, "structured_output"
        else:
            parsed = extract_json(result.result)
            if parsed is not None:
                out["structured"], out["parse"] = parsed, "text_fallback"
    _write_json(os.path.join(out_dir, "candidates.json"), out)
    progress.update(state="done" if out["structured"] is not None else "no_output", updated=time.time())
    _write_json(progress_path, progress)
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    out_dir = argv[2]
    try:
        return asyncio.run(run(argv[1], out_dir))
    except Exception as exc:
        _write_json(os.path.join(out_dir, "candidates.json"), {"error": f"{type(exc).__name__}: {exc}", "trace": traceback.format_exc()[-4000:]})
        _write_json(os.path.join(out_dir, "progress.json"), {"state": "error", "updated": time.time(), "last": f"{type(exc).__name__}: {exc}"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
