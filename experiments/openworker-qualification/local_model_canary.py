#!/usr/bin/env python3
"""Gate 2: real local-model tool-use canary for OpenWorker.

Runs OpenWorker with its native Ollama provider path. No model/API credentials are allowed.
The model must read private-to-the-prompt workspace data, derive the expected answer, request a
write through OpenWorker's governance surface, and produce a deterministically validated file.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import sys
import tempfile
import time
from pathlib import Path

from coworker.server.manager import SessionManager

MODEL = os.environ.get("OPENWORKER_LOCAL_MODEL", "ollama:qwen3:0.6b")
EXPECTED = "sum=42\nnonce=quartz-5819\n"


def tool_names_from_messages(messages: list[dict]) -> list[str]:
    out: list[str] = []
    for message in messages:
        if message.get("role") != "assistant":
            continue
        for call in message.get("tool_calls") or []:
            fn = call.get("function") or {}
            name = fn.get("name")
            if name:
                out.append(str(name))
    return out


async def run_canary(root: Path) -> dict:
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    source = workspace / "SOURCE.txt"
    target = workspace / "RESULT.txt"
    source.write_text("left=17\nright=25\nnonce=quartz-5819\n", encoding="utf-8")

    # Keep all OpenWorker state ephemeral and separate from the checked-out public repository.
    os.environ["COWORKER_STATE_DIR"] = str(root / "state")
    manager = SessionManager(
        workspace=workspace,
        data_dir=root / "data",
        model=MODEL,
    )
    sid = "local-model-canary"
    engine = manager.get_engine(sid, agent="cowork", workspace=str(workspace))

    prompt = (
        "/no_think\n"
        "This is a deterministic qualification task. Use file tools, not shell or network. "
        "Read SOURCE.txt from the current workspace. Add the two integer values named left and "
        "right. Then create RESULT.txt containing exactly two lines: first `sum=<integer>` and "
        "second `nonce=<the nonce from SOURCE.txt>`. Do not add Markdown fences, commentary, or "
        "any other bytes to RESULT.txt. After the file is written, briefly report completion."
    )

    events: list[dict] = []
    approval_count = 0
    unexpected_attention: list[dict] = []
    seen_items: set[str] = set()

    async def consume() -> None:
        async for event in engine.run(prompt):
            payload = dict(event.data or {})
            # Keep evidence compact: event type and tool names/status/error only.
            compact = {"type": str(event.type)}
            for key in ("tool_calls", "status", "error", "error_type"):
                if key in payload:
                    compact[key] = payload[key]
            events.append(compact)

    task = asyncio.create_task(consume())
    deadline = time.monotonic() + 180
    while not task.done():
        if time.monotonic() > deadline:
            task.cancel()
            raise AssertionError("local-model OpenWorker turn exceeded 180 seconds")

        for item in manager.inbox.pending(sid):
            if item.id in seen_items:
                continue
            seen_items.add(item.id)
            snapshot = {
                "kind": item.kind,
                "title": item.title,
                "body": item.body,
            }
            if item.kind != "approval":
                unexpected_attention.append(snapshot)
                await manager.resolve_inbox(item.id, "qualification does not permit questions")
                task.cancel()
                raise AssertionError(f"unexpected human-attention request: {snapshot}")

            title = item.title.lower()
            body = item.body
            allowed = (
                "write_file" in title
                and "RESULT.txt" in body
                and "sum=42" in body
                and "nonce=quartz-5819" in body
            )
            if not allowed:
                unexpected_attention.append(snapshot)
                await manager.resolve_inbox(item.id, "deny")
                task.cancel()
                raise AssertionError(f"unexpected or incorrect requested side effect: {snapshot}")

            approval_count += 1
            await manager.resolve_inbox(item.id, "allow")

        await asyncio.sleep(0.05)

    await task
    manager.save(sid, engine)

    if not target.is_file():
        raise AssertionError("real model completed without producing RESULT.txt")
    observed = target.read_text(encoding="utf-8")
    if observed != EXPECTED:
        raise AssertionError(f"RESULT.txt content mismatch: {observed!r}")

    names = tool_names_from_messages(engine.messages)
    if "read_file" not in names:
        raise AssertionError(f"model did not use read_file; observed tools: {names}")
    if "write_file" not in names:
        raise AssertionError(f"model did not use write_file; observed tools: {names}")
    if approval_count != 1:
        raise AssertionError(f"expected exactly one governed write approval, got {approval_count}")

    return {
        "model": MODEL,
        "tool_calls": names,
        "approval_count": approval_count,
        "result_sha256_source": "validated exact bytes",
        "result": "PASS",
        "unexpected_attention": unexpected_attention,
    }


def append_summary(evidence: dict) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n## OpenWorker local-model canary\n\n")
        fh.write(f"- model: `{evidence.get('model')}`\n")
        fh.write(f"- result: **{evidence.get('result')}**\n")
        fh.write(f"- observed tool calls: `{evidence.get('tool_calls', [])}`\n")
        fh.write(f"- governed approvals: `{evidence.get('approval_count', 0)}`\n")
        fh.write("- model/API credentials: **none**\n")


async def main() -> int:
    started = time.monotonic()
    evidence = {
        "schema_version": 1,
        "model": MODEL,
        "platform": platform.platform(),
        "python": sys.version.split()[0],
    }
    credential_names = (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OLLAMA_API_KEY",
    )
    try:
        present = [name for name in credential_names if os.environ.get(name)]
        if present:
            raise AssertionError(f"zero-cost sovereign canary received model credentials: {present}")
        with tempfile.TemporaryDirectory(prefix="openworker-local-model-") as td:
            evidence.update(await run_canary(Path(td)))
        code = 0
    except Exception as exc:
        evidence["result"] = "FAIL"
        evidence["error"] = f"{type(exc).__name__}: {exc}"
        code = 1
    finally:
        evidence["elapsed_seconds"] = round(time.monotonic() - started, 3)
        print(json.dumps(evidence, indent=2, sort_keys=True))
        append_summary(evidence)
    return code


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
