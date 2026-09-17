#!/usr/bin/env python3
"""Gate 3: minimal actor-projection canary for OpenWorker.

This keeps the same real Ollama model and deterministic file task as the full-worker canary,
but instantiates OpenWorker's TurnEngine directly with only the two capabilities the actor needs:
read_file and write_file. The native PermissionEngine remains in the path and the write must be
explicitly approved by the harness. Authority and answer correctness are deliberately separate:
the approver constrains WHERE the actor may write; the postcondition validator judges WHAT it wrote.

OpenWorker's own capability table declares Ollama models as parallel_tool_calls=False because many
local models fake or mishandle parallel calls. Ollama's Chat Completions compatibility request does
not implement the parallel_tool_calls parameter, so this rep adds the smallest capability-enforcing
membrane at OpenWorker's provider boundary: when a model is declared non-parallel, expose only the
first proposed tool call to the engine, return that observation, and let the next model turn choose
the next action. Suppressed speculative calls are retained as evidence, never executed.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import replace
import json
import os
import platform
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

import aisuite as ai

from coworker.engine import ApprovalOutcome, PermissionRequest, TurnEngine
from coworker.permissions import PermissionEngine
from coworker.providers import AssistantTurn, ModelCapabilities, ProviderClient, StreamChunk
from coworker.providers.router import ProviderRouter
from coworker.tools import ToolRegistry

MODEL = os.environ.get("OPENWORKER_LOCAL_MODEL", "ollama:qwen3:1.7b")
MODEL_SETTINGS = {"parallel_tool_calls": False}
EXPECTED = "sum=42\nnonce=quartz-5819\n"
PROMPT = (
    "/no_think\n"
    "This is a deterministic qualification task. Use file tools, not shell or network. "
    "Read SOURCE.txt from the current workspace. Add the two integer values named left and "
    "right. Then create RESULT.txt containing exactly two lines: first `sum=<integer>` and "
    "second `nonce=<the nonce from SOURCE.txt>`. Do not add Markdown fences, commentary, or "
    "any other bytes to RESULT.txt. After the file is written, briefly report completion."
)


class CapabilityEnforcingProvider(ProviderClient):
    """Honor OpenWorker's non-parallel capability even when a compat endpoint cannot."""

    def __init__(self, delegate: ProviderClient) -> None:
        self.delegate = delegate
        self.suppressed_batches: list[dict[str, Any]] = []

    def capabilities(self, model: str) -> ModelCapabilities:
        return self.delegate.capabilities(model)

    def _enforce(self, model: str, turn: AssistantTurn) -> AssistantTurn:
        calls = list(turn.tool_calls or [])
        if self.capabilities(model).parallel_tool_calls or len(calls) <= 1:
            return turn
        kept = calls[0]
        suppressed = calls[1:]
        self.suppressed_batches.append(
            {
                "kept": {"name": kept.name, "arguments": kept.arguments},
                "suppressed": [
                    {"name": call.name, "arguments": call.arguments}
                    for call in suppressed
                ],
            }
        )
        return replace(turn, tool_calls=[kept])

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        **settings: Any,
    ) -> AssistantTurn:
        turn = self.delegate.complete(
            model=model, messages=messages, tools=tools, **settings
        )
        return self._enforce(model, turn)

    def stream(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: Optional[list[dict[str, Any]]] = None,
        **settings: Any,
    ):
        for chunk in self.delegate.stream(
            model=model, messages=messages, tools=tools, **settings
        ):
            if chunk.turn is None:
                yield chunk
            else:
                yield replace(chunk, turn=self._enforce(model, chunk.turn))


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


def bounded_assistant_text(messages: list[dict]) -> list[str]:
    texts: list[str] = []
    for message in messages:
        if message.get("role") != "assistant":
            continue
        text = str(message.get("content") or "").strip()
        if text:
            texts.append(text[:500])
    return texts[-3:]


def projected_file_registry(workspace: Path) -> ToolRegistry:
    available = {
        getattr(func, "__name__", ""): func
        for func in ai.toolkits.files(root=str(workspace), allow_write=True)
    }
    required = ("read_file", "write_file")
    missing = [name for name in required if name not in available]
    if missing:
        raise AssertionError(f"OpenWorker/aisuite file toolkit missing required tools: {missing}")

    registry = ToolRegistry()
    for name in required:
        registry.register(available[name])
    if registry.names() != list(required):
        raise AssertionError(f"projection drift: {registry.names()}")
    return registry


async def run_canary(root: Path) -> dict:
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    source = workspace / "SOURCE.txt"
    target = workspace / "RESULT.txt"
    source.write_text("left=17\nright=25\nnonce=quartz-5819\n", encoding="utf-8")

    registry = projected_file_registry(workspace)
    permissions = PermissionEngine(workspace_root=workspace)
    provider = CapabilityEnforcingProvider(
        ProviderRouter(secrets=None, default_provider="openai")
    )

    if provider.capabilities(MODEL).parallel_tool_calls:
        raise AssertionError(
            f"qualification expects OpenWorker to declare {MODEL} non-parallel"
        )

    approval_requests: list[dict] = []

    async def approver(request: PermissionRequest) -> ApprovalOutcome:
        snapshot = {
            "tool_name": request.tool_name,
            "arguments": dict(request.arguments or {}),
            "reason": request.reason,
        }
        approval_requests.append(snapshot)

        # This is an AUTHORITY decision only. The actor may write exactly RESULT.txt
        # inside its bounded workspace. Content correctness is tested after execution.
        raw_path = str((request.arguments or {}).get("path") or "")
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = workspace / candidate
        allowed = (
            request.tool_name == "write_file"
            and candidate.resolve() == target.resolve()
        )
        return ApprovalOutcome.ONCE if allowed else ApprovalOutcome.DENY

    engine = TurnEngine(
        provider=provider,
        registry=registry,
        permissions=permissions,
        model=MODEL,
        approver=approver,
        max_iterations=6,
        model_settings=MODEL_SETTINGS,
    )

    event_counts: Counter[str] = Counter()
    salient_events: list[dict] = []

    async def consume() -> None:
        async for event in engine.run(PROMPT):
            event_type = str(event.type)
            event_counts[event_type] += 1
            payload = dict(event.data or {})
            if event_type not in {
                "EventType.REASONING_DELTA",
                "EventType.ASSISTANT_DELTA",
            }:
                compact = {"type": event_type}
                for key in ("tool_calls", "status", "error", "error_type", "iterations"):
                    if key in payload:
                        compact[key] = payload[key]
                salient_events.append(compact)

    started = time.monotonic()
    task = asyncio.create_task(consume())
    try:
        await asyncio.wait_for(task, timeout=180)
    except asyncio.TimeoutError as exc:
        raise AssertionError(
            f"projected local-model turn exceeded 180 seconds; "
            f"event_counts={dict(event_counts)}; salient={salient_events[-12:]}"
        ) from exc
    elapsed = time.monotonic() - started

    names = tool_names_from_messages(engine.messages)
    trace = {
        "model_settings": MODEL_SETTINGS,
        "declared_parallel_tool_calls": provider.capabilities(MODEL).parallel_tool_calls,
        "suppressed_speculative_batches": provider.suppressed_batches,
        "tool_calls": names,
        "approvals": approval_requests,
        "assistant_text_tail": bounded_assistant_text(engine.messages),
        "event_counts": dict(event_counts),
        "salient_events": salient_events,
        "target_exists": target.is_file(),
        "target_content": target.read_text(encoding="utf-8") if target.is_file() else None,
    }
    print("PROJECTED_TRACE=" + json.dumps(trace, sort_keys=True))

    if not target.is_file():
        raise AssertionError(
            f"projected model completed without RESULT.txt; tool_calls={names}; "
            f"approvals={approval_requests}; salient={salient_events[-12:]}"
        )
    observed = target.read_text(encoding="utf-8")
    if observed not in {EXPECTED, EXPECTED.rstrip("\n")}:
        raise AssertionError(
            f"RESULT.txt content mismatch: {observed!r}; tool_calls={names}; "
            f"approvals={approval_requests}"
        )

    if "read_file" not in names:
        raise AssertionError(f"model did not use read_file; observed tools: {names}")
    if "write_file" not in names:
        raise AssertionError(f"model did not use write_file; observed tools: {names}")
    if any(name not in {"read_file", "write_file"} for name in names):
        raise AssertionError(f"actor escaped projected capability set: {names}")
    if len(approval_requests) != 1:
        raise AssertionError(
            f"expected exactly one governed write approval, got {approval_requests}"
        )
    if approval_requests[0]["tool_name"] != "write_file":
        raise AssertionError(f"unexpected approval request: {approval_requests[0]}")

    return {
        "model": MODEL,
        "model_settings": MODEL_SETTINGS,
        "declared_parallel_tool_calls": provider.capabilities(MODEL).parallel_tool_calls,
        "suppressed_batch_count": len(provider.suppressed_batches),
        "projection": registry.names(),
        "tool_schema_count": len(registry.schemas()),
        "tool_schema_chars": len(json.dumps(registry.schemas(), sort_keys=True)),
        "prompt_chars": len(PROMPT),
        "tool_calls": names,
        "approval_count": len(approval_requests),
        "turn_elapsed_seconds": round(elapsed, 3),
        "event_counts": dict(event_counts),
        "result": "PASS",
    }


def append_summary(evidence: dict) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n## OpenWorker projected local-model canary\n\n")
        fh.write(f"- model: `{evidence.get('model')}`\n")
        fh.write(f"- result: **{evidence.get('result')}**\n")
        fh.write(f"- model settings: `{evidence.get('model_settings')}`\n")
        fh.write(f"- declared parallel tool calls: `{evidence.get('declared_parallel_tool_calls')}`\n")
        fh.write(f"- suppressed speculative batches: `{evidence.get('suppressed_batch_count')}`\n")
        fh.write(f"- actor capabilities: `{evidence.get('projection', [])}`\n")
        fh.write(f"- tool schema chars: `{evidence.get('tool_schema_chars')}`\n")
        fh.write(f"- observed tool calls: `{evidence.get('tool_calls', [])}`\n")
        fh.write(f"- governed approvals: `{evidence.get('approval_count', 0)}`\n")
        fh.write(f"- turn seconds: `{evidence.get('turn_elapsed_seconds')}`\n")
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
            raise AssertionError(f"zero-cost projected canary received model credentials: {present}")
        with tempfile.TemporaryDirectory(prefix="openworker-projected-") as td:
            evidence.update(await run_canary(Path(td)))
        code = 0
    except Exception as exc:
        evidence["result"] = "FAIL"
        evidence["error"] = f"{type(exc).__name__}: {exc}"
        evidence["model_settings"] = MODEL_SETTINGS
        code = 1
    finally:
        evidence["elapsed_seconds"] = round(time.monotonic() - started, 3)
        print(json.dumps(evidence, indent=2, sort_keys=True))
        append_summary(evidence)
    return code


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
