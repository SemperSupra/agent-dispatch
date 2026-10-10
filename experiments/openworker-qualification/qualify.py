#!/usr/bin/env python3
"""Independent zero-cost qualification harness for OpenWorker.

This deliberately uses an injected scripted provider: the goal of this first gate is to
qualify OpenWorker's runtime, durable approval/resume, scheduler, REST surface, and installed
entry points without spending model/API credits or exposing credentials to a public runner.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from coworker.automation import Schedule, ScheduledTask, Scheduler, TaskRun, TaskStore
from coworker.providers import AssistantTurn, ModelCapabilities, ProviderClient, ToolCall
from coworker.server.app import create_app
from coworker.server.manager import SessionManager


class ScriptedProvider(ProviderClient):
    def __init__(self, turns):
        self._turns = list(turns)

    def complete(self, *, model, messages, tools=None, **settings):
        if not self._turns:
            raise AssertionError("qualification provider exhausted unexpectedly")
        return self._turns.pop(0)

    def capabilities(self, model):
        return ModelCapabilities()


def tool_turn(name: str, args: dict, call_id: str) -> AssistantTurn:
    return AssistantTurn(tool_calls=[ToolCall(id=call_id, name=name, arguments=args)])


def text_turn(text: str) -> AssistantTurn:
    return AssistantTurn(text=text, finish_reason="stop")


def check_cli_surfaces() -> dict:
    results = {}
    for executable in ("openworker", "openworker-server", "openworker-connectors", "ocw"):
        proc = subprocess.run(
            [executable, "--help"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(
                f"{executable} --help failed with {proc.returncode}: {proc.stdout[-1000:]}"
            )
        results[executable] = "ok"
    return results


async def _run_until_pending(manager: SessionManager, sid: str, engine):
    async def first_turn():
        async for _ in engine.run("write the qualification marker"):
            pass

    task = asyncio.create_task(first_turn())
    pending = []
    for _ in range(150):
        await asyncio.sleep(0.02)
        pending = manager.inbox.pending(sid)
        if pending:
            break
    if not pending:
        task.cancel()
        raise AssertionError("approval never became a durable Inbox item")

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    manager._engines.pop(sid, None)
    manager.mark_idle(sid)
    return pending[0]


async def check_durable_approval_resume(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    workspace = root / "workspace"
    workspace.mkdir()
    target = workspace / "qualification-marker.txt"
    os.environ["COWORKER_STATE_DIR"] = str(root / "state")

    provider = ScriptedProvider(
        [
            tool_turn(
                "write_file",
                {"path": str(target), "content": "openworker-qualified\n"},
                "qualification-write",
            ),
            text_turn("Done — qualification marker written."),
        ]
    )
    manager = SessionManager(
        workspace=workspace,
        data_dir=root / "data",
        provider=provider,
    )
    sid = "qualification-durable-resume"
    engine = manager.get_engine(sid, agent="cowork", workspace=str(workspace))
    item = await _run_until_pending(manager, sid, engine)

    if item.kind != "approval" or item.tool_call_id != "qualification-write":
        raise AssertionError(f"unexpected pending item: {item.kind} {item.tool_call_id}")
    if target.exists():
        raise AssertionError("write_file executed before approval")

    await manager.resolve_inbox(item.id, "allow")

    if target.read_text(encoding="utf-8") != "openworker-qualified\n":
        raise AssertionError("approved write did not produce the expected durable file")
    if manager.inbox.pending(sid):
        raise AssertionError("approval Inbox was not cleared after durable resume")

    record = manager.session_store.load(sid)
    if record is None:
        raise AssertionError("resumed session was not persisted")
    assistant_text = [
        m.get("content")
        for m in record.messages
        if m.get("role") == "assistant" and m.get("content")
    ]
    if not any("qualification marker" in text.lower() for text in assistant_text):
        raise AssertionError("final assistant result was not persisted after resume")

    return {
        "approval_parked_before_side_effect": True,
        "simulated_restart": True,
        "approved_side_effect_executed": True,
        "session_persisted": True,
    }


async def check_scheduler(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    store = TaskStore(root / "automation.db")
    task = ScheduledTask(
        title="Qualification automation",
        instructions="produce a bounded qualification result",
        schedule=Schedule(kind="cron", cron="0 9 * * *", timezone="UTC"),
        workspace=str(root),
    )
    store.save(task)

    async def runner(scheduled_task, trigger):
        # OpenWorker's scheduler deliberately injects execution. The execution runner owns
        # successful TaskRun history persistence; Scheduler owns overlap control and advances
        # the durable task counters/status/next-run state after the runner returns.
        run = TaskRun(
            task_id=scheduled_task.id,
            status="ok",
            trigger=trigger,
            result_text="scheduled qualification executed",
        )
        store.add_run(run)
        return run

    scheduler = Scheduler(store, runner)
    result = await scheduler.run_task(task, trigger="manual")
    if result is None or result.status != "ok":
        raise AssertionError("scheduler did not execute the injected task runner")

    saved = store.get(task.id)
    runs = store.runs(task.id)
    if (
        saved is None
        or saved.run_count != 1
        or saved.last_status != "ok"
        or len(runs) != 1
        or runs[0].status != "ok"
    ):
        raise AssertionError("scheduler/runner state was not durably recorded as contracted")

    return {
        "sqlite_state": True,
        "runner_result_persisted": True,
        "scheduler_state_advanced": True,
        "run_count": saved.run_count,
    }


def check_rest_surface(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    os.environ["COWORKER_STATE_DIR"] = str(root / "rest-state")
    manager = SessionManager(
        workspace=root,
        data_dir=root / "rest-data",
        provider=ScriptedProvider([]),
    )
    task = ScheduledTask(
        title="REST qualification",
        instructions="prove the automation REST surface",
        schedule=Schedule(kind="cron", cron="15 10 * * *", timezone="UTC"),
        workspace=str(root),
    )
    manager.task_store.save(task)
    client = TestClient(create_app(manager))
    response = client.get("/v1/automations")
    if response.status_code != 200:
        raise AssertionError(f"automation REST surface returned {response.status_code}")
    body = response.json()
    if not body.get("tasks") or body["tasks"][0]["title"] != "REST qualification":
        raise AssertionError("automation REST surface did not expose durable task state")
    return {"status_code": 200, "automation_visible": True}


def append_summary(evidence: dict) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as fh:
        fh.write("## OpenWorker zero-cost qualification\n\n")
        fh.write(f"- upstream commit: `{evidence['upstream_sha']}`\n")
        fh.write(f"- result: **{evidence['result']}**\n")
        fh.write("- paid model/API calls: **0**\n")
        fh.write("- provider credentials supplied: **no**\n")
        fh.write(f"- elapsed seconds: `{evidence['elapsed_seconds']}`\n")
        fh.write("- proved: installed CLI surfaces; durable approval/restart/resume/write; scheduler/runner persistence contract; automation REST surface\n")


async def main() -> int:
    started = time.monotonic()
    evidence = {
        "schema_version": 1,
        "upstream_sha": os.environ.get("OPENWORKER_UPSTREAM_SHA", "UNKNOWN"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "model_api_credentials_present": {
            name: bool(os.environ.get(name))
            for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")
        },
        "checks": {},
    }
    try:
        if any(evidence["model_api_credentials_present"].values()):
            raise AssertionError("public zero-cost qualification must not receive model API credentials")

        evidence["checks"]["cli"] = check_cli_surfaces()
        with tempfile.TemporaryDirectory(prefix="openworker-qualification-") as td:
            root = Path(td)
            evidence["checks"]["durable_approval_resume"] = await check_durable_approval_resume(root / "durable")
            evidence["checks"]["scheduler"] = await check_scheduler(root / "scheduler")
            evidence["checks"]["rest"] = check_rest_surface(root / "rest")
        evidence["result"] = "PASS"
        return_code = 0
    except Exception as exc:
        evidence["result"] = "FAIL"
        evidence["error"] = f"{type(exc).__name__}: {exc}"
        return_code = 1
    finally:
        evidence["elapsed_seconds"] = round(time.monotonic() - started, 3)
        print(json.dumps(evidence, indent=2, sort_keys=True))
        append_summary(evidence)
    return return_code


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
