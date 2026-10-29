#!/usr/bin/env python3
"""Ablation: validate observed postcondition before accepting model-declared completion.

Relative to the provider-controlled no-thinking experiment, this changes one behavior only:
when OpenWorker yields a no-tool assistant message while the exact RESULT.txt postcondition is
false, inject one bounded steering message through OpenWorker's existing queue_steering seam and
let the same turn continue. A second false completion is not retried; the existing deterministic
postcondition validator fails the rep.

This is desired-state reconciliation, not generic retry. Model, 2,048-token ceiling, natural
sampling, authority projection, sequencing membrane, idempotent-effect membrane, permission gate,
bootstrap, and 180-second turn deadline remain unchanged. Upstream OpenWorker is immutable.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import tempfile
from typing import Any, Optional

import projected_no_think_canary as no_think

base = no_think.base
_OriginalTurnEngine = base.TurnEngine
_original_run_canary = base.run_canary
_ACTIVE_TARGET: Optional[Path] = None
_LAST_ENGINE: Optional["CompletionGateTurnEngine"] = None
MAX_COMPLETION_RECONCILIATIONS = 1


def _postcondition_state(target: Path) -> dict[str, Any]:
    if not target.is_file():
        return {"satisfied": False, "reason": "RESULT.txt does not exist"}
    try:
        observed = target.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return {
            "satisfied": False,
            "reason": "RESULT.txt is not readable as UTF-8",
            "error_type": type(exc).__name__,
        }
    accepted = {base.EXPECTED, base.EXPECTED.rstrip("\n")}
    if observed in accepted:
        return {
            "satisfied": True,
            "reason": "exact requested file state observed",
            "observed_bytes": len(observed.encode("utf-8")),
        }
    return {
        "satisfied": False,
        "reason": "RESULT.txt content does not satisfy requested postcondition",
        "observed_bytes": len(observed.encode("utf-8")),
        "observed_sha256": hashlib.sha256(observed.encode("utf-8")).hexdigest(),
    }


def _reconciliation_text(state: dict[str, Any]) -> str:
    return (
        "Completion validation failed: "
        + str(state.get("reason") or "the requested postcondition is not satisfied")
        + ". Continue the task using the available tools. Do not report completion until "
        "the requested filesystem postcondition is actually satisfied."
    )


class CompletionGateTurnEngine(_OriginalTurnEngine):
    """Use OpenWorker's native steering queue for one evidence-bearing reconciliation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.completion_reconciliations: list[dict[str, Any]] = []
        global _LAST_ENGINE
        _LAST_ENGINE = self

    async def run(self, *args: Any, **kwargs: Any):
        async for event in super().run(*args, **kwargs):
            if str(event.type) == "EventType.ASSISTANT_MESSAGE":
                payload = dict(event.data or {})
                if not payload.get("tool_calls") and _ACTIVE_TARGET is not None:
                    state = _postcondition_state(_ACTIVE_TARGET)
                    if (
                        not state["satisfied"]
                        and len(self.completion_reconciliations)
                        < MAX_COMPLETION_RECONCILIATIONS
                    ):
                        record = {
                            "attempt": len(self.completion_reconciliations) + 1,
                            "state": state,
                            "action": "queue_steering",
                        }
                        self.completion_reconciliations.append(record)
                        self.queue_steering(_reconciliation_text(state))
                        print(
                            "COMPLETION_RECONCILIATION="
                            + json.dumps(record, sort_keys=True)
                        )
            yield event


def verify_completion_gate_deterministically() -> None:
    """Witness the exact-state decision without depending on stochastic model behavior."""

    with tempfile.TemporaryDirectory(prefix="openworker-completion-witness-") as td:
        target = Path(td) / "RESULT.txt"
        missing = _postcondition_state(target)
        if missing["satisfied"] or "does not exist" not in missing["reason"]:
            raise AssertionError(f"missing-target witness failed: {missing}")

        target.write_text("wrong\n", encoding="utf-8")
        wrong = _postcondition_state(target)
        if wrong["satisfied"] or "sha256" not in "".join(wrong.keys()):
            raise AssertionError(f"wrong-content witness failed: {wrong}")

        target.write_text(base.EXPECTED, encoding="utf-8")
        correct = _postcondition_state(target)
        if not correct["satisfied"]:
            raise AssertionError(f"exact-state witness failed: {correct}")

    print("COMPLETION_GATE_WITNESS=PASS")


async def run_canary(root: Path) -> dict[str, Any]:
    global _ACTIVE_TARGET, _LAST_ENGINE
    _ACTIVE_TARGET = (root / "workspace" / "RESULT.txt").resolve()
    _LAST_ENGINE = None
    try:
        evidence = await _original_run_canary(root)
        reconciliations = (
            list(_LAST_ENGINE.completion_reconciliations)
            if _LAST_ENGINE is not None
            else []
        )
        evidence["completion_reconciliations"] = reconciliations
        evidence["completion_reconciliation_count"] = len(reconciliations)
        print(
            "COMPLETION_RECONCILIATIONS="
            + json.dumps(reconciliations, sort_keys=True)
        )
        return evidence
    finally:
        _ACTIVE_TARGET = None


# Patch only this experiment harness. Upstream OpenWorker remains immutable.
base.TurnEngine = CompletionGateTurnEngine
base.run_canary = run_canary


async def main() -> int:
    verify_completion_gate_deterministically()
    # Preserve the already-qualified deterministic idempotent-effect witness as well.
    return await no_think.idempotent.main()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
