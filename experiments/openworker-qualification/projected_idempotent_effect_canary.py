#!/usr/bin/env python3
"""Ablation: suppress only provably redundant idempotent file-replacement effects.

This keeps the current 2,048-token candidate configuration fixed and adds one behavioral
primitive: after the sequencing membrane, an exact `write_file(..., overwrite=True)` proposal
is suppressed before authorization when the bounded workspace already contains exactly the
requested bytes at that path. The suppression is evidence-bearing; non-idempotent operations,
failed/mismatched postconditions, paths outside the workspace, and non-overwrite writes pass
through unchanged.

This is desired-state reconciliation, not generic tool-call deduplication. The native
PermissionEngine remains authoritative for every effect that is not already satisfied.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import tempfile
from typing import Any, Optional

from coworker.providers import AssistantTurn, ModelCapabilities, ProviderClient, ToolCall

import projected_bounded_generation_2048_canary as bounded

base = bounded.base
_OriginalProvider = base.CapabilityEnforcingProvider
_original_run_canary = base.run_canary
_ACTIVE_WORKSPACE: Optional[Path] = None
_LAST_PROVIDER: Optional["DesiredStateEffectProvider"] = None


class DesiredStateEffectProvider(_OriginalProvider):
    """Suppress an already-satisfied idempotent file replacement before approval/execution."""

    def __init__(self, delegate: ProviderClient) -> None:
        super().__init__(delegate)
        self.idempotent_effect_suppressions: list[dict[str, Any]] = []
        global _LAST_PROVIDER
        _LAST_PROVIDER = self

    def _already_satisfied_write(self, call: ToolCall) -> Optional[dict[str, Any]]:
        workspace = _ACTIVE_WORKSPACE
        if workspace is None or call.name != "write_file":
            return None

        args = dict(call.arguments or {})
        # This experiment only treats explicit replacement semantics as idempotent.
        if args.get("overwrite") is not True:
            return None
        raw_path = str(args.get("path") or "")
        content = args.get("content")
        if not raw_path or not isinstance(content, str):
            return None

        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = workspace / candidate
        try:
            resolved_workspace = workspace.resolve()
            resolved = candidate.resolve()
            relative = resolved.relative_to(resolved_workspace)
        except (OSError, ValueError):
            return None

        if not resolved.is_file():
            return None
        try:
            observed = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return None
        if observed != content:
            return None

        return {
            "tool_name": call.name,
            "path": str(relative),
            "reason": "exact desired file state already satisfied",
            "content_bytes": len(content.encode("utf-8")),
        }

    def _enforce(self, model: str, turn: AssistantTurn) -> AssistantTurn:
        # Preserve the already-qualified non-parallel sequencing membrane first.
        turn = super()._enforce(model, turn)
        calls = list(turn.tool_calls or [])
        if len(calls) != 1:
            return turn

        suppression = self._already_satisfied_write(calls[0])
        if suppression is None:
            return turn
        self.idempotent_effect_suppressions.append(suppression)
        return replace(turn, tool_calls=[])


class _StubProvider(ProviderClient):
    """Deterministic witness delegate; no model call should occur."""

    def capabilities(self, model: str) -> ModelCapabilities:
        return ModelCapabilities(parallel_tool_calls=False)

    def complete(self, *, model: str, messages: list[dict[str, Any]], tools=None, **settings):
        raise AssertionError("deterministic membrane witness must not call the model")

    def stream(self, *, model: str, messages: list[dict[str, Any]], tools=None, **settings):
        raise AssertionError("deterministic membrane witness must not call the model")
        yield  # pragma: no cover


def verify_membrane_deterministically() -> None:
    """Exercise the suppression path without depending on stochastic model behavior."""

    global _ACTIVE_WORKSPACE
    with tempfile.TemporaryDirectory(prefix="openworker-idempotent-witness-") as td:
        workspace = Path(td).resolve()
        target = workspace / "RESULT.txt"
        wanted = "sum=42\nnonce=quartz-5819"
        target.write_text(wanted, encoding="utf-8")
        _ACTIVE_WORKSPACE = workspace

        provider = DesiredStateEffectProvider(_StubProvider())
        proposed = AssistantTurn(
            tool_calls=[
                ToolCall(
                    id="duplicate-write",
                    name="write_file",
                    arguments={
                        "path": "RESULT.txt",
                        "content": wanted,
                        "overwrite": True,
                    },
                )
            ]
        )
        filtered = provider._enforce("witness", proposed)
        if filtered.tool_calls:
            raise AssertionError("already-satisfied idempotent write was not suppressed")
        if len(provider.idempotent_effect_suppressions) != 1:
            raise AssertionError(
                "expected exactly one deterministic idempotent-effect suppression, got "
                f"{provider.idempotent_effect_suppressions}"
            )
        if target.read_text(encoding="utf-8") != wanted:
            raise AssertionError("suppression witness unexpectedly mutated the target")

    _ACTIVE_WORKSPACE = None
    print("IDEMPOTENT_EFFECT_MEMBRANE_WITNESS=PASS")


async def run_canary(root: Path) -> dict[str, Any]:
    global _ACTIVE_WORKSPACE, _LAST_PROVIDER
    _ACTIVE_WORKSPACE = (root / "workspace").resolve()
    _LAST_PROVIDER = None
    try:
        evidence = await _original_run_canary(root)
        suppressions = (
            list(_LAST_PROVIDER.idempotent_effect_suppressions)
            if _LAST_PROVIDER is not None
            else []
        )
        evidence["idempotent_effect_suppressions"] = suppressions
        evidence["idempotent_effect_suppression_count"] = len(suppressions)
        print("IDEMPOTENT_EFFECT_SUPPRESSIONS=" + json.dumps(suppressions, sort_keys=True))
        return evidence
    finally:
        _ACTIVE_WORKSPACE = None


# Patch only the experiment harness. Upstream OpenWorker remains immutable.
base.CapabilityEnforcingProvider = DesiredStateEffectProvider
base.run_canary = run_canary


async def main() -> int:
    verify_membrane_deterministically()
    return await base.main()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
