#!/usr/bin/env python3
"""Ablation: remove the experiment's explicit 2,048-token generation ceiling.

Pinned OpenWorker's OpenAI-compatible provider supplies its own 32,000-token ceiling when
`max_tokens` is absent. This experiment therefore compares the qualified 2,048 configuration
against the provider default, not against an unbounded model.

Only the explicit generation ceiling changes. Provider-controlled no-thinking, one bounded
completion reconciliation, the non-parallel sequencing membrane, idempotent-effect membrane,
legible authority, native PermissionEngine, exact postcondition validator, natural sampling,
pinned model/runtime/bootstrap, and 180-second actor-turn deadline remain unchanged.
"""

from __future__ import annotations

import asyncio
import json

from coworker.providers.openai_provider import DEFAULT_MAX_TOKENS
import projected_completion_gate_canary as gated

base = gated.base
removed = base.MODEL_SETTINGS.pop("max_tokens", None)
if removed != 2048:
    raise RuntimeError(f"expected to ablate max_tokens=2048, found {removed!r}")
if DEFAULT_MAX_TOKENS != 32000:
    raise RuntimeError(
        f"pinned OpenWorker provider default drifted: expected 32000, found {DEFAULT_MAX_TOKENS!r}"
    )

GENERATION_CEILING_ABLATION = {
    "explicit_max_tokens_removed": removed,
    "provider_default_max_tokens": DEFAULT_MAX_TOKENS,
}
print(
    "GENERATION_CEILING_ABLATION="
    + json.dumps(GENERATION_CEILING_ABLATION, sort_keys=True)
)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(gated.main()))
