#!/usr/bin/env python3
"""Ablation: disable Qwen thinking through Ollama's OpenAI-compatible control.

Relative to the idempotent desired-state experiment, this changes only one model setting:
`reasoning_effort="none"`. Ollama v0.34.1 maps that value to internal Think=false on
/v1/chat/completions. Model, 2,048-token ceiling, natural sampling, authority projection,
sequencing membrane, idempotent-effect membrane, permission gate, exact postcondition,
bootstrap, and 180-second turn deadline remain unchanged.
"""

from __future__ import annotations

import asyncio
import json

import projected_idempotent_effect_canary as idempotent

base = idempotent.base
REASONING_CONTROL = {"reasoning_effort": "none"}
base.MODEL_SETTINGS = {**base.MODEL_SETTINGS, **REASONING_CONTROL}

print("REASONING_CONTROL=" + json.dumps(REASONING_CONTROL, sort_keys=True))

if __name__ == "__main__":
    raise SystemExit(asyncio.run(idempotent.main()))
