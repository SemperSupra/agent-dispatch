#!/usr/bin/env python3
"""Ablation: bound each local-model completion while preserving prior qualified controls.

This layers one change onto the legible-authority projected canary: OpenWorker's model settings
send max_tokens=1024 through the Ollama OpenAI-compatible provider. Natural sampling remains
unchanged. The 180-second turn ceiling, pinned model/runtime, projected tools, sequencing membrane,
permission gate, authority projection, exact postcondition, and one-write/one-approval criterion
remain unchanged.
"""

from __future__ import annotations

import asyncio
import json

import projected_legible_authority_canary as authority

base = authority.base
GENERATION_BOUND = {"max_tokens": 1024}
base.MODEL_SETTINGS = {**base.MODEL_SETTINGS, **GENERATION_BOUND}

print("GENERATION_BOUND=" + json.dumps(GENERATION_BOUND, sort_keys=True))

if __name__ == "__main__":
    raise SystemExit(asyncio.run(base.main()))
