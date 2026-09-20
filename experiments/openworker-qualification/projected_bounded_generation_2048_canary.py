#!/usr/bin/env python3
"""Ablation: test a 2,048-token local-model completion bound.

This changes only the per-model-call max_tokens value relative to the qualified
legible-authority actor configuration. Natural sampling, the 180-second turn ceiling,
pinned model/runtime, ephemeral bootstrap, projected tools, sequencing membrane,
permission gate, authority projection, exact postcondition, and one-write/one-approval
criterion remain unchanged.
"""

from __future__ import annotations

import asyncio
import json

import projected_legible_authority_canary as authority

base = authority.base
GENERATION_BOUND = {"max_tokens": 2048}
base.MODEL_SETTINGS = {**base.MODEL_SETTINGS, **GENERATION_BOUND}

print("GENERATION_BOUND=" + json.dumps(GENERATION_BOUND, sort_keys=True))

if __name__ == "__main__":
    raise SystemExit(asyncio.run(base.main()))
