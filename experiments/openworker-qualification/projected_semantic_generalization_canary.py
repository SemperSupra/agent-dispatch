#!/usr/bin/env python3
"""Generalize the qualified semantic-transform lane across fresh input values.

Only SOURCE.txt contents and the independently expected postcondition vary by GitHub
run attempt. The qualified semantic capability, adapter, authority, permission gate,
completion reconciliation, model/runtime pins, and validators are reused unchanged.
"""

from __future__ import annotations

import asyncio
import json
import os

import projected_semantic_transform_canary as qualified


def case_for_attempt(attempt: int) -> tuple[int, int, str]:
    if attempt < 1:
        raise ValueError(f"invalid run attempt: {attempt}")
    left = 11 + ((attempt * 37) % 89)
    right = 5 + ((attempt * 53) % 97)
    nonce = f"gen-{attempt:03d}-{(attempt * 7919) % 100000:05d}"
    return left, right, nonce


def main() -> int:
    attempt = int(os.environ.get("GITHUB_RUN_ATTEMPT", "1"))
    left, right, nonce = case_for_attempt(attempt)
    expected = f"sum={left + right}\nnonce={nonce}\n"

    qualified.SOURCE_CONTENT = f"left={left}\nright={right}\nnonce={nonce}\n"
    qualified.EXPECTED = expected

    # The completion-gate experiment intentionally reads the lower-layer base.EXPECTED
    # rather than this semantic adapter's module alias. Keep the desired-state witness
    # dynamically bound to the same independently calculated postcondition so a correct
    # generalized result is not falsely reconciled against the historical sum=42 case.
    qualified.base.EXPECTED = expected
    qualified.completion_gate.base.EXPECTED = expected
    if qualified.EXPECTED != qualified.completion_gate.base.EXPECTED:
        raise RuntimeError("generalization expected-state binding drift")

    print(
        "GENERALIZATION_CASE="
        + json.dumps(
            {
                "run_attempt": attempt,
                "left": left,
                "right": right,
                "expected_sum": left + right,
                "nonce": nonce,
            },
            sort_keys=True,
        )
    )
    return asyncio.run(qualified.main())


if __name__ == "__main__":
    raise SystemExit(main())
