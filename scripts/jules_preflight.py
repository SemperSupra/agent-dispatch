#!/usr/bin/env python3
"""Sanitized, non-mutating readiness preflight for approved Jules dispatch inputs.

The preflight deliberately reuses the hardened dispatcher policy and provider
source-resolution functions. It validates only that the opaque target and task
are admitted and that the target has exactly one Jules Source. It never creates
a Jules session and never prints repository, branch, source, prompt, credential,
or provider metadata.
"""

from __future__ import annotations

import argparse
import json

from jules import load_task, resolve_source, resolve_target


def preflight(target: str, task: str) -> dict:
    repository, _branch = resolve_target(target)
    load_task(task)
    resolve_source(repository)
    return {
        "ready": True,
        "target": target,
        "task": task,
        "target_policy": "approved",
        "task_policy": "approved",
        "jules_source": "available-unique",
        "session_created": False,
        "authority_mutation": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="approved opaque target ID")
    parser.add_argument("--task", required=True, help="approved task ID")
    args = parser.parse_args()
    print(json.dumps(preflight(args.target, args.task), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
