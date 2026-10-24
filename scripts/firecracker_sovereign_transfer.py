#!/usr/bin/env python3
"""Sovereign/local reproduction entry point for the qualified Firecracker RDTE path."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import firecracker_sovereign_preflight as detailed_preflight
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_p3_same_host_handoff as p3

SCHEMA = "firecracker-sovereign-transfer/v1"


def preflight() -> dict:
    detailed = detailed_preflight.build_receipt()
    return {
        "schema": SCHEMA,
        "mode": "preflight",
        "github_actions_environment_required": False,
        "result": {
            "classification": (
                "SUPPORTED"
                if detailed["result"].get("host_admission_prerequisites_pass")
                else detailed["result"].get("classification", "SETUP_REQUIRED")
            ),
            "operationally_qualified": False,
        },
        "detailed_preflight": detailed,
    }

def run_f3(input_path: pathlib.Path) -> dict:
    receipt = f3.run_probe("sovereign-local-f3", input_path)
    return {
        "schema": SCHEMA,
        "mode": "f3",
        "github_actions_environment_required": False,
        "receipt": receipt,
    }


def run_p3() -> dict:
    receipt = p3.run_probe("sovereign-local-p3")
    return {
        "schema": SCHEMA,
        "mode": "p3",
        "github_actions_environment_required": False,
        "receipt": receipt,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    pf = sub.add_parser("preflight")
    pf.add_argument("--out", type=pathlib.Path, required=True)

    wf = sub.add_parser("f3")
    wf.add_argument("--input", type=pathlib.Path, default=f3.DEFAULT_INPUT)
    wf.add_argument("--out", type=pathlib.Path, required=True)

    hp = sub.add_parser("p3")
    hp.add_argument("--out", type=pathlib.Path, required=True)

    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)

    try:
        if args.command == "preflight":
            result = preflight()
            classification = result["result"]["classification"]
        elif args.command == "f3":
            result = run_f3(args.input)
            classification = result["receipt"]["result"]["classification"]
        else:
            result = run_p3()
            classification = result["receipt"]["result"]["classification"]
    except Exception as exc:
        result = {
            "schema": SCHEMA,
            "mode": args.command,
            "github_actions_environment_required": False,
            "result": {
                "classification": "HARNESS_FAILURE",
                "reason": f"{type(exc).__name__}: {exc}",
            },
        }
        classification = "HARNESS_FAILURE"

    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if classification == "SUPPORTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
