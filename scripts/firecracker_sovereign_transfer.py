#!/usr/bin/env python3
"""Sovereign/local reproduction entry point for the qualified Firecracker RDTE path."""
from __future__ import annotations

import argparse
import json
import pathlib
import platform
import shutil
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import firecracker_execution_adapter as exec_adapter
import firecracker_host_fingerprint as hostfp
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_p3_same_host_handoff as p3

SCHEMA = "firecracker-sovereign-transfer/v1"


def _tool(name: str) -> dict:
    path = shutil.which(name)
    return {"available": bool(path), "path": path}


def preflight() -> dict:
    vm = f1._load_json(f3.VMM_MANIFEST)
    kernel = f1._load_json(f3.KERNEL_MANIFEST)
    access = exec_adapter.select_kvm_access()
    tools = {name: _tool(name) for name in ("gcc", "curl", "timeout", "python3")}
    platform_ok = platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"}
    tools_ok = all(item["available"] for item in tools.values())
    supported = platform_ok and tools_ok and access.get("classification") == "SUPPORTED"
    return {
        "schema": SCHEMA,
        "mode": "preflight",
        "result": {
            "classification": "SUPPORTED" if supported else "SETUP_REQUIRED",
            "platform_ok": platform_ok,
            "tools_ok": tools_ok,
            "kvm_ok": access.get("classification") == "SUPPORTED",
        },
        "host_fingerprint": hostfp.fingerprint(),
        "kvm_execution": {
            "mode": access.get("mode"),
            "kvm_api_version": access.get("kvm_api_version"),
            "direct_user_callable": bool((access.get("user_probe") or {}).get("callable")),
            "sudo_fallback_callable": bool((access.get("sudo_probe") or {}).get("callable")),
        },
        "required_tools": tools,
        "portable_artifacts": {
            "firecracker_version": vm["version"],
            "firecracker_url": vm["archive_url"],
            "firecracker_sha256": vm["archive_sha256"],
            "kernel_version": kernel["kernel_version"],
            "kernel_url": kernel["kernel_url"],
            "kernel_sha256": kernel["kernel_sha256"],
            "f3_candidate_source": str(f3.CANDIDATE_SOURCE),
            "f3_guest_init_source": str(f3.INIT_SOURCE),
            "p3_guest_init_source": str(p3.INIT_SOURCE),
        },
        "github_actions_environment_required": False,
        "operational_promotion": {
            "qualified_on_sovereign_host": False,
            "note": (
                "This package reproduces the GHA-qualified mechanics. Operational promotion "
                "requires running F3 and P3 on the intended sovereign KVM host and accepting "
                "those receipts there."
            ),
        },
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
