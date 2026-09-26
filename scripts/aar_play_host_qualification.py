#!/usr/bin/env python3
"""Run the AAR Play-host lifecycle as one bounded GitHub-runner qualification rep."""
from __future__ import annotations

import argparse
import json
import pathlib
import platform
import shutil
import subprocess
import sys
from typing import Any


def run_stage(
    tool: pathlib.Path,
    state: pathlib.Path,
    command: list[str],
) -> tuple[int, dict[str, Any], str]:
    argv = [sys.executable, str(tool), "--state-root", str(state), "--format", "json", *command]
    cp = subprocess.run(
        argv,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    payload: dict[str, Any] = {}
    if cp.stdout.strip():
        try:
            payload = json.loads(cp.stdout)
        except json.JSONDecodeError:
            payload = {}
    return cp.returncode, payload, (cp.stderr or "")[-4000:]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--aar-root", type=pathlib.Path, required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    p.add_argument("--expect", choices=("supported", "unsupported", "venue-limited"), default="supported")
    args = p.parse_args()

    aar = args.aar_root.resolve()
    tool = aar / "tools" / "aar_play_host.py"
    state = aar / ".local" / "gha-play-host"
    if state.exists():
        shutil.rmtree(state)

    result: dict[str, Any] = {
        "schema": "agent-dispatch-aar-play-host-qualification/v1",
        "expectation": args.expect,
        "runner": {
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "stages": [],
        "classification": "INCONCLUSIVE",
        "passed": False,
    }

    privileged_runtime = False

    def stage(name: str, argv: list[str]) -> tuple[int, dict[str, Any]]:
        rc, receipt, stderr = run_stage(tool, state, argv)
        result["stages"].append({
            "name": name,
            "exit_code": rc,
            "receipt": receipt,
            "stderr_tail": stderr or None,
        })
        return rc, receipt

    observe_rc, observe = stage("observe", ["observe"])
    if args.expect == "supported" and platform.system() == "Linux":
        accel = observe.get("evidence", {}).get("acceleration", {})
        if accel.get("present") and not accel.get("writable"):
            sudo = subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True)
            privileged_runtime = sudo.returncode == 0
            result["linux_kvm_venue_adapter"] = {
                "required": True,
                "selected": "sudo -n env <explicit Android vars> <emulator> only" if privileged_runtime else None,
                "reason": "GitHub runner exposes /dev/kvm but the runner account lacks direct write access",
            }
    if args.expect == "unsupported":
        ok = observe_rc == 2 and observe.get("status") == "unsupported_host"
        result["classification"] = "EXPECTED_UNSUPPORTED" if ok else "UNEXPECTED_SUPPORT_RESULT"
        result["passed"] = ok
        final_rc = 0 if ok else 1
    elif observe_rc != 0:
        result["classification"] = "OBSERVE_FAILED"
        final_rc = 1
    else:
        plan_rc, plan = stage("plan", ["plan", "--accept-sdk-licenses"])
        if plan_rc != 0:
            result["classification"] = "PLAN_FAILED"
            final_rc = 1
        else:
            plan_path = pathlib.Path(plan["evidence"]["plan"])
            apply_rc, apply_receipt = stage("apply", ["apply", "--plan", str(plan_path)])
            if apply_rc != 0:
                result["classification"] = "APPLY_FAILED"
                final_rc = 1
            else:
                boot_timeout = "600" if platform.system() == "Darwin" and platform.machine().casefold() in {"x86_64", "amd64"} else "300"
                verify_args = ["verify", "--plan", str(plan_path), "--boot-timeout", boot_timeout]
                if privileged_runtime:
                    verify_args.append("--emulator-sudo")
                verify_rc, verify = stage("verify", verify_args)
                identity = apply_receipt.get("evidence", {}).get("toolchain_identity", {})
                result["toolchain_identity_sha256"] = identity.get("identity_sha256")
                result["profile"] = observe.get("host", {}).get("profile")
                if verify_rc == 3 and verify.get("status") == "venue_limitation":
                    result["venue_failure_type"] = verify.get("failure_type")
                    cleanup_rc, _ = stage("cleanup", ["cleanup", "--plan", str(plan_path)])
                    result["cleanup_passed"] = cleanup_rc == 0
                    expected_negative = args.expect == "venue-limited" and cleanup_rc == 0
                    result["classification"] = "EXPECTED_VENUE_LIMITATION" if expected_negative else "VENUE_LIMITATION"
                    result["passed"] = expected_negative
                    final_rc = 0 if expected_negative else 3
                elif verify_rc != 0:
                    result["classification"] = "VERIFY_FAILED"
                    # Cleanup is best effort after a failed verification.
                    cleanup_rc, _ = stage("cleanup", ["cleanup", "--plan", str(plan_path)])
                    result["cleanup_passed"] = cleanup_rc == 0
                    final_rc = 1
                else:
                    fresh_plan_rc, fresh_plan = stage("fresh-plan", ["plan"])
                    fresh_plan_path = (
                        pathlib.Path(fresh_plan.get("evidence", {}).get("plan", ""))
                        if fresh_plan_rc == 0
                        else None
                    )
                    fresh_plan_ok = (
                        fresh_plan_rc == 0
                        and fresh_plan.get("status") == "no-op-planned"
                        and fresh_plan.get("evidence", {}).get("plan_mode") == "verify-existing"
                        and fresh_plan_path is not None
                    )
                    if fresh_plan_ok:
                        noop_rc, noop = stage(
                            "fresh-apply",
                            ["apply", "--plan", str(fresh_plan_path)],
                        )
                        cleanup_plan = fresh_plan_path
                    else:
                        noop_rc, noop = 1, {}
                        cleanup_plan = plan_path
                    cleanup_rc, cleanup = stage(
                        "cleanup", ["cleanup", "--plan", str(cleanup_plan)]
                    )
                    ok = (
                        fresh_plan_ok
                        and noop_rc == 0
                        and noop.get("status") == "no-op"
                        and cleanup_rc == 0
                        and cleanup.get("status") == "cleaned"
                    )
                    result["classification"] = "PASS" if ok else "IDEMPOTENCY_OR_CLEANUP_FAILED"
                    result["passed"] = ok
                    result["verified_guest"] = verify.get("evidence", {}).get("avd")
                    result["fresh_plan_convergence"] = {
                        "passed": fresh_plan_ok and noop_rc == 0 and noop.get("status") == "no-op",
                        "plan_status": fresh_plan.get("status"),
                        "plan_mode": fresh_plan.get("evidence", {}).get("plan_mode"),
                        "apply_status": noop.get("status"),
                    }
                    final_rc = 0 if ok else 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return final_rc


if __name__ == "__main__":
    raise SystemExit(main())
