#!/usr/bin/env python3
"""Six sequential injected-failure lifecycle exercises in ONE hosted KVM lane.

Public synthetic disposable objects only. Expect controlled exit 3 with exact
first-failure evidence and *zero* resource residue at each lifecycle boundary.
Never run against real Windows, private WinBot source, or production hosts.
"""
from __future__ import annotations
import json
import os
import pathlib
import subprocess
import sys

BASE = pathlib.Path("/tmp/winbot-fault-matrix")
STAGES = (
    "after_overlay_created",
    "after_network_defined_before_ack",
    "after_network_started",
    "after_domain_defined_before_ack",
    "after_domain_defined",
    "after_domain_started",
)

def main() -> int:
    if BASE.exists():
        raise RuntimeError("refuse preexisting failure-matrix evidence")
    BASE.mkdir(mode=0o700)
    results = []
    passed = True
    for stage in STAGES:
        path = pathlib.Path("/tmp/winbot-fault-"+stage)
        if path.exists() or path.is_symlink():
            raise RuntimeError("refuse preexisting stage evidence: "+stage)
        env = os.environ.copy()
        env.update({
            "WINBOT_PUBLIC_OVERLAY_EVIDENCE_DIR": str(path),
            "WINBOT_PUBLIC_FAULT_STAGE": stage,
            "WINBOT_PUBLIC_SYNTHETIC_FAULTS": "1",
        })
        attempt = subprocess.run(
            [sys.executable, "-m", "scripts.winbot_public_overlay_readback"],
            env=env, text=True, capture_output=True, timeout=120, check=False)
        if not path.is_dir():
            raise RuntimeError("owned failure receipt missing: "+stage)
        error = json.loads((path/"error.json").read_text())
        cleanup = json.loads((path/"cleanup.json").read_text())
        expected = "RuntimeError: EXPECTED_SYNTHETIC_FAILURE:"+stage
        item = {
            "stage": stage,
            "exit_code": attempt.returncode,
            "first_failure": cleanup.get("prior_failure"),
            "error_classification": error.get("classification"),
            "domain_absent": cleanup.get("domain_absent"),
            "network_absent": cleanup.get("owned_network_absent"),
            "overlay_absent": cleanup.get("owned_overlay_absent"),
            "master_fixture_absent": cleanup.get("owned_master_fixture_absent"),
            "cleanup_errors": cleanup.get("problems"),
            "reason_exact_expected": cleanup.get("prior_failure") == expected,
        }
        item["qualified"] = (
            item["exit_code"] == 3 and item["reason_exact_expected"] and
            item["error_classification"] == "HARNESS_OR_ENVIRONMENT_FAILURE" and
            all(item[k] is True for k in
                ("domain_absent","network_absent",
                 "overlay_absent","master_fixture_absent")) and
            item["cleanup_errors"] == [])
        results.append(item)
        if not item["qualified"]:
            passed = False
            break  # fail closed; don't compound a leaking workcell
    report = {
        "schema": "winbot-public-kvm-six-stage-rollback/v1",
        "classification": "SYNTHETIC_LIFECYCLE_FAILURE_QUALIFICATION",
        "all_stages_passed": passed and len(results) == len(STAGES),
        "stages": results,
        "real_windows_media_or_guest": False,
        "private_winbot_source_executed": False,
        "product_apply_power_destroy_admitted": False,
        "physical_infrastructure_touched": False,
        "deployment_or_merge_authorized": False,
    }
    (BASE/"fault-matrix.json").write_text(
        json.dumps(report, sort_keys=True, indent=2)+"\n")
    print(json.dumps({"qualified":report["all_stages_passed"],"stages":results}))
    return 0 if report["all_stages_passed"] else 3

if __name__=="__main__":
    raise SystemExit(main())
