#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-R5 prodtest-network.target runtime probe."""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib

_R4_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_e2_var_tmp_runtime.py")
_R4_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_var_tmp_runtime", _R4_SCRIPT)
if _R4_SPEC is None or _R4_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_e2_var_tmp_runtime.py")
r4 = importlib.util.module_from_spec(_R4_SPEC)
_R4_SPEC.loader.exec_module(r4)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-prodtest-network-runtime/v1"
SUPERVISOR_TARGET = "prodtest-network.target"


def _hits(paths: dict, *keys: str) -> int:
    return sum(paths.get(key, {}).get("hitCount", 0) for key in keys)


def classify_r5(receipt: dict) -> str:
    runtime = receipt.get("runtime", {})
    if runtime.get("ctlmgrProcessObserved"):
        return "E2_R5_CTLMGR_PROCESS_OBSERVED"
    trace = runtime.get("fixedPathTrace", {})
    if trace.get("ctlmgrExecveCount", 0) > 0:
        return "E2_R5_CTLMGR_EXEC_ATTEMPTED"
    paths = trace.get("paths", {})
    ctlmgr_hits = _hits(paths, "ctlmgr_unit", "ctlmgr_unit_relative")
    avmipcd_hits = _hits(paths, "avmipcd_unit", "avmipcd_unit_relative")
    selected_hits = _hits(paths, "selected_target", "selected_target_relative")
    psupport_failures = paths.get("psupport_data", {}).get("failureCount", 0)
    if ctlmgr_hits > 0 and psupport_failures > 0:
        return "E2_R5_CTLMGR_UNIT_READ_PSUPPORT_MISSING"
    if ctlmgr_hits > 0:
        return "E2_R5_CTLMGR_UNIT_READ"
    if avmipcd_hits > 0:
        return "E2_R5_AVMIPCD_UNIT_READ"
    if selected_hits > 0:
        return "E2_R5_SELECTED_TARGET_READ"
    return "E2_R5_SELECTED_TARGET_NOT_OBSERVED"


def annotate(receipt: dict) -> dict:
    runtime = receipt.get("runtime", {})
    if runtime.get("supervisorArguments") != [r4.r3.UNIT_ROOT, SUPERVISOR_TARGET]:
        raise RuntimeError("R5 runtime did not use exact prodtest-network.target")
    receipt["schemaVersion"] = SCHEMA_VERSION
    receipt["experiment"] = EXPERIMENT
    receipt["runtimeClassification"] = receipt.get("classification")
    receipt["classification"] = classify_r5(receipt)
    paths = runtime.get("fixedPathTrace", {}).get("paths", {})
    receipt["targetTraversal"] = {
        "selectedTargetHits": _hits(paths, "selected_target", "selected_target_relative"),
        "ctlmgrUnitHits": _hits(paths, "ctlmgr_unit", "ctlmgr_unit_relative"),
        "avmipcdUnitHits": _hits(paths, "avmipcd_unit", "avmipcd_unit_relative"),
        "ctlmgrExecveCount": runtime.get("fixedPathTrace", {}).get("ctlmgrExecveCount", 0),
        "psupportFailureCount": paths.get("psupport_data", {}).get("failureCount", 0),
    }
    receipt["targetSelection"] = {
        "selectedTarget": SUPERVISOR_TARGET,
        "selectionEvidence": "E2-D5 exact target admission graph",
        "admittedUnitCount": 6,
        "ctlmgrAdmitted": True,
        "avmipcdAdmitted": True,
        "broaderNetworkTargetUsed": False,
    }
    receipt.setdefault("safety", {})["prodtestNetworkTargetUsed"] = True
    receipt["safety"]["networkTargetUsed"] = False
    return receipt


def run_probe(args: argparse.Namespace) -> dict:
    args.supervisor_target = SUPERVISOR_TARGET
    receipt = r4.run_probe(args)
    return annotate(receipt)


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url")
    p.add_argument("--expected-size", type=int)
    p.add_argument("--expected-sha256")
    p.add_argument("--work-dir")
    p.add_argument("--receipt")
    p.add_argument("--startup-observe-seconds", type=float, default=5.0)
    p.add_argument("--sample-interval-seconds", type=float, default=0.05)
    p.add_argument("--status-grace-seconds", type=float, default=0.15)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    required = (args.firmware_url, args.expected_size, args.expected_sha256, args.work_dir, args.receipt)
    if any(v is None for v in required):
        raise SystemExit("normal mode requires firmware/size/hash/work/receipt")

    receipt_path = pathlib.Path(args.receipt)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = run_probe(args)
        rc = 0 if receipt.get("oracleSatisfied") else 2
    except Exception as exc:
        receipt = {
            "schemaVersion": SCHEMA_VERSION,
            "experiment": EXPERIMENT,
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "error": {"type": type(exc).__name__, "message": str(exc)[:1000]},
            "safety": {
                "rawFirmwarePublished": False,
                "rootfsPublished": False,
                "rawTargetStdoutPublished": False,
                "rawTargetStderrPublished": False,
                "rawStracePublished": False,
                "rawSvctlOutputPublished": False,
                "rawHttpBodyPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
                "externalNetworkAvailableToTarget": False,
                "targetSpecificShimAdded": False,
                "genericRuntimeFixtureAdded": False,
                "onlyVarTmpCreated": False,
                "psupportDataFabricated": False,
                "avmipcdStateFabricated": False,
                "varRunCreated": False,
                "devShmCreated": False,
                "prodtestNetworkTargetUsed": False,
                "networkTargetUsed": False,
            },
        }
        rc = 3
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": receipt["classification"], "oracleSatisfied": receipt["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
