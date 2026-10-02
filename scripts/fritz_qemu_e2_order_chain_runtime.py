#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-R6 ordered predecessor-chain runtime probe."""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib

_R5_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_e2_prodtest_network_runtime.py")
_R5_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_prodtest_network_runtime", _R5_SCRIPT)
if _R5_SPEC is None or _R5_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_e2_prodtest_network_runtime.py")
r5 = importlib.util.module_from_spec(_R5_SPEC)
_R5_SPEC.loader.exec_module(r5)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-order-chain-runtime/v1"

UNIT_KEYS = (
    "selected_network_pre_unit",
    "selected_network_pre_unit_relative",
    "net_basic_unit",
    "net_basic_unit_relative",
    "avmipcd_unit",
    "avmipcd_unit_relative",
    "ctlmgr_unit",
    "ctlmgr_unit_relative",
    "multid_unit",
    "multid_unit_relative",
    "dsld_unit",
    "dsld_unit_relative",
)
EXEC_KEYS = (
    "net_basic_exec",
    "avmipcd_exec",
    "ctlmgr_exec",
    "multid_exec",
    "dsld_exec",
)


def execve_count(paths: dict, key: str) -> int:
    return int(paths.get(key, {}).get("syscalls", {}).get("execve", 0) or 0)


def observed_order(paths: dict) -> list[dict]:
    rows = []
    for key in UNIT_KEYS + EXEC_KEYS:
        item = paths.get(key, {})
        idx = item.get("firstSeenIndex")
        if idx is None:
            continue
        rows.append({
            "key": key,
            "path": item.get("path"),
            "firstSeenIndex": idx,
            "hitCount": item.get("hitCount", 0),
            "execveCount": execve_count(paths, key),
        })
    return sorted(rows, key=lambda x: (x["firstSeenIndex"], x["key"]))


def classify(receipt: dict) -> str:
    runtime = receipt.get("runtime", {})
    for attempt in runtime.get("httpAttempts", []):
        if attempt.get("httpStatus") == 200 and "session_info" in attempt.get("responseMarkers", []):
            return "E2_R6_LOGIN_HTTP_SUPPORTED"
    if runtime.get("ctlmgrProcessObserved"):
        return "E2_R6_CTLMGR_PROCESS_OBSERVED"
    paths = runtime.get("fixedPathTrace", {}).get("paths", {})
    if execve_count(paths, "ctlmgr_exec") > 0:
        return "E2_R6_CTLMGR_EXEC_REACHED"
    if execve_count(paths, "avmipcd_exec") > 0:
        return "E2_R6_AVMIPCD_EXEC_REACHED_CTLMGR_NOT_REACHED"
    if execve_count(paths, "net_basic_exec") > 0:
        return "E2_R6_NET_BASIC_EXEC_REACHED"
    if execve_count(paths, "multid_exec") > 0 or execve_count(paths, "dsld_exec") > 0:
        return "E2_R6_PARALLEL_SERVICE_EXEC_REACHED"
    if any(paths.get(k, {}).get("hitCount", 0) for k in UNIT_KEYS):
        return "E2_R6_UNITS_READ_NO_BUNDLE_EXEC"
    return "E2_R6_BUNDLE_NOT_OBSERVED"


def annotate(receipt: dict) -> dict:
    runtime = receipt.get("runtime", {})
    if runtime.get("supervisorArguments") != [
        r5.r4.r3.UNIT_ROOT,
        r5.SUPERVISOR_TARGET,
    ]:
        raise RuntimeError("R6 did not preserve exact prodtest-network.target treatment")
    trace = runtime.get("fixedPathTrace", {})
    paths = trace.get("paths", {})
    receipt["schemaVersion"] = SCHEMA_VERSION
    receipt["experiment"] = EXPERIMENT
    receipt["r5Classification"] = receipt.get("classification")
    receipt["classification"] = classify(receipt)
    receipt["orderChainObservation"] = {
        "unitReadKeys": {
            key: paths.get(key, {}).get("hitCount", 0)
            for key in UNIT_KEYS
        },
        "execveCounts": {
            key: execve_count(paths, key)
            for key in EXEC_KEYS
        },
        "firstSeenSequence": observed_order(paths),
        "statusAttempted": runtime.get("svctlStatusAttempted"),
        "statusExitCode": runtime.get("svctlStatusExitCode"),
        "controlSocketObserved": runtime.get("controlSocketObserved"),
        "ctlmgrProcessObserved": runtime.get("ctlmgrProcessObserved"),
    }
    receipt.setdefault("safety", {})["newRuntimeFixtureAddedForR6"] = False
    return receipt


def run_probe(args: argparse.Namespace) -> dict:
    return annotate(r5.run_probe(args))


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url", required=True)
    p.add_argument("--expected-size", type=int, required=True)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--work-dir", required=True)
    p.add_argument("--receipt", required=True)
    p.add_argument("--startup-observe-seconds", type=float, default=5.0)
    p.add_argument("--sample-interval-seconds", type=float, default=0.05)
    p.add_argument("--status-grace-seconds", type=float, default=0.15)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
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
                "newRuntimeFixtureAddedForR6": False,
            },
        }
        rc = 3
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": receipt["classification"], "oracleSatisfied": receipt["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
