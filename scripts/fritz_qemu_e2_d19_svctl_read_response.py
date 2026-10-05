#!/usr/bin/env python3
"""E2-D19b: debugger-only observation at the earned _svctl_read entry role."""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys

_D18_PATH = pathlib.Path(__file__).with_name("fritz_qemu_e2_d18_runtime_callsite_observe.py")
_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_d18_runtime_callsite_observe", _D18_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load D18")
d18 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d18)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-d19b-svctl-read-entry/v1"
TARGETS = ("_svctl_read",)
ROLE_DOC = pathlib.Path(__file__).resolve().parents[1] / "evidence" / "fritz-e2-d19-response-role.json"


def load_role() -> dict:
    r = json.loads(ROLE_DOC.read_text(encoding="utf-8"))
    if r.get("classification") != "E2_D19_SVCTL_READ_ENTRY_ROLE_EARNED":
        raise RuntimeError("D19 response role classification not accepted")
    if r.get("oracleSatisfied") is not True:
        raise RuntimeError("D19 response role oracle not satisfied")
    role = r.get("earnedObservationRole") or {}
    if role.get("symbol") != "_svctl_read" or role.get("boundary") != "function_entry":
        raise RuntimeError("D19 response role boundary mismatch")
    b = r.get("interpretationBoundary") or {}
    if b.get("libcReadOwnershipInferred") is not False or b.get("returnRoleEarned") is not False:
        raise RuntimeError("D19 boundary was widened")
    return r


def safe_response_svctl_call(root: pathlib.Path, env: dict, verb: str, service: str) -> dict:
    try:
        return d18.instrumented_svctl_call(
            root,
            env,
            verb,
            service,
            host_strace=False,
            targets=TARGETS,
            require_d17_callsites=False,
        )
    except Exception as exc:
        return d18.instrumentation_failure_result(
            root,
            verb,
            service,
            type(exc).__name__,
            "d19b_svctl_read_outer_wrapper",
            host_strace=False,
        )


def namespace_helper(args: argparse.Namespace) -> int:
    original = d18.r6.svctl_call
    d18.r6.svctl_call = safe_response_svctl_call
    try:
        return d18.r6.namespace_helper(args)
    finally:
        d18.r6.svctl_call = original


def classify(instrument: dict) -> str:
    if (
        not instrument.get("allCallsInstrumentationReady")
        or not instrument.get("allExpectedTargetHits")
    ):
        return "E2_D19B_SVCTL_READ_INSTRUMENTATION_INCOMPLETE"
    if instrument.get("stableDimensionDiscriminatorCount", 0) > 0:
        return "E2_D19B_SVCTL_READ_STABLE_RESPONSE_DISCRIMINATOR_FOUND"
    if instrument.get("unstableStatusDimensionCount", 0) > 0:
        return "E2_D19B_SVCTL_READ_UNSTABLE_STATUS_NO_DISCRIMINATOR"
    return "E2_D19B_SVCTL_READ_NO_RUNTIME_DISCRIMINATOR"


def run_probe(args: argparse.Namespace) -> dict:
    role = load_role()
    root, meta = d18.r6.prepare_root(args)
    ns_result = pathlib.Path(args.work_dir).resolve() / "namespace-result-d19b.json"

    cp = d18.r6._run(
        [
            "sudo", "-n", "unshare", "--net", "--pid", "--fork", "--kill-child",
            "--mount-proc", sys.executable, str(pathlib.Path(__file__).resolve()),
            "--namespace-helper", "--root", str(root),
            "--namespace-result", str(ns_result),
            "--control-wait-seconds", str(args.control_wait_seconds),
            "--verify-seconds", str(args.verify_seconds),
            "--sample-interval-seconds", str(args.sample_interval_seconds),
        ],
        timeout=max(60, int(args.control_wait_seconds + args.verify_seconds) + 45),
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"isolated D19b probe failed (exit={cp.returncode}, stderrBytes={len(cp.stderr.encode())})"
        )
    if not ns_result.exists():
        raise RuntimeError("D19b namespace probe emitted no result")

    runtime = json.loads(ns_result.read_text(encoding="utf-8"))
    instrument = d18.summarize_instrumentation(runtime, TARGETS)
    classification = classify(instrument)
    oracle = bool(
        runtime.get("probeCompleted")
        and instrument.get("allCallsInstrumentationReady")
        and instrument.get("allExpectedTargetHits")
    )

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classification,
        "oracleSatisfied": oracle,
        **meta,
        "transaction": {
            "inspect": ["svctl", "status", "ctlmgr"],
            "apply": ["svctl", "start", "ctlmgr"],
            "applyCount": 1 if runtime.get("start", {}).get("exitCode") is not None else 0,
            "verify": ["svctl", "status", "ctlmgr"],
            "disposalIsRollback": True,
        },
        "staticPrecondition": {
            "roleClassification": role["classification"],
            "roleOracleSatisfied": True,
            "observedSymbol": "_svctl_read",
            "observedBoundary": "function_entry",
            "libcReadOwnershipAccepted": False,
            "returnRoleAccepted": False,
        },
        "wireOracle": {
            "sameRunCaptureAttempted": False,
            "sameRunCaptureRequired": False,
            "independentAcceptedR9EvidencePreserved": True,
        },
        "instrumentation": instrument,
        "runtimeSummary": {
            "statusChanged": runtime.get("statusChanged"),
            "ctlmgrProcessObserved": runtime.get("ctlmgrProcessObserved"),
            "maxCtlmgrProcessCount": runtime.get("maxCtlmgrProcessCount"),
        },
        "interpretationBoundary": {
            "d19RoleReceiptRequired": True,
            "observedRole": "_svctl_read_entry",
            "sharedSymbolBindingOnly": True,
            "argumentScalarClassesAndMemoryDigestsOnly": True,
            "dimensionLevelStatusControlRequired": True,
            "prePostStatusStabilityRequiredForDifferenceClaim": True,
            "hostStraceExcludedFromSvctlCalls": True,
            "sameRunWireCaptureExcluded": True,
            "independentR9WireOracleNotReinterpreted": True,
            "digestValuesPublished": False,
            "libcReadOwnershipInferred": False,
            "returnRoleEarned": False,
            "responsePayloadPublished": False,
            "responseFieldLayoutAccepted": False,
            "protocolEnumValuesAccepted": False,
            "payloadOffsetsAccepted": False,
            "noAdditionalDownstreamPointEarned": True,
        },
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "rawControlPayloadPublished": False,
            "controlPayloadPersisted": False,
            "rawHostStracePublished": False,
            "rawDebuggerOutputPublished": False,
            "rawRegisterValuesPublished": False,
            "rawPointedMemoryPublished": False,
            "callsiteAddressesPublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
            "externalNetworkAvailableToTarget": False,
            "targetSpecificShimAdded": False,
            "shippedFilesModified": False,
            "genericRuntimeFixtureAdded": True,
            "onlyVarTmpCreated": True,
            "serviceStartRequested": True,
            "serviceStartCountMaximum": 1,
            "sameRunWireCaptureAttempted": False,
            "disposableEmulatorMutationOnly": True,
        },
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url")
    p.add_argument("--expected-size", type=int)
    p.add_argument("--expected-sha256")
    p.add_argument("--work-dir")
    p.add_argument("--receipt")
    p.add_argument("--control-wait-seconds", type=float, default=2.0)
    p.add_argument("--verify-seconds", type=float, default=2.0)
    p.add_argument("--sample-interval-seconds", type=float, default=0.05)
    p.add_argument("--namespace-helper", action="store_true")
    p.add_argument("--root")
    p.add_argument("--namespace-result")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.namespace_helper:
        if not args.root or not args.namespace_result:
            raise SystemExit("namespace helper requires root/result")
        return namespace_helper(args)

    required = (
        args.firmware_url, args.expected_size, args.expected_sha256,
        args.work_dir, args.receipt,
    )
    if any(v is None for v in required):
        raise SystemExit("normal mode requires firmware/size/hash/work/receipt")

    receipt = pathlib.Path(args.receipt)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = run_probe(args)
        rc = 0 if data.get("oracleSatisfied") else 2
    except Exception as exc:
        data = {
            "schemaVersion": SCHEMA_VERSION,
            "experiment": EXPERIMENT,
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "error": {"type": type(exc).__name__, "message": str(exc)[:1000]},
            "safety": {
                "rawFirmwarePublished": False,
                "rootfsPublished": False,
                "rawControlPayloadPublished": False,
                "controlPayloadPersisted": False,
                "rawHostStracePublished": False,
                "rawDebuggerOutputPublished": False,
                "rawRegisterValuesPublished": False,
                "rawPointedMemoryPublished": False,
                "callsiteAddressesPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
                "externalNetworkAvailableToTarget": False,
                "targetSpecificShimAdded": False,
                "shippedFilesModified": False,
                "genericRuntimeFixtureAdded": False,
                "onlyVarTmpCreated": False,
                "serviceStartRequested": False,
                "serviceStartCountMaximum": 1,
                "sameRunWireCaptureAttempted": False,
                "disposableEmulatorMutationOnly": True,
            },
        }
        rc = 3

    receipt.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": data["classification"], "oracleSatisfied": data["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
