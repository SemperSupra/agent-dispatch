#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-R4 one-variable /var/tmp runtime fixture probe."""
from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import stat

_R3_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_e2_svctl_status_runtime.py")
_R3_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_svctl_status_runtime", _R3_SCRIPT)
if _R3_SPEC is None or _R3_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_e2_svctl_status_runtime.py")
r3 = importlib.util.module_from_spec(_R3_SPEC)
_R3_SPEC.loader.exec_module(r3)

_D4_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_e2_runtime_dirs.py")
_D4_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_runtime_dirs", _D4_SCRIPT)
if _D4_SPEC is None or _D4_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_e2_runtime_dirs.py")
d4 = importlib.util.module_from_spec(_D4_SPEC)
_D4_SPEC.loader.exec_module(d4)

base = r3.base

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-var-tmp-runtime/v1"
VAR_TMP = "/var/tmp"
TMP = "/tmp"
FIXTURE_MODE = 0o755


def materialize_var_tmp(root: pathlib.Path) -> dict:
    var = root / "var"
    if not var.is_dir():
        raise RuntimeError("exact root /var must exist as directory before R4")
    tmp_meta = d4.path_metadata(root, TMP)
    before = d4.path_metadata(root, VAR_TMP)
    if not (
        tmp_meta.get("type") == "symlink"
        and tmp_meta.get("symlinkTarget") == "./var/tmp"
    ):
        raise RuntimeError("exact /tmp -> ./var/tmp contract not present")
    if before.get("exists"):
        raise RuntimeError("R4 expects /var/tmp absent before one-variable fixture")

    target = root / VAR_TMP.lstrip("/")
    target.mkdir()
    target.chmod(FIXTURE_MODE)
    after = d4.path_metadata(root, VAR_TMP)
    if not after.get("exists") or after.get("type") != "directory":
        raise RuntimeError("failed to materialize /var/tmp directory")

    return {
        "path": VAR_TMP,
        "before": before,
        "after": after,
        "modeTreatment": f"{FIXTURE_MODE:04o}",
        "modeIsExactFirmwareClaim": False,
        "purpose": "satisfy exact /tmp symlink target for supervisor control-socket falsification",
    }


def run_probe(args: argparse.Namespace) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    firmware = work / "original" / "firmware.image"
    payload = work / "payload"
    roots_dir = work / "roots"
    scratch = work / "scratch"
    ns_result = work / "namespace-result.json"
    for p in (firmware.parent, payload, roots_dir, scratch):
        p.mkdir(parents=True, exist_ok=True)

    exact = base.download_exact(
        args.firmware_url, firmware,
        expected_size=args.expected_size,
        expected_sha256=args.expected_sha256,
    )
    outer = base.extract_outer(firmware, payload)
    roots = base.extract_squashfs_roots(payload, roots_dir, scratch)
    root = base.select_root(roots)

    for guest in (r3.SUPERVISOR, r3.SVCTL, r3.CTLMGR):
        path = root / guest.lstrip("/")
        header = base.parse_elf_header(path)
        if not header or header.get("machineName") != "MIPS":
            raise RuntimeError(f"candidate absent/not MIPS: {guest}")

    unit_path = root / r3.UNIT_ROOT.lstrip("/") / r3.TARGET_UNIT
    if not unit_path.is_file():
        raise RuntimeError("ctlmgr.service absent from exact root")

    fixture = materialize_var_tmp(root)
    symlinks = base.normalize_guest_absolute_symlinks(root)
    r3.prepare_qemu(root)
    runtime = r3.run_namespace(root, ns_result, args)

    control_trace = runtime.get("fixedPathTrace", {}).get("paths", {}).get("control_socket", {})
    unit_trace = runtime.get("fixedPathTrace", {}).get("paths", {}).get("ctlmgr_unit", {})
    ctlmgr_execve = runtime.get("fixedPathTrace", {}).get("ctlmgrExecveCount", 0)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": runtime.get("classification"),
        "oracleSatisfied": bool(runtime.get("probeCompleted")),
        "target": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "extraction": {
            "outerMemberCount": len(outer),
            "squashfsRootCount": len(roots),
            "selectedRootRegularFileCount": base.root_file_count(root),
            "guestAbsoluteSymlinksTranslated": symlinks["rewrittenCount"],
        },
        "fixture": fixture,
        "fixtureEffect": {
            "controlSocketBindSuccessCount": control_trace.get("syscalls", {}).get("bind", 0) - control_trace.get("failureCount", 0)
                if control_trace.get("syscalls", {}).get("bind", 0) else 0,
            "controlSocketObserved": bool(runtime.get("controlSocketObserved")),
            "ctlmgrUnitTraceHits": unit_trace.get("hitCount", 0),
            "ctlmgrExecveCount": ctlmgr_execve,
            "ctlmgrProcessObserved": bool(runtime.get("ctlmgrProcessObserved")),
        },
        "runtime": runtime,
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
            "genericRuntimeFixtureAdded": True,
            "onlyVarTmpCreated": True,
            "psupportDataFabricated": False,
            "avmipcdStateFabricated": False,
            "varRunCreated": False,
            "devShmCreated": False,
        },
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url")
    p.add_argument("--expected-size", type=int)
    p.add_argument("--expected-sha256")
    p.add_argument("--work-dir")
    p.add_argument("--receipt")
    p.add_argument("--startup-observe-seconds", type=float, default=3.0)
    p.add_argument("--sample-interval-seconds", type=float, default=0.05)
    p.add_argument("--status-grace-seconds", type=float, default=0.15)
    p.add_argument("--namespace-helper", action="store_true")
    p.add_argument("--root")
    p.add_argument("--namespace-result")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.namespace_helper:
        # The R3 module is the namespace implementation; this entrypoint is
        # never used in helper mode because r3.run_namespace invokes r3's file.
        raise SystemExit("R4 does not expose namespace-helper mode directly")

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
            },
        }
        rc = 3
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": receipt["classification"], "oracleSatisfied": receipt["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
