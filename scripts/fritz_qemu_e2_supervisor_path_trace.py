#!/usr/bin/env python3
"""Public-safe FRITZ E2-R4 supervisor path-access reducer.

Runs the exact accepted supervisor target in the same isolated qemu-user
treatment and reduces raw QEMU strace to allowlisted guest-path access metadata.
Raw stdout/stderr/strace are ephemeral.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location("fritz_qemu_user_probe", _BASE_SCRIPT)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_user_probe.py")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-supervisor-path-trace/v1"
QEMU_GUEST_PATH = "/usr/bin/qemu-mips-static"
CPU_PROFILE = "24KEc"
SUPERVISOR = "/bin/supervisor"
UNIT_ROOT = "/lib/systemd/system"
TARGET_UNIT = "ctlmgr.service"
TARGET_UNIT_PATH = f"{UNIT_ROOT}/{TARGET_UNIT}"
AVMIPCD_UNIT_PATH = f"{UNIT_ROOT}/avmipcd.service"
PSUPPORT_DATA = "/var/tmp/psupport.data"
CONTROL_SOCKET = "/tmp/supervisor.ctrl.socket"

ALLOWED_PREFIXES = (
    "/lib/systemd/system/",
    "/tmp/",
    "/var/tmp/",
    "/proc/",
    "/dev/",
    "/lib/",
    "/usr/lib/",
    "/usr/local/lib/",
    "/etc/",
)
QUOTED_ABS_PATH = re.compile(r'"(/[^"\\]*)"')
SYSCALL = re.compile(r"^\s*\d+\s+([A-Za-z0-9_]+)\(")
RESULT = re.compile(r"\)\s+=\s+(-?\d+)(?:\s+errno=(\d+))?")


def _run(argv: list[str], *, timeout: int = 60, env: dict | None = None):
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def path_allowed(path: str) -> bool:
    return path.startswith(ALLOWED_PREFIXES)


def outcome_class(return_value: int | None, errno: int | None) -> str:
    if return_value is not None and return_value >= 0:
        return "success"
    if errno == 2:
        return "ENOENT"
    if errno is not None:
        return f"ERRNO_{errno}"
    if return_value is not None and return_value < 0:
        return "error-unclassified"
    return "unknown"


def reduce_strace(text: str) -> dict:
    records: dict[tuple[str, str, str], dict] = {}
    first_sequence = 0
    for line_no, line in enumerate(text.splitlines()):
        sm = SYSCALL.search(line)
        if not sm:
            continue
        syscall = sm.group(1)
        rm = RESULT.search(line)
        rv = int(rm.group(1)) if rm else None
        eno = int(rm.group(2)) if rm and rm.group(2) else None
        outcome = outcome_class(rv, eno)
        for path in QUOTED_ABS_PATH.findall(line):
            if not path_allowed(path):
                continue
            key = (path, syscall, outcome)
            if key not in records:
                records[key] = {
                    "path": path,
                    "syscall": syscall,
                    "outcome": outcome,
                    "count": 0,
                    "firstSeenSequence": first_sequence,
                    "firstSeenTraceLine": line_no,
                }
                first_sequence += 1
            records[key]["count"] += 1

    items = sorted(records.values(), key=lambda x: x["firstSeenSequence"])
    unit_accesses = [x for x in items if x["path"].startswith(UNIT_ROOT + "/")]
    return {
        "records": items,
        "recordCount": len(items),
        "unitAccesses": unit_accesses,
        "targetUnitObserved": any(x["path"] == TARGET_UNIT_PATH for x in items),
        "avmipcdUnitObserved": any(x["path"] == AVMIPCD_UNIT_PATH for x in items),
        "psupportDataObserved": any(x["path"] == PSUPPORT_DATA for x in items),
        "controlSocketObserved": any(x["path"] == CONTROL_SOCKET for x in items),
    }


def classify(trace: dict) -> str:
    if trace["targetUnitObserved"]:
        if trace["psupportDataObserved"]:
            return "E2_TARGET_UNIT_AND_ENV_PATH_OBSERVED"
        if trace["avmipcdUnitObserved"]:
            return "E2_TARGET_UNIT_AND_AVMIPCD_UNIT_OBSERVED"
        return "E2_TARGET_UNIT_OBSERVED"
    if trace["unitAccesses"]:
        return "E2_UNIT_TREE_OBSERVED_BEFORE_TARGET_UNIT"
    return "E2_EXIT_BEFORE_UNIT_TREE_ACCESS"


def ensure_mount_target(path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() and not path.is_symlink():
        path.touch()


def prepare_qemu(root: pathlib.Path) -> None:
    source = shutil.which("qemu-mips-static")
    if not source:
        raise RuntimeError("qemu-mips-static not installed")
    target = root / QEMU_GUEST_PATH.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def namespace_helper(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root).resolve()
    result_path = pathlib.Path(args.namespace_result).resolve()

    if _run(["ip", "link", "set", "lo", "up"]).returncode != 0:
        raise RuntimeError("failed to bring loopback up")
    links = _run(["ip", "-o", "link", "show"])
    interfaces = sorted(set(
        m.group(1)
        for line in links.stdout.splitlines()
        if (m := re.match(r"\d+:\s+([^:@]+)", line))
    ))
    if interfaces != ["lo"]:
        raise RuntimeError(f"unexpected interfaces: {interfaces!r}")
    default = _run(["ip", "route", "show", "default"])
    if default.returncode != 0 or default.stdout.strip():
        raise RuntimeError("network namespace unexpectedly has a default route")

    (root / "proc").mkdir(parents=True, exist_ok=True)
    if _run(["mount", "--bind", "/proc", str(root / "proc")]).returncode != 0:
        raise RuntimeError("failed to bind procfs")
    for dev in ("null", "zero", "random", "urandom"):
        target = root / "dev" / dev
        ensure_mount_target(target)
        if _run(["mount", "--bind", f"/dev/{dev}", str(target)]).returncode != 0:
            raise RuntimeError(f"failed to bind /dev/{dev}")

    env = {"PATH": "/bin:/sbin:/usr/bin:/usr/sbin", "HOME": "/", "LANG": "C", "LC_ALL": "C"}
    raw_dir = result_path.parent / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = raw_dir / "supervisor.stdout"
    stderr_path = raw_dir / "supervisor.strace"

    cmd = [
        "chroot", str(root), QEMU_GUEST_PATH, "-cpu", CPU_PROFILE,
        "-strace", SUPERVISOR, UNIT_ROOT, TARGET_UNIT,
    ]
    started = time.monotonic()
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        proc = subprocess.Popen(
            cmd,
            stdout=out,
            stderr=err,
            env=env,
            start_new_session=True,
        )
        try:
            proc.wait(timeout=args.timeout_seconds)
            terminated = False
        except subprocess.TimeoutExpired:
            terminated = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=1)

    trace_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    trace = reduce_strace(trace_text)
    result = {
        "probeCompleted": True,
        "interfaces": interfaces,
        "defaultRoutePresent": False,
        "cpuProfile": CPU_PROFILE,
        "supervisorPath": SUPERVISOR,
        "supervisorArguments": [UNIT_ROOT, TARGET_UNIT],
        "launcherExitCode": proc.returncode,
        "terminatedByHarness": terminated,
        "elapsedSeconds": round(time.monotonic() - started, 6),
        "stdoutBytes": stdout_path.stat().st_size if stdout_path.exists() else 0,
        "straceBytes": stderr_path.stat().st_size if stderr_path.exists() else 0,
        "pathTrace": trace,
    }
    result["classification"] = classify(trace)
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    shutil.rmtree(raw_dir, ignore_errors=True)
    return 0


def run_namespace(root: pathlib.Path, result_path: pathlib.Path, args: argparse.Namespace) -> dict:
    cp = _run(
        [
            "sudo", "-n", "unshare", "--net", "--pid", "--fork", "--kill-child",
            "--mount-proc", sys.executable, str(pathlib.Path(__file__).resolve()),
            "--namespace-helper", "--root", str(root),
            "--namespace-result", str(result_path),
            "--timeout-seconds", str(args.timeout_seconds),
        ],
        timeout=max(45, int(args.timeout_seconds) + 30),
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"isolated namespace probe failed (exit={cp.returncode}, stderrBytes={len(cp.stderr.encode())})"
        )
    if not result_path.exists():
        raise RuntimeError("namespace probe emitted no result")
    return json.loads(result_path.read_text(encoding="utf-8"))


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
        args.firmware_url,
        firmware,
        expected_size=args.expected_size,
        expected_sha256=args.expected_sha256,
    )
    outer = base.extract_outer(firmware, payload)
    roots = base.extract_squashfs_roots(payload, roots_dir, scratch)
    root = base.select_root(roots)

    supervisor_path = root / SUPERVISOR.lstrip("/")
    unit_path = root / TARGET_UNIT_PATH.lstrip("/")
    if not unit_path.is_file():
        raise RuntimeError("ctlmgr.service absent from exact root")
    header = base.parse_elf_header(supervisor_path)
    if not header or header.get("machineName") != "MIPS":
        raise RuntimeError("supervisor absent/not MIPS")

    symlinks = base.normalize_guest_absolute_symlinks(root)
    prepare_qemu(root)
    runtime = run_namespace(root, ns_result, args)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": runtime["classification"],
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
        "exactTreatment": {
            "supervisorPath": SUPERVISOR,
            "arguments": [UNIT_ROOT, TARGET_UNIT],
            "targetUnitPath": TARGET_UNIT_PATH,
            "targetSpecificShimAdded": False,
        },
        "runtime": runtime,
        "interpretationBoundary": {
            "pathAccessDoesNotProveSemanticUse": True,
            "successfulOpenDoesNotProveUnitAdmission": True,
            "fixtureAuthorizedByThisRep": False,
        },
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "binaryPayloadPublished": False,
            "rawTargetStdoutPublished": False,
            "rawStracePublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
            "externalNetworkAvailableToTarget": False,
            "targetSpecificShimAdded": False,
        },
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url")
    p.add_argument("--expected-size", type=int)
    p.add_argument("--expected-sha256")
    p.add_argument("--work-dir")
    p.add_argument("--receipt")
    p.add_argument("--timeout-seconds", type=float, default=2.0)
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
        args.firmware_url,
        args.expected_size,
        args.expected_sha256,
        args.work_dir,
        args.receipt,
    )
    if any(v is None for v in required):
        raise SystemExit("normal mode requires firmware/size/hash/work/receipt")

    receipt_path = pathlib.Path(args.receipt)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = run_probe(args)
        rc = 0 if receipt["oracleSatisfied"] else 2
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
                "binaryPayloadPublished": False,
                "rawTargetStdoutPublished": False,
                "rawStracePublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
                "externalNetworkAvailableToTarget": False,
                "targetSpecificShimAdded": False,
            },
        }
        rc = 3

    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "classification": receipt["classification"],
        "oracleSatisfied": receipt["oracleSatisfied"],
    }, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
