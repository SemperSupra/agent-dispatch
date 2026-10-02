#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-R3 supervisor control-socket + svctl status probe."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import shutil
import signal
import stat
import subprocess
import sys
import time

_R2_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_e2_ctlmgr_service_runtime.py")
_R2_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_ctlmgr_service_runtime", _R2_SCRIPT)
if _R2_SPEC is None or _R2_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_e2_ctlmgr_service_runtime.py")
r2 = importlib.util.module_from_spec(_R2_SPEC)
_R2_SPEC.loader.exec_module(r2)

base = r2.base
r1 = r2.r1

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-svctl-status-runtime/v1"
QEMU_GUEST_PATH = r2.QEMU_GUEST_PATH
CPU_PROFILE = r2.CPU_PROFILE
SUPERVISOR = r2.SUPERVISOR
SVCTL = "/bin/svctl"
CTLMGR = r2.CTLMGR
UNIT_ROOT = r2.UNIT_ROOT
TARGET_UNIT = r2.TARGET_UNIT
CONTROL_SOCKET = "/tmp/supervisor.ctrl.socket"
LOGIN_PATH = r1.LOGIN_PATH


def _run(argv: list[str], *, timeout: int = 60, env: dict | None = None):
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def socket_path_state(root: pathlib.Path) -> dict:
    path = root / CONTROL_SOCKET.lstrip("/")
    try:
        st = path.lstat()
    except FileNotFoundError:
        return {"exists": False, "type": "missing"}
    mode = st.st_mode
    if stat.S_ISSOCK(mode):
        kind = "socket"
    elif stat.S_ISREG(mode):
        kind = "regular"
    elif stat.S_ISLNK(mode):
        kind = "symlink"
    elif stat.S_ISDIR(mode):
        kind = "directory"
    else:
        kind = "other"
    return {"exists": True, "type": kind}


def classify(result: dict) -> str:
    for attempt in result.get("httpAttempts", []):
        if (
            attempt.get("httpStatus") == 200
            and "session_info" in attempt.get("responseMarkers", [])
        ):
            return "E2_LOGIN_HTTP_SUPPORTED"
    if result.get("ctlmgrProcessObservedAfterStatus"):
        return "E2_CTLMGR_OBSERVED_AFTER_STATUS"
    if not result.get("supervisorProcessObservedBeforeStatus"):
        return "E2_SUPERVISOR_NOT_LIVE"
    if result.get("svctlStatusAttempted") and result.get("svctlStatusExitCode") == 0:
        return "E2_SVCTL_STATUS_COMPLETED"
    before = result.get("controlSocketBeforeStatus", {})
    after = result.get("controlSocketAfterStatus", {})
    if before.get("type") != "socket" and after.get("type") != "socket":
        return "E2_SUPERVISOR_CONTROL_SOCKET_ABSENT"
    if result.get("svctlStatusAttempted"):
        return "E2_SVCTL_STATUS_REJECTED"
    return "E2_STATUS_NOT_ATTEMPTED"


def ensure_mount_target(path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() and not path.is_symlink():
        path.touch()


def namespace_helper(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root).resolve()
    result_path = pathlib.Path(args.namespace_result).resolve()

    if _run(["ip", "link", "set", "lo", "up"]).returncode != 0:
        raise RuntimeError("failed to bring loopback up")
    links = _run(["ip", "-o", "link", "show"])
    import re
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
    response_dir = result_path.parent / "responses"

    supervisor_out = raw_dir / "supervisor.stdout"
    supervisor_err = raw_dir / "supervisor.stderr"
    supervisor_cmd = [
        "chroot", str(root), QEMU_GUEST_PATH, "-cpu", CPU_PROFILE,
        "-strace", SUPERVISOR, UNIT_ROOT, TARGET_UNIT,
    ]

    started = time.monotonic()
    with supervisor_out.open("wb") as out, supervisor_err.open("wb") as err:
        supervisor_proc = subprocess.Popen(
            supervisor_cmd,
            stdout=out,
            stderr=err,
            env=env,
            start_new_session=True,
        )

        time.sleep(args.supervisor_settle_seconds)
        supervisor_count_before = r1.count_guest_processes(SUPERVISOR)
        ctlmgr_count_before = r1.count_guest_processes(CTLMGR)
        control_before = socket_path_state(root)
        tcp_before, unix_before = r1.observe_sockets()

        status_attempted = supervisor_count_before > 0
        status_exit = None
        status_stdout_bytes = 0
        status_stderr_bytes = 0
        status_missing: list[dict] = []
        if status_attempted:
            status_cp = _run(
                [
                    "chroot", str(root), QEMU_GUEST_PATH, "-cpu", CPU_PROFILE,
                    "-strace", SVCTL, "status", "ctlmgr",
                ],
                timeout=10,
                env=env,
            )
            status_exit = status_cp.returncode
            status_stdout_bytes = len(status_cp.stdout.encode("utf-8", errors="replace"))
            status_stderr_bytes = len(status_cp.stderr.encode("utf-8", errors="replace"))
            status_missing = r1.parse_missing_paths(status_cp.stderr)

        time.sleep(args.post_status_settle_seconds)
        supervisor_count_after = r1.count_guest_processes(SUPERVISOR)
        ctlmgr_count_after = r1.count_guest_processes(CTLMGR)
        control_after = socket_path_state(root)
        tcp_after, unix_after = r1.observe_sockets()
        http_attempts = r1.http_probe(tcp_after, response_dir) if tcp_after else []

        if supervisor_proc.poll() is None:
            try:
                os.killpg(supervisor_proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                supervisor_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(supervisor_proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                supervisor_proc.wait(timeout=2)

    supervisor_err_text = supervisor_err.read_text(encoding="utf-8", errors="replace") if supervisor_err.exists() else ""
    elapsed = round(time.monotonic() - started, 3)
    result = {
        "probeCompleted": True,
        "interfaces": interfaces,
        "defaultRoutePresent": False,
        "cpuProfile": CPU_PROFILE,
        "supervisorPath": SUPERVISOR,
        "supervisorArguments": [UNIT_ROOT, TARGET_UNIT],
        "supervisorLauncherExitCode": supervisor_proc.returncode,
        "supervisorProcessObservedBeforeStatus": supervisor_count_before > 0,
        "supervisorProcessCountBeforeStatus": supervisor_count_before,
        "supervisorProcessCountAfterStatus": supervisor_count_after,
        "ctlmgrProcessCountBeforeStatus": ctlmgr_count_before,
        "ctlmgrProcessCountAfterStatus": ctlmgr_count_after,
        "ctlmgrProcessObservedAfterStatus": ctlmgr_count_after > 0,
        "controlSocketBeforeStatus": control_before,
        "controlSocketAfterStatus": control_after,
        "tcpListenersBeforeStatus": tcp_before,
        "tcpListenersAfterStatus": tcp_after,
        "unixSocketPathsBeforeStatus": unix_before,
        "unixSocketPathsAfterStatus": unix_after,
        "svctlStatusAttempted": status_attempted,
        "svctlStatusArguments": ["status", "ctlmgr"] if status_attempted else None,
        "svctlStatusExitCode": status_exit,
        "svctlStatusStdoutBytes": status_stdout_bytes,
        "svctlStatusStderrBytes": status_stderr_bytes,
        "svctlStatusMissingGuestPaths": status_missing,
        "supervisorMissingGuestPaths": r1.parse_missing_paths(supervisor_err_text),
        "httpAttempts": http_attempts,
        "elapsedSeconds": elapsed,
    }
    result["classification"] = classify(result)
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    shutil.rmtree(raw_dir, ignore_errors=True)
    shutil.rmtree(response_dir, ignore_errors=True)
    return 0


def prepare_qemu(root: pathlib.Path) -> None:
    source = shutil.which("qemu-mips-static")
    if not source:
        raise RuntimeError("qemu-mips-static not installed")
    target = root / QEMU_GUEST_PATH.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def run_namespace(root: pathlib.Path, result: pathlib.Path, args: argparse.Namespace) -> dict:
    cp = _run(
        [
            "sudo", "-n", "unshare", "--net", "--pid", "--fork", "--kill-child",
            "--mount-proc", sys.executable, str(pathlib.Path(__file__).resolve()),
            "--namespace-helper", "--root", str(root),
            "--namespace-result", str(result),
            "--supervisor-settle-seconds", str(args.supervisor_settle_seconds),
            "--post-status-settle-seconds", str(args.post_status_settle_seconds),
        ],
        timeout=max(45, int(args.supervisor_settle_seconds + args.post_status_settle_seconds) + 30),
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"isolated namespace probe failed (exit={cp.returncode}, stderrBytes={len(cp.stderr.encode())})"
        )
    if not result.exists():
        raise RuntimeError("namespace probe emitted no result")
    return json.loads(result.read_text(encoding="utf-8"))


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

    for guest in (SUPERVISOR, SVCTL, CTLMGR):
        path = root / guest.lstrip("/")
        header = base.parse_elf_header(path)
        if not header or header.get("machineName") != "MIPS":
            raise RuntimeError(f"candidate absent/not MIPS: {guest}")

    unit_path = root / UNIT_ROOT.lstrip("/") / TARGET_UNIT
    if not unit_path.is_file():
        raise RuntimeError("ctlmgr.service absent from exact root")

    preflight = {
        "ctlmgrUnitPresent": unit_path.is_file(),
        "avmipcdUnitPresent": (root / r2.AVMIPCD_UNIT.lstrip("/")).is_file(),
        "psupportDataPresent": (root / r2.PSUPPORT_DATA.lstrip("/")).exists(),
        "controlSocketPresentBeforeLaunch": (root / CONTROL_SOCKET.lstrip("/")).exists(),
    }

    symlinks = base.normalize_guest_absolute_symlinks(root)
    prepare_qemu(root)
    runtime = run_namespace(root, ns_result, args)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": runtime["classification"],
        "oracleSatisfied": bool(runtime.get("probeCompleted")),
        "target": {
            "kind": "public-runtime-download",
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
            "supervisorArguments": [UNIT_ROOT, TARGET_UNIT],
            "statusController": SVCTL,
            "statusArguments": ["status", "ctlmgr"],
            "preflightPathPresence": preflight,
            "fabricatedEnvironmentFile": False,
            "fabricatedAvmipcdState": False,
            "serviceStartRequested": False,
        },
        "isolation": {
            "filesystemChroot": True,
            "freshMountNamespace": True,
            "freshPidNamespace": True,
            "freshNetworkNamespace": True,
            "loopbackOnlyRequired": True,
            "externalRouteRequiredAbsent": True,
        },
        "runtime": runtime,
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "binaryPayloadPublished": False,
            "rawTargetStdoutPublished": False,
            "rawTargetStderrPublished": False,
            "rawStracePublished": False,
            "rawSvctlOutputPublished": False,
            "rawHttpBodyPublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
            "externalNetworkAvailableToTarget": False,
            "targetSpecificShimAdded": False,
            "psupportDataFabricated": False,
            "avmipcdStateFabricated": False,
            "serviceStartRequested": False,
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url")
    p.add_argument("--expected-size", type=int)
    p.add_argument("--expected-sha256")
    p.add_argument("--work-dir")
    p.add_argument("--receipt")
    p.add_argument("--supervisor-settle-seconds", type=float, default=3.0)
    p.add_argument("--post-status-settle-seconds", type=float, default=1.0)
    p.add_argument("--namespace-helper", action="store_true")
    p.add_argument("--root")
    p.add_argument("--namespace-result")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.namespace_helper:
        if not args.root or not args.namespace_result:
            raise SystemExit("namespace helper requires root/result")
        return namespace_helper(args)

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
                "binaryPayloadPublished": False,
                "rawTargetStdoutPublished": False,
                "rawTargetStderrPublished": False,
                "rawStracePublished": False,
                "rawSvctlOutputPublished": False,
                "rawHttpBodyPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
                "externalNetworkAvailableToTarget": False,
                "targetSpecificShimAdded": False,
                "psupportDataFabricated": False,
                "avmipcdStateFabricated": False,
                "serviceStartRequested": False,
            },
        }
        rc = 3
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": receipt["classification"], "oracleSatisfied": receipt["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
