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
EXPERIMENT = "fritz-qemu-e2-svctl-status-runtime/v2"
QEMU_GUEST_PATH = r2.QEMU_GUEST_PATH
CPU_PROFILE = r2.CPU_PROFILE
SUPERVISOR = r2.SUPERVISOR
SVCTL = "/bin/svctl"
CTLMGR = r2.CTLMGR
UNIT_ROOT = r2.UNIT_ROOT
TARGET_UNIT = r2.TARGET_UNIT
CONTROL_SOCKET = "/tmp/supervisor.ctrl.socket"
TRACE_PATHS = {
    "unit_root": UNIT_ROOT,
    "selected_network_pre_unit": f"{UNIT_ROOT}/network-pre.target",
    "selected_network_pre_unit_relative": "network-pre.target",
    "net_basic_unit": f"{UNIT_ROOT}/net_basic.service",
    "net_basic_unit_relative": "net_basic.service",
    "avmipcd_unit": r2.AVMIPCD_UNIT,
    "avmipcd_unit_relative": "avmipcd.service",
    "ctlmgr_unit": f"{UNIT_ROOT}/{TARGET_UNIT}",
    "ctlmgr_unit_relative": TARGET_UNIT,
    "multid_unit": f"{UNIT_ROOT}/multid.service",
    "multid_unit_relative": "multid.service",
    "dsld_unit": f"{UNIT_ROOT}/dsld.service",
    "dsld_unit_relative": "dsld.service",
    "net_basic_exec": "/etc/net_basic.sh",
    "avmipcd_exec": "/bin/avmipcd",
    "ctlmgr_exec": CTLMGR,
    "multid_exec": "/sbin/multid",
    "dsld_exec": "/sbin/dsld",
    "psupport_data": r2.PSUPPORT_DATA,
    "control_socket": CONTROL_SOCKET,
}
SAFE_TRACE_SYSCALLS = {"open", "openat", "access", "stat", "lstat", "readlink", "execve", "unlink", "bind", "connect"}


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


def fixed_trace_evidence(raw: str, extra_paths: dict[str, str] | None = None) -> dict:
    import re
    trace_paths = dict(TRACE_PATHS)
    if extra_paths:
        trace_paths.update(extra_paths)
    evidence = {
        key: {
            "path": path,
            "hitCount": 0,
            "successCount": 0,
            "failureCount": 0,
            "syscalls": {},
            "firstSeenIndex": None,
        }
        for key, path in trace_paths.items()
    }
    ctlmgr_execve_count = 0
    for line_index, line in enumerate(raw.splitlines()):
        m = re.match(r"^\s*\d+\s+([A-Za-z0-9_]+)\(", line)
        syscall = m.group(1) if m and m.group(1) in SAFE_TRACE_SYSCALLS else None
        failed = "errno=" in line or re.search(r"=\s*-\d+", line) is not None
        for key, path in trace_paths.items():
            if f'"{path}"' not in line:
                continue
            item = evidence[key]
            item["hitCount"] += 1
            if item["firstSeenIndex"] is None:
                item["firstSeenIndex"] = line_index
            if failed:
                item["failureCount"] += 1
            else:
                item["successCount"] += 1
            if syscall:
                item["syscalls"][syscall] = item["syscalls"].get(syscall, 0) + 1
                if key == "ctlmgr_exec" and syscall == "execve":
                    ctlmgr_execve_count += 1
    return {
        "paths": evidence,
        "ctlmgrExecveCount": ctlmgr_execve_count,
    }


def classify(result: dict) -> str:
    for attempt in result.get("httpAttempts", []):
        if (
            attempt.get("httpStatus") == 200
            and "session_info" in attempt.get("responseMarkers", [])
        ):
            return "E2_LOGIN_HTTP_SUPPORTED"
    if result.get("ctlmgrProcessObserved"):
        return "E2_CTLMGR_OBSERVED"
    trace = result.get("fixedPathTrace", {})
    if trace.get("ctlmgrExecveCount", 0) > 0:
        return "E2_CTLMGR_EXEC_ATTEMPTED"
    paths = trace.get("paths", {})
    unit_hits = (
        paths.get("ctlmgr_unit", {}).get("hitCount", 0)
        + paths.get("ctlmgr_unit_relative", {}).get("hitCount", 0)
    )
    psupport = paths.get("psupport_data", {})
    if unit_hits > 0:
        if psupport.get("failureCount", 0) > 0:
            return "E2_CTLMGR_UNIT_READ_PSUPPORT_MISSING"
        return "E2_CTLMGR_UNIT_READ_NO_EXEC"
    if result.get("svctlStatusAttempted") and result.get("svctlStatusExitCode") == 0:
        return "E2_SVCTL_STATUS_COMPLETED"
    if result.get("svctlStatusAttempted"):
        if not result.get("controlSocketObserved"):
            return "E2_SVCTL_STATUS_NO_CONTROL_SOCKET"
        return "E2_SVCTL_STATUS_REJECTED"
    if result.get("supervisorProcessObserved"):
        if not result.get("controlSocketObserved"):
            return "E2_SUPERVISOR_TRANSIENT_NO_CONTROL_SOCKET"
        return "E2_SUPERVISOR_CONTROL_SOCKET_OBSERVED_NO_STATUS"
    return "E2_SUPERVISOR_NEVER_OBSERVED"


def ensure_mount_target(path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() and not path.is_symlink():
        path.touch()


def run_svctl_status(root: pathlib.Path, env: dict) -> dict:
    cp = _run(
        [
            "chroot", str(root), QEMU_GUEST_PATH, "-cpu", CPU_PROFILE,
            "-strace", SVCTL, "status", "ctlmgr",
        ],
        timeout=10,
        env=env,
    )
    return {
        "exitCode": cp.returncode,
        "stdoutBytes": len(cp.stdout.encode("utf-8", errors="replace")),
        "stderrBytes": len(cp.stderr.encode("utf-8", errors="replace")),
        "missingGuestPaths": r1.parse_missing_paths(cp.stderr),
    }


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
    supervisor_target = getattr(args, "supervisor_target", TARGET_UNIT)
    supervisor_cmd = [
        "chroot", str(root), QEMU_GUEST_PATH, "-cpu", CPU_PROFILE,
        "-strace", SUPERVISOR, UNIT_ROOT, supervisor_target,
    ]

    started = time.monotonic()
    supervisor_seen = False
    control_seen = False
    ctlmgr_seen = False
    first_supervisor_seen = None
    last_supervisor_seen = None
    first_control_seen = None
    max_supervisor_count = 0
    max_ctlmgr_count = 0

    status_attempted = False
    status_reason = None
    status_exit = None
    status_stdout_bytes = 0
    status_stderr_bytes = 0
    status_missing: list[dict] = []

    tcp_seen: set[int] = set()
    unix_seen: set[str] = set()
    http_attempts: list[dict] = []

    with supervisor_out.open("wb") as out, supervisor_err.open("wb") as err:
        supervisor_proc = subprocess.Popen(
            supervisor_cmd,
            stdout=out,
            stderr=err,
            env=env,
            start_new_session=True,
        )

        deadline = time.monotonic() + args.startup_observe_seconds
        while time.monotonic() < deadline:
            now = time.monotonic()
            elapsed = now - started

            supervisor_count = r1.count_guest_processes(SUPERVISOR)
            ctlmgr_count = r1.count_guest_processes(CTLMGR)
            max_supervisor_count = max(max_supervisor_count, supervisor_count)
            max_ctlmgr_count = max(max_ctlmgr_count, ctlmgr_count)

            if supervisor_count > 0:
                supervisor_seen = True
                if first_supervisor_seen is None:
                    first_supervisor_seen = round(elapsed, 4)
                last_supervisor_seen = round(elapsed, 4)
            if ctlmgr_count > 0:
                ctlmgr_seen = True

            control_state = socket_path_state(root)
            if control_state.get("type") == "socket":
                control_seen = True
                if first_control_seen is None:
                    first_control_seen = round(elapsed, 4)

            tcp_now, unix_now = r1.observe_sockets()
            tcp_seen.update(tcp_now)
            unix_seen.update(unix_now)

            if (
                not status_attempted
                and (
                    control_seen
                    or (
                        supervisor_seen
                        and first_supervisor_seen is not None
                        and elapsed - first_supervisor_seen >= args.status_grace_seconds
                        and supervisor_count > 0
                    )
                )
            ):
                status_attempted = True
                status_reason = "control-socket-observed" if control_seen else "live-supervisor-grace-expired"
                status_result = run_svctl_status(root, env)
                status_exit = status_result["exitCode"]
                status_stdout_bytes = status_result["stdoutBytes"]
                status_stderr_bytes = status_result["stderrBytes"]
                status_missing = status_result["missingGuestPaths"]

            if tcp_now:
                http_attempts.extend(r1.http_probe(tcp_now, response_dir))

            if supervisor_proc.poll() is not None and supervisor_count == 0:
                break

            time.sleep(args.sample_interval_seconds)

        natural_exit_before_cleanup = supervisor_proc.poll() is not None
        natural_exit_code = supervisor_proc.returncode if natural_exit_before_cleanup else None

        control_after = socket_path_state(root)
        supervisor_after = r1.count_guest_processes(SUPERVISOR)
        ctlmgr_after = r1.count_guest_processes(CTLMGR)
        max_supervisor_count = max(max_supervisor_count, supervisor_after)
        max_ctlmgr_count = max(max_ctlmgr_count, ctlmgr_after)
        ctlmgr_seen = ctlmgr_seen or ctlmgr_after > 0
        if control_after.get("type") == "socket":
            control_seen = True

        if not status_attempted and control_after.get("type") == "socket":
            status_attempted = True
            status_reason = "control-socket-final-observed"
            status_result = run_svctl_status(root, env)
            status_exit = status_result["exitCode"]
            status_stdout_bytes = status_result["stdoutBytes"]
            status_stderr_bytes = status_result["stderrBytes"]
            status_missing = status_result["missingGuestPaths"]

        tcp_after, unix_after = r1.observe_sockets()
        tcp_seen.update(tcp_after)
        unix_seen.update(unix_after)

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
    trace_evidence = fixed_trace_evidence(
        supervisor_err_text,
        {
            "selected_target": f"{UNIT_ROOT}/{supervisor_target}",
            "selected_target_relative": supervisor_target,
        },
    )
    elapsed_total = round(time.monotonic() - started, 3)

    # Keep only distinct public-safe HTTP metadata rows.
    deduped_http = []
    seen_http = set()
    for item in http_attempts:
        key = (
            item.get("scheme"), item.get("port"), item.get("curlExitCode"),
            item.get("httpStatus"), item.get("bodyBytes"),
            tuple(item.get("responseMarkers", [])),
        )
        if key not in seen_http:
            seen_http.add(key)
            deduped_http.append(item)

    result = {
        "probeCompleted": True,
        "interfaces": interfaces,
        "defaultRoutePresent": False,
        "cpuProfile": CPU_PROFILE,
        "supervisorPath": SUPERVISOR,
        "supervisorArguments": [UNIT_ROOT, supervisor_target],
        "supervisorLauncherExitCode": supervisor_proc.returncode,
        "supervisorExitedNaturallyBeforeCleanup": natural_exit_before_cleanup,
        "supervisorNaturalExitCode": natural_exit_code,
        "supervisorProcessObserved": supervisor_seen,
        "firstSupervisorObservedSeconds": first_supervisor_seen,
        "lastSupervisorObservedSeconds": last_supervisor_seen,
        "maxSupervisorProcessCount": max_supervisor_count,
        "ctlmgrProcessObserved": ctlmgr_seen,
        "maxCtlmgrProcessCount": max_ctlmgr_count,
        "controlSocketObserved": control_seen,
        "firstControlSocketObservedSeconds": first_control_seen,
        "controlSocketFinalState": control_after,
        "svctlStatusAttempted": status_attempted,
        "svctlStatusAttemptReason": status_reason,
        "svctlStatusArguments": ["status", "ctlmgr"] if status_attempted else None,
        "svctlStatusExitCode": status_exit,
        "svctlStatusStdoutBytes": status_stdout_bytes,
        "svctlStatusStderrBytes": status_stderr_bytes,
        "svctlStatusMissingGuestPaths": status_missing,
        "supervisorMissingGuestPaths": r1.parse_missing_paths(supervisor_err_text),
        "fixedPathTrace": trace_evidence,
        "tcpListenersObserved": sorted(tcp_seen),
        "unixSocketPathsObserved": sorted(unix_seen)[:100],
        "httpAttempts": deduped_http,
        "elapsedSeconds": elapsed_total,
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
            "--startup-observe-seconds", str(args.startup_observe_seconds),
            "--sample-interval-seconds", str(args.sample_interval_seconds),
            "--status-grace-seconds", str(args.status_grace_seconds),
            "--supervisor-target", str(getattr(args, "supervisor_target", TARGET_UNIT)),
        ],
        timeout=max(45, int(args.startup_observe_seconds) + 30),
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

    unit_path = root / UNIT_ROOT.lstrip("/") / args.supervisor_target
    if not unit_path.is_file():
        raise RuntimeError(f"supervisor target absent from exact root: {args.supervisor_target}")

    preflight = {
        "selectedTargetPresent": unit_path.is_file(),
        "ctlmgrUnitPresent": (root / UNIT_ROOT.lstrip("/") / TARGET_UNIT).is_file(),
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
            "supervisorArguments": [UNIT_ROOT, args.supervisor_target],
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
    p.add_argument("--startup-observe-seconds", type=float, default=3.0)
    p.add_argument("--sample-interval-seconds", type=float, default=0.05)
    p.add_argument("--status-grace-seconds", type=float, default=0.15)
    p.add_argument(
        "--supervisor-target",
        choices=(TARGET_UNIT, "prodtest-network.target", "network.target"),
        default=TARGET_UNIT,
    )
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
