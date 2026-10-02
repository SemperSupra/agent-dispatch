#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-R3 supervisor control/status observation probe.

R3 keeps the exact accepted E2-R2 supervisor treatment and adds only:
- read-only observation of /tmp/supervisor.ctrl.socket; and
- exact shipped /bin/svctl status ctlmgr.

No service start, target widening, target-specific fixture, or router contact is
authorized. Raw target/provider output remains ephemeral.
"""
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

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location("fritz_qemu_user_probe", _BASE_SCRIPT)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_user_probe.py")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

_R1_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_e2_supervisor_runtime.py")
_R1_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_supervisor_runtime", _R1_SCRIPT)
if _R1_SPEC is None or _R1_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_e2_supervisor_runtime.py")
r1 = importlib.util.module_from_spec(_R1_SPEC)
_R1_SPEC.loader.exec_module(r1)

_R2_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_e2_ctlmgr_service_runtime.py")
_R2_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_ctlmgr_service_runtime", _R2_SCRIPT)
if _R2_SPEC is None or _R2_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_e2_ctlmgr_service_runtime.py")
r2 = importlib.util.module_from_spec(_R2_SPEC)
_R2_SPEC.loader.exec_module(r2)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-supervisor-status/v1"
QEMU_GUEST_PATH = "/usr/bin/qemu-mips-static"
CPU_PROFILE = "24KEc"
SUPERVISOR = "/bin/supervisor"
SVCTL = "/bin/svctl"
CTLMGR = "/usr/bin/ctlmgr"
UNIT_ROOT = "/lib/systemd/system"
TARGET_UNIT = "ctlmgr.service"
CONTROL_SOCKET = "/tmp/supervisor.ctrl.socket"
AVMIPCD_UNIT = "/lib/systemd/system/avmipcd.service"
PSUPPORT_DATA = "/var/tmp/psupport.data"


def _run(argv: list[str], *, timeout: int = 60, env: dict | None = None):
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def supervisor_guest_argv() -> list[str]:
    return [SUPERVISOR, UNIT_ROOT, TARGET_UNIT]


def svctl_status_guest_argv() -> list[str]:
    return [SVCTL, "status", "ctlmgr"]


def guest_socket_state(root: pathlib.Path, guest_path: str) -> dict:
    host_path = root / guest_path.lstrip("/")
    try:
        mode = host_path.lstat().st_mode
    except OSError:
        return {"path": guest_path, "exists": False, "isUnixSocket": False}
    return {
        "path": guest_path,
        "exists": True,
        "isUnixSocket": stat.S_ISSOCK(mode),
    }


def classify(result: dict) -> str:
    for attempt in result.get("httpAttempts", []):
        if (
            attempt.get("httpStatus") == 200
            and "session_info" in attempt.get("responseMarkers", [])
        ):
            return "E2_LOGIN_HTTP_SUPPORTED"
    if result.get("ctlmgrTcpListenersAfterStatus"):
        return "E2_CTLMGR_LISTENER_OBSERVED"
    if result.get("ctlmgrProcessObservedAfterStatus"):
        return "E2_CTLMGR_STARTED_NO_LISTENER"
    if (
        result.get("svctlStatusAttempted")
        and result.get("svctlStatusExitCode") == 0
    ):
        return "E2_SVCTL_STATUS_OK_CTLMGR_NOT_RUNNING"
    socket_state = result.get("controlSocketBeforeStatus", {})
    if (
        socket_state.get("exists")
        and socket_state.get("isUnixSocket")
        and result.get("svctlStatusAttempted")
    ):
        return "E2_CTRL_SOCKET_PRESENT_SVCTL_STATUS_REJECTED"
    if result.get("svctlStatusAttempted"):
        return "E2_STATUS_DURING_LAUNCHER_NO_SOCKET"
    if result.get("launcherObservedRunning"):
        return "E2_LAUNCHER_WINDOW_TOO_SHORT_FOR_STATUS"
    return "E2_LAUNCHER_NOT_OBSERVED"


def ensure_mount_target(path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() and not path.is_symlink():
        path.touch()


def _dedupe_http(attempts: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for item in attempts:
        key = (
            item.get("scheme"),
            item.get("port"),
            item.get("curlExitCode"),
            item.get("httpStatus"),
            item.get("bodyBytes"),
            tuple(item.get("responseMarkers", [])),
        )
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def namespace_helper(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root).resolve()
    result_path = pathlib.Path(args.namespace_result).resolve()

    if _run(["ip", "link", "set", "lo", "up"]).returncode != 0:
        raise RuntimeError("failed to bring loopback up")
    links = _run(["ip", "-o", "link", "show"])
    interfaces = sorted(set(
        m.group(1)
        for line in links.stdout.splitlines()
        if (m := __import__("re").match(r"\d+:\s+([^:@]+)", line))
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

    env = {
        "PATH": "/bin:/sbin:/usr/bin:/usr/sbin",
        "HOME": "/",
        "LANG": "C",
        "LC_ALL": "C",
    }
    raw_dir = result_path.parent / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    response_dir = result_path.parent / "responses"

    supervisor_out = raw_dir / "supervisor.stdout"
    supervisor_err = raw_dir / "supervisor.stderr"
    supervisor_cmd = [
        "chroot", str(root), QEMU_GUEST_PATH, "-cpu", CPU_PROFILE,
        "-strace", *supervisor_guest_argv(),
    ]

    started = time.monotonic()
    launcher_seen = False
    launcher_exit_elapsed: float | None = None
    control_socket_first_seen: float | None = None
    socket_before_status = guest_socket_state(root, CONTROL_SOCKET)
    socket_after_status = socket_before_status

    svctl_attempted = False
    svctl_exit: int | None = None
    svctl_stdout_bytes = 0
    svctl_stderr_bytes = 0
    svctl_missing: list[dict] = []
    status_attempt_elapsed: float | None = None

    ctlmgr_seen_before = False
    ctlmgr_seen_after = False
    max_ctlmgr_before = 0
    max_ctlmgr_after = 0
    tcp_before: set[int] = set()
    unix_before: set[str] = set()
    tcp_after: set[int] = set()
    unix_after: set[str] = set()
    http_attempts: list[dict] = []
    probed_ports: set[int] = set()

    with supervisor_out.open("wb") as out, supervisor_err.open("wb") as err:
        supervisor_proc = subprocess.Popen(
            supervisor_cmd,
            stdout=out,
            stderr=err,
            env=env,
            start_new_session=True,
        )

        # Observe from process birth. R2's host /proc token counter also matched
        # the qemu launcher argv, so poll() is the authoritative launcher gate.
        deadline = time.monotonic() + args.status_window_seconds
        while time.monotonic() < deadline:
            now = time.monotonic()
            elapsed = now - started
            launcher_running = supervisor_proc.poll() is None
            launcher_seen = launcher_seen or launcher_running
            if not launcher_running and launcher_exit_elapsed is None:
                launcher_exit_elapsed = round(elapsed, 6)

            socket_now = guest_socket_state(root, CONTROL_SOCKET)
            if (
                socket_now.get("exists")
                and socket_now.get("isUnixSocket")
                and control_socket_first_seen is None
            ):
                control_socket_first_seen = round(elapsed, 6)

            # The exact launcher lifetime is short (~0.12 s in the first
            # corrected rep). Attempt read-only status before expensive /proc
            # and socket inventories so the probe is actually concurrent with
            # the live invocation.
            should_attempt_status = (
                not svctl_attempted
                and launcher_running
                and (
                    socket_now.get("isUnixSocket")
                    or elapsed >= args.status_fallback_delay_seconds
                )
            )
            if should_attempt_status:
                socket_before_status = socket_now
                status_attempt_elapsed = round(elapsed, 6)
                cp = _run(
                    [
                        "chroot", str(root), QEMU_GUEST_PATH, "-cpu", CPU_PROFILE,
                        "-strace", *svctl_status_guest_argv(),
                    ],
                    timeout=10,
                    env=env,
                )
                svctl_attempted = True
                svctl_exit = cp.returncode
                svctl_stdout_bytes = len(
                    cp.stdout.encode("utf-8", errors="replace")
                )
                svctl_stderr_bytes = len(
                    cp.stderr.encode("utf-8", errors="replace")
                )
                svctl_missing = r1.parse_missing_paths(cp.stderr)
                socket_after_status = guest_socket_state(root, CONTROL_SOCKET)
                break

            if not launcher_running:
                break

            # Before the one status attempt, do not spend the launch window on
            # /proc or socket-table inventory. Those observations occur after
            # status; here we only wait/poll for the socket or bounded fallback.
            time.sleep(args.sample_interval_seconds)

        post_deadline = time.monotonic() + args.post_status_observe_seconds
        while time.monotonic() < post_deadline:
            if supervisor_proc.poll() is not None and launcher_exit_elapsed is None:
                launcher_exit_elapsed = round(time.monotonic() - started, 6)

            ctlmgr_count = r1.count_guest_processes(CTLMGR)
            ctlmgr_seen_after = ctlmgr_seen_after or ctlmgr_count > 0
            max_ctlmgr_after = max(max_ctlmgr_after, ctlmgr_count)
            tcp_now, unix_now = r1.observe_sockets()
            tcp_after.update(tcp_now)
            unix_after.update(unix_now)
            new_ports = sorted(set(tcp_now) - probed_ports)
            if new_ports:
                http_attempts.extend(r1.http_probe(new_ports, response_dir))
                probed_ports.update(new_ports)

            socket_now = guest_socket_state(root, CONTROL_SOCKET)
            if (
                socket_now.get("exists")
                and socket_now.get("isUnixSocket")
                and control_socket_first_seen is None
            ):
                control_socket_first_seen = round(
                    time.monotonic() - started, 6
                )
            socket_after_status = socket_now
            time.sleep(args.sample_interval_seconds)

        terminated_by_harness = supervisor_proc.poll() is None
        if terminated_by_harness:
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
        elif launcher_exit_elapsed is None:
            launcher_exit_elapsed = round(time.monotonic() - started, 6)

    supervisor_err_text = (
        supervisor_err.read_text(encoding="utf-8", errors="replace")
        if supervisor_err.exists() else ""
    )
    result = {
        "probeCompleted": True,
        "interfaces": interfaces,
        "defaultRoutePresent": False,
        "cpuProfile": CPU_PROFILE,
        "supervisorPath": SUPERVISOR,
        "supervisorArguments": [UNIT_ROOT, TARGET_UNIT],
        "supervisorLauncherExitCode": supervisor_proc.returncode,
        "launcherObservedRunning": launcher_seen,
        "launcherExitElapsedSeconds": launcher_exit_elapsed,
        "launcherTerminatedByHarness": terminated_by_harness,
        "controlSocketFirstSeenElapsedSeconds": control_socket_first_seen,
        "controlSocketBeforeStatus": socket_before_status,
        "controlSocketAfterStatus": socket_after_status,
        "ctlmgrProcessObservedBeforeStatus": ctlmgr_seen_before,
        "maxCtlmgrProcessCountBeforeStatus": max_ctlmgr_before,
        "tcpListenersBeforeStatus": sorted(tcp_before),
        "unixSocketPathsBeforeStatus": sorted(unix_before)[:100],
        "svctlStatusAttempted": svctl_attempted,
        "svctlStatusAttemptElapsedSeconds": status_attempt_elapsed,
        "svctlStatusInvocation": ["status", "ctlmgr"] if svctl_attempted else None,
        "svctlStatusExitCode": svctl_exit,
        "svctlStatusStdoutBytes": svctl_stdout_bytes,
        "svctlStatusStderrBytes": svctl_stderr_bytes,
        "svctlStatusMissingGuestPaths": svctl_missing,
        "ctlmgrProcessObservedAfterStatus": ctlmgr_seen_after,
        "maxCtlmgrProcessCountAfterStatus": max_ctlmgr_after,
        "ctlmgrTcpListenersAfterStatus": sorted(tcp_after),
        "unixSocketPathsAfterStatus": sorted(unix_after)[:100],
        "httpAttempts": _dedupe_http(http_attempts),
        "supervisorStdoutBytes": (
            supervisor_out.stat().st_size if supervisor_out.exists() else 0
        ),
        "supervisorStderrBytes": (
            supervisor_err.stat().st_size if supervisor_err.exists() else 0
        ),
        "supervisorMissingGuestPaths": r1.parse_missing_paths(
            supervisor_err_text
        ),
        "elapsedSeconds": round(time.monotonic() - started, 3),
    }
    result["classification"] = classify(result)
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

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
            "--status-window-seconds", str(args.status_window_seconds),
            "--status-fallback-delay-seconds", str(args.status_fallback_delay_seconds),
            "--post-status-observe-seconds", str(args.post_status_observe_seconds),
            "--sample-interval-seconds", str(args.sample_interval_seconds),
        ],
        timeout=max(
            45,
            int(args.status_window_seconds + args.post_status_observe_seconds) + 30,
        ),
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"isolated namespace probe failed (exit={cp.returncode}, "
            f"stderrBytes={len(cp.stderr.encode())})"
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
        args.firmware_url,
        firmware,
        expected_size=args.expected_size,
        expected_sha256=args.expected_sha256,
    )
    outer = base.extract_outer(firmware, payload)
    roots = base.extract_squashfs_roots(payload, roots_dir, scratch)
    root = base.select_root(roots)

    candidates = {}
    for guest in (SUPERVISOR, SVCTL, CTLMGR):
        path = root / guest.lstrip("/")
        header = base.parse_elf_header(path)
        if not header or header.get("machineName") != "MIPS":
            raise RuntimeError(f"candidate absent/not MIPS: {guest}")
        candidates[guest] = {
            "elf": header,
            "dynamicInterpreter": base.dynamic_interpreter(path),
            "readelfFlags": base.readelf_flags(path),
        }

    unit_path = root / UNIT_ROOT.lstrip("/") / TARGET_UNIT
    if not unit_path.is_file():
        raise RuntimeError("ctlmgr.service absent from exact root")

    preflight = {
        "ctlmgrUnitPresent": unit_path.is_file(),
        "avmipcdUnitPresent": (root / AVMIPCD_UNIT.lstrip("/")).is_file(),
        "psupportDataPresent": (root / PSUPPORT_DATA.lstrip("/")).exists(),
        "controlSocketPresentBeforeLaunch": (
            root / CONTROL_SOCKET.lstrip("/")
        ).exists(),
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
        "candidates": candidates,
        "exactTreatment": {
            "supervisorPath": SUPERVISOR,
            "supervisorArguments": [UNIT_ROOT, TARGET_UNIT],
            "svctlPath": SVCTL,
            "svctlArguments": ["status", "ctlmgr"],
            "targetUnit": TARGET_UNIT,
            "controlSocketPath": CONTROL_SOCKET,
            "preflightPathPresence": preflight,
            "serviceStartAuthorized": False,
            "targetWideningAuthorized": False,
            "fabricatedEnvironmentFile": False,
            "fabricatedAvmipcdState": False,
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
            "rawHttpBodyPublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
            "externalNetworkAvailableToTarget": False,
            "targetSpecificShimAdded": False,
            "psupportDataFabricated": False,
            "avmipcdStateFabricated": False,
            "serviceStartAuthorized": False,
            "targetWideningAuthorized": False,
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url")
    p.add_argument("--expected-size", type=int)
    p.add_argument("--expected-sha256")
    p.add_argument("--work-dir")
    p.add_argument("--receipt")
    p.add_argument("--status-window-seconds", type=float, default=2.0)
    p.add_argument("--status-fallback-delay-seconds", type=float, default=0.005)
    p.add_argument("--post-status-observe-seconds", type=float, default=2.0)
    p.add_argument("--sample-interval-seconds", type=float, default=0.005)
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
                "rawHttpBodyPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
                "externalNetworkAvailableToTarget": False,
                "targetSpecificShimAdded": False,
                "psupportDataFabricated": False,
                "avmipcdStateFabricated": False,
                "serviceStartAuthorized": False,
                "targetWideningAuthorized": False,
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
