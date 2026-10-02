#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-R6 one-shot svctl start ctlmgr experiment.

Exact stock service-manager treatment:
  supervisor /lib/systemd/system prodtest-network.target
with only the already-earned generic /var/tmp runtime directory.

Transaction:
  inspect(status ctlmgr) -> apply(start ctlmgr exactly once) -> verify(status/process/socket/http)

The experiment is isolated, loopback-only, disposable, and does not contact a
physical router. Raw target/svctl output is never published.
"""
from __future__ import annotations

import argparse
import hashlib
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

_R5_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_e2_prodtest_network_runtime.py")
_R5_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_prodtest_network_runtime", _R5_SCRIPT)
if _R5_SPEC is None or _R5_SPEC.loader is None:
    raise RuntimeError("unable to load R5 module")
r5 = importlib.util.module_from_spec(_R5_SPEC)
_R5_SPEC.loader.exec_module(r5)

r4 = r5.r4
r3 = r4.r3
r1 = r3.r1
base = r3.base

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-svctl-start-ctlmgr/v1"
QEMU_GUEST_PATH = r3.QEMU_GUEST_PATH
CPU_PROFILE = r3.CPU_PROFILE
SUPERVISOR = r3.SUPERVISOR
SVCTL = r3.SVCTL
CTLMGR = r3.CTLMGR
UNIT_ROOT = r3.UNIT_ROOT
SUPERVISOR_TARGET = r5.SUPERVISOR_TARGET
CONTROL_SOCKET = r3.CONTROL_SOCKET
NOTIFY_SOCKET = "/tmp/supervisor.notify.socket"
PSUPPORT_DATA = r3.r2.PSUPPORT_DATA


def _run(argv: list[str], *, timeout: int = 30, env: dict | None = None):
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def socket_state(root: pathlib.Path, guest_path: str) -> dict:
    path = root / guest_path.lstrip("/")
    try:
        st = path.lstat()
    except OSError:
        return {"path": guest_path, "exists": False, "type": "missing"}
    mode = st.st_mode
    if stat.S_ISSOCK(mode):
        kind = "socket"
    elif stat.S_ISREG(mode):
        kind = "regular"
    elif stat.S_ISDIR(mode):
        kind = "directory"
    elif stat.S_ISLNK(mode):
        kind = "symlink"
    else:
        kind = "other"
    return {"path": guest_path, "exists": True, "type": kind}


def svctl_call(root: pathlib.Path, env: dict, verb: str, service: str) -> dict:
    cp = _run(
        [
            "chroot", str(root), QEMU_GUEST_PATH, "-cpu", CPU_PROFILE,
            "-strace", SVCTL, verb, service,
        ],
        timeout=10,
        env=env,
    )
    return {
        "verb": verb,
        "service": service,
        "exitCode": cp.returncode,
        "stdoutBytes": len(cp.stdout.encode("utf-8", errors="replace")),
        "stdoutSha256": sha256_text(cp.stdout),
        "stderrBytes": len(cp.stderr.encode("utf-8", errors="replace")),
        "missingGuestPaths": r1.parse_missing_paths(cp.stderr),
        "rawOutputPublished": False,
    }


def status_changed(pre: dict, post: dict) -> bool:
    return (
        pre.get("exitCode") != post.get("exitCode")
        or pre.get("stdoutBytes") != post.get("stdoutBytes")
        or pre.get("stdoutSha256") != post.get("stdoutSha256")
    )


def classify(result: dict) -> str:
    for attempt in result.get("httpAttempts", []):
        if (
            attempt.get("httpStatus") == 200
            and "session_info" in attempt.get("responseMarkers", [])
        ):
            return "E2_LOGIN_HTTP_SUPPORTED"
    if result.get("ctlmgrTcpListeners"):
        return "E2_R6_CTLMGR_LISTENER_OBSERVED"
    if result.get("ctlmgrProcessObserved"):
        return "E2_R6_CTLMGR_PROCESS_OBSERVED"
    start = result.get("start", {})
    if not result.get("controlSocketReady"):
        return "E2_R6_CONTROL_SOCKET_NOT_READY"
    if start.get("exitCode") != 0:
        return "E2_R6_START_REJECTED"
    if result.get("statusChanged"):
        return "E2_R6_START_ACCEPTED_STATUS_CHANGED_NO_PROCESS"
    return "E2_R6_START_ACCEPTED_NO_OBSERVED_TRANSITION"


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
        "-strace", SUPERVISOR, UNIT_ROOT, SUPERVISOR_TARGET,
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

        # The R5 oracle proved the control socket may survive the short launcher.
        control_ready = False
        control_first_seen = None
        deadline = time.monotonic() + args.control_wait_seconds
        while time.monotonic() < deadline:
            state = socket_state(root, CONTROL_SOCKET)
            if state.get("type") == "socket":
                control_ready = True
                control_first_seen = round(time.monotonic() - started, 6)
                break
            time.sleep(args.sample_interval_seconds)

        pre = svctl_call(root, env, "status", "ctlmgr") if control_ready else None
        start_result = (
            svctl_call(root, env, "start", "ctlmgr")
            if control_ready
            else {
                "verb": "start",
                "service": "ctlmgr",
                "exitCode": None,
                "stdoutBytes": 0,
                "stdoutSha256": None,
                "stderrBytes": 0,
                "missingGuestPaths": [],
                "rawOutputPublished": False,
            }
        )

        ctlmgr_seen = False
        max_ctlmgr_count = 0
        tcp_seen: set[int] = set()
        unix_seen: set[str] = set()
        http_attempts: list[dict] = []
        probed_ports: set[int] = set()

        verify_deadline = time.monotonic() + args.verify_seconds
        while time.monotonic() < verify_deadline:
            ctlmgr_count = r1.count_guest_processes(CTLMGR)
            max_ctlmgr_count = max(max_ctlmgr_count, ctlmgr_count)
            ctlmgr_seen = ctlmgr_seen or ctlmgr_count > 0
            tcp_now, unix_now = r1.observe_sockets()
            tcp_seen.update(tcp_now)
            unix_seen.update(unix_now)
            new_ports = sorted(set(tcp_now) - probed_ports)
            if new_ports:
                http_attempts.extend(r1.http_probe(new_ports, response_dir))
                probed_ports.update(new_ports)
            time.sleep(args.sample_interval_seconds)

        post = svctl_call(root, env, "status", "ctlmgr") if control_ready else None

        control_final = socket_state(root, CONTROL_SOCKET)
        notify_final = socket_state(root, NOTIFY_SOCKET)

        if supervisor_proc.poll() is None:
            try:
                os.killpg(supervisor_proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                supervisor_proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(supervisor_proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                supervisor_proc.wait(timeout=1)

    supervisor_trace = (
        supervisor_err.read_text(encoding="utf-8", errors="replace")
        if supervisor_err.exists() else ""
    )
    fixed = r3.fixed_trace_evidence(
        supervisor_trace,
        {
            "selected_target": f"{UNIT_ROOT}/{SUPERVISOR_TARGET}",
            "selected_target_relative": SUPERVISOR_TARGET,
        },
    )

    deduped_http: list[dict] = []
    seen_http: set[tuple] = set()
    for item in http_attempts:
        key = (
            item.get("scheme"),
            item.get("port"),
            item.get("curlExitCode"),
            item.get("httpStatus"),
            item.get("bodyBytes"),
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
        "supervisorArguments": [UNIT_ROOT, SUPERVISOR_TARGET],
        "controlSocketReady": control_ready,
        "controlSocketFirstSeenSeconds": control_first_seen,
        "controlSocketFinalState": control_final,
        "notifySocketFinalState": notify_final,
        "preStatus": pre,
        "start": start_result,
        "postStatus": post,
        "statusChanged": (
            status_changed(pre, post)
            if isinstance(pre, dict) and isinstance(post, dict)
            else False
        ),
        "ctlmgrProcessObserved": ctlmgr_seen,
        "maxCtlmgrProcessCount": max_ctlmgr_count,
        "ctlmgrTcpListeners": sorted(tcp_seen),
        "unixSocketPathsObserved": sorted(unix_seen)[:100],
        "httpAttempts": deduped_http,
        "fixedPathTrace": fixed,
        "supervisorMissingGuestPaths": r1.parse_missing_paths(supervisor_trace),
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


def prepare_root(args: argparse.Namespace) -> tuple[pathlib.Path, dict]:
    work = pathlib.Path(args.work_dir).resolve()
    firmware = work / "original" / "firmware.image"
    payload = work / "payload"
    roots_dir = work / "roots"
    scratch = work / "scratch"
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

    for guest in (SUPERVISOR, SVCTL, CTLMGR):
        path = root / guest.lstrip("/")
        header = base.parse_elf_header(path)
        if not header or header.get("machineName") != "MIPS":
            raise RuntimeError(f"candidate absent/not MIPS: {guest}")

    target_path = root / UNIT_ROOT.lstrip("/") / SUPERVISOR_TARGET
    if not target_path.is_file():
        raise RuntimeError("prodtest-network.target absent from exact root")

    fixture = r4.materialize_var_tmp(root)
    symlinks = base.normalize_guest_absolute_symlinks(root)
    r3.prepare_qemu(root)

    meta = {
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
    }
    return root, meta


def run_probe(args: argparse.Namespace) -> dict:
    root, meta = prepare_root(args)
    ns_result = pathlib.Path(args.work_dir).resolve() / "namespace-result.json"
    cp = _run(
        [
            "sudo", "-n", "unshare", "--net", "--pid", "--fork", "--kill-child",
            "--mount-proc", sys.executable, str(pathlib.Path(__file__).resolve()),
            "--namespace-helper", "--root", str(root),
            "--namespace-result", str(ns_result),
            "--control-wait-seconds", str(args.control_wait_seconds),
            "--verify-seconds", str(args.verify_seconds),
            "--sample-interval-seconds", str(args.sample_interval_seconds),
        ],
        timeout=max(45, int(args.control_wait_seconds + args.verify_seconds) + 30),
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"isolated namespace probe failed (exit={cp.returncode}, stderrBytes={len(cp.stderr.encode())})"
        )
    if not ns_result.exists():
        raise RuntimeError("namespace probe emitted no result")
    runtime = json.loads(ns_result.read_text(encoding="utf-8"))

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": runtime["classification"],
        "oracleSatisfied": bool(runtime.get("probeCompleted")),
        **meta,
        "transaction": {
            "inspect": ["svctl", "status", "ctlmgr"],
            "apply": ["svctl", "start", "ctlmgr"],
            "applyCount": 1 if runtime.get("start", {}).get("exitCode") is not None else 0,
            "verify": ["svctl", "status", "ctlmgr"],
            "disposalIsRollback": True,
        },
        "runtime": runtime,
        "interpretationBoundary": {
            "startExitZeroDoesNotProveServiceHealthy": True,
            "statusHashChangeDoesNotRevealStatusContent": True,
            "physicalRouterSemanticsNotInferred": True,
        },
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
            "serviceStartRequested": True,
            "serviceStartCountMaximum": 1,
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
                "serviceStartRequested": False,
                "serviceStartCountMaximum": 1,
                "disposableEmulatorMutationOnly": True,
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
