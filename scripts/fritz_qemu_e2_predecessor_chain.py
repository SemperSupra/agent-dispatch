#!/usr/bin/env python3
"""FRITZ E2-R7 conditional prodtest predecessor-chain experiment.

Exact isolated emulator treatment:
  supervisor /lib/systemd/system prodtest-network.target
  + already-earned generic /var/tmp fixture.

Causal chain:
  net_basic -> avmipcd -> ctlmgr

Each successor is attempted only if its predecessor produces either:
- a changed sanitized status fingerprint; or
- a newly observed exact execve in the supervisor trace.

No additional runtime fixture is introduced.
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

_R6_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_e2_svctl_start_ctlmgr.py")
_R6_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_svctl_start_ctlmgr", _R6_SCRIPT)
if _R6_SPEC is None or _R6_SPEC.loader is None:
    raise RuntimeError("unable to load R6 module")
r6 = importlib.util.module_from_spec(_R6_SPEC)
_R6_SPEC.loader.exec_module(r6)

r5 = r6.r5
r4 = r6.r4
r3 = r6.r3
r1 = r6.r1
base = r6.base

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-prodtest-predecessor-chain/v1"
QEMU_GUEST_PATH = r6.QEMU_GUEST_PATH
CPU_PROFILE = r6.CPU_PROFILE
SUPERVISOR = r6.SUPERVISOR
SVCTL = r6.SVCTL
UNIT_ROOT = r6.UNIT_ROOT
SUPERVISOR_TARGET = r6.SUPERVISOR_TARGET
CONTROL_SOCKET = r6.CONTROL_SOCKET

CHAIN = (
    ("net_basic", "/etc/net_basic.sh"),
    ("avmipcd", "/bin/avmipcd"),
    ("ctlmgr", "/usr/bin/ctlmgr"),
)


def _run(argv: list[str], *, timeout: int = 30, env: dict | None = None):
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def ensure_mount_target(path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() and not path.is_symlink():
        path.touch()


def exact_trace(raw: str) -> dict:
    extras = {
        "net_basic_exec": "/etc/net_basic.sh",
        "avmipcd_exec": "/bin/avmipcd",
        "selected_target": f"{UNIT_ROOT}/{SUPERVISOR_TARGET}",
        "selected_target_relative": SUPERVISOR_TARGET,
    }
    return r3.fixed_trace_evidence(raw, extras)


def execve_count(trace: dict, service: str) -> int:
    key = {
        "net_basic": "net_basic_exec",
        "avmipcd": "avmipcd_exec",
        "ctlmgr": "ctlmgr_exec",
    }[service]
    return int(
        trace.get("paths", {})
        .get(key, {})
        .get("syscalls", {})
        .get("execve", 0)
    )


def stage_progressed(pre: dict, post: dict, before_exec: int, after_exec: int) -> bool:
    return bool(r6.status_changed(pre, post) or after_exec > before_exec)


def classify(result: dict) -> str:
    stages = result.get("stages", [])
    if not result.get("controlSocketReady"):
        return "E2_R7_CONTROL_SOCKET_NOT_READY"
    if not stages:
        return "E2_R7_NO_STAGE_EXECUTED"

    for stage in stages:
        if stage["service"] == "ctlmgr":
            if result.get("ctlmgrTcpListeners"):
                return "E2_R7_CTLMGR_LISTENER_OBSERVED"
            if result.get("ctlmgrProcessObserved"):
                return "E2_R7_CTLMGR_PROCESS_OBSERVED"
            if stage.get("progressed"):
                return "E2_R7_CTLMGR_TRANSITION_WITHOUT_PROCESS"
            return "E2_R7_CTLMGR_NO_TRANSITION"

    last = stages[-1]
    if last["service"] == "avmipcd":
        return (
            "E2_R7_AVMIPCD_PROGRESSED_CTL MGR_NOT_ATTEMPTED".replace(" ", "_")
            if last.get("progressed")
            else "E2_R7_AVMIPCD_NO_TRANSITION"
        )
    if last["service"] == "net_basic":
        return (
            "E2_R7_NET_BASIC_PROGRESSED_AVMIPCD_NOT_ATTEMPTED"
            if last.get("progressed")
            else "E2_R7_NET_BASIC_NO_TRANSITION"
        )
    return "E2_R7_UNKNOWN_TERMINAL_STAGE"


def wait_observe(
    root: pathlib.Path,
    raw_trace_path: pathlib.Path,
    seconds: float,
    sample_interval: float,
) -> dict:
    deadline = time.monotonic() + seconds
    process_seen = {service: False for service, _ in CHAIN}
    max_process = {service: 0 for service, _ in CHAIN}
    tcp_seen: set[int] = set()
    unix_seen: set[str] = set()
    while time.monotonic() < deadline:
        for service, executable in CHAIN:
            count = r1.count_guest_processes(executable)
            process_seen[service] = process_seen[service] or count > 0
            max_process[service] = max(max_process[service], count)
        tcp_now, unix_now = r1.observe_sockets()
        tcp_seen.update(tcp_now)
        unix_seen.update(unix_now)
        time.sleep(sample_interval)

    raw = (
        raw_trace_path.read_text(encoding="utf-8", errors="replace")
        if raw_trace_path.exists()
        else ""
    )
    return {
        "processObserved": process_seen,
        "maxProcessCount": max_process,
        "tcpListeners": sorted(tcp_seen),
        "unixSockets": sorted(unix_seen)[:100],
        "trace": exact_trace(raw),
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
        raise RuntimeError("unexpected default route")

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
    supervisor_out = raw_dir / "supervisor.stdout"
    supervisor_err = raw_dir / "supervisor.stderr"

    started = time.monotonic()
    supervisor_cmd = [
        "chroot", str(root), QEMU_GUEST_PATH, "-cpu", CPU_PROFILE,
        "-strace", SUPERVISOR, UNIT_ROOT, SUPERVISOR_TARGET,
    ]

    with supervisor_out.open("wb") as out, supervisor_err.open("wb") as err:
        supervisor_proc = subprocess.Popen(
            supervisor_cmd,
            stdout=out,
            stderr=err,
            env=env,
            start_new_session=True,
        )

        control_ready = False
        control_first_seen = None
        deadline = time.monotonic() + args.control_wait_seconds
        while time.monotonic() < deadline:
            state = r6.socket_state(root, CONTROL_SOCKET)
            if state.get("type") == "socket":
                control_ready = True
                control_first_seen = round(time.monotonic() - started, 6)
                break
            time.sleep(args.sample_interval_seconds)

        pre_status = {
            service: r6.svctl_call(root, env, "status", service)
            for service, _ in CHAIN
        } if control_ready else {}

        stages: list[dict] = []
        aggregate_process_seen = {service: False for service, _ in CHAIN}
        aggregate_max = {service: 0 for service, _ in CHAIN}
        aggregate_tcp: set[int] = set()
        aggregate_unix: set[str] = set()

        for index, (service, executable) in enumerate(CHAIN):
            if not control_ready:
                break
            if index > 0 and not stages[-1].get("progressed"):
                break

            before_raw = (
                supervisor_err.read_text(encoding="utf-8", errors="replace")
                if supervisor_err.exists()
                else ""
            )
            before_trace = exact_trace(before_raw)
            before_exec = execve_count(before_trace, service)

            start_result = r6.svctl_call(root, env, "start", service)
            observed = wait_observe(
                root,
                supervisor_err,
                args.stage_verify_seconds,
                args.sample_interval_seconds,
            )
            after_exec = execve_count(observed["trace"], service)
            post_status = r6.svctl_call(root, env, "status", service)
            progressed = stage_progressed(
                pre_status[service],
                post_status,
                before_exec,
                after_exec,
            )

            for k, v in observed["processObserved"].items():
                aggregate_process_seen[k] = aggregate_process_seen[k] or v
            for k, v in observed["maxProcessCount"].items():
                aggregate_max[k] = max(aggregate_max[k], v)
            aggregate_tcp.update(observed["tcpListeners"])
            aggregate_unix.update(observed["unixSockets"])

            stages.append({
                "index": index,
                "service": service,
                "executable": executable,
                "preStatus": pre_status[service],
                "start": start_result,
                "postStatus": post_status,
                "statusChanged": r6.status_changed(
                    pre_status[service], post_status
                ),
                "execveCountBefore": before_exec,
                "execveCountAfter": after_exec,
                "execveCountDelta": max(0, after_exec - before_exec),
                "processObserved": observed["processObserved"][service],
                "maxProcessCount": observed["maxProcessCount"][service],
                "progressed": progressed,
            })

            # Successor is deliberately gated on actual evidence of transition.
            if not progressed:
                break

        final_raw = (
            supervisor_err.read_text(encoding="utf-8", errors="replace")
            if supervisor_err.exists()
            else ""
        )
        final_trace = exact_trace(final_raw)

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

    result = {
        "probeCompleted": True,
        "interfaces": interfaces,
        "defaultRoutePresent": False,
        "cpuProfile": CPU_PROFILE,
        "supervisorArguments": [UNIT_ROOT, SUPERVISOR_TARGET],
        "controlSocketReady": control_ready,
        "controlSocketFirstSeenSeconds": control_first_seen,
        "preStatus": pre_status,
        "stages": stages,
        "attemptedServices": [x["service"] for x in stages],
        "startCount": len(stages),
        "finalTrace": final_trace,
        "processObserved": aggregate_process_seen,
        "maxProcessCount": aggregate_max,
        "ctlmgrProcessObserved": aggregate_process_seen.get("ctlmgr", False),
        "ctlmgrTcpListeners": sorted(aggregate_tcp),
        "unixSocketPathsObserved": sorted(aggregate_unix)[:100],
        "controlSocketFinalState": r6.socket_state(root, CONTROL_SOCKET),
        "elapsedSeconds": round(time.monotonic() - started, 3),
    }
    result["classification"] = classify(result)
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    shutil.rmtree(raw_dir, ignore_errors=True)
    return 0


def run_probe(args: argparse.Namespace) -> dict:
    root, meta = r6.prepare_root(args)
    ns_result = pathlib.Path(args.work_dir).resolve() / "namespace-result.json"
    cp = _run(
        [
            "sudo", "-n", "unshare", "--net", "--pid", "--fork", "--kill-child",
            "--mount-proc", sys.executable, str(pathlib.Path(__file__).resolve()),
            "--namespace-helper", "--root", str(root),
            "--namespace-result", str(ns_result),
            "--control-wait-seconds", str(args.control_wait_seconds),
            "--stage-verify-seconds", str(args.stage_verify_seconds),
            "--sample-interval-seconds", str(args.sample_interval_seconds),
        ],
        timeout=max(
            45,
            int(args.control_wait_seconds + args.stage_verify_seconds * 3) + 30,
        ),
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
        "chain": {
            "orderedServices": [x[0] for x in CHAIN],
            "orderedExecutables": [x[1] for x in CHAIN],
            "successorRequiresPredecessorProgress": True,
            "progressEvidence": ["status-fingerprint-change", "execve-count-increase"],
        },
        "runtime": runtime,
        "interpretationBoundary": {
            "AfterEdgeNotAssumedHardRequirement": True,
            "successorNotAttemptedWithoutPredecessorProgress": True,
            "startExitZeroAloneDoesNotCountAsProgress": True,
            "physicalRouterSemanticsNotInferred": True,
        },
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "rawTargetStdoutPublished": False,
            "rawTargetStderrPublished": False,
            "rawStracePublished": False,
            "rawSvctlOutputPublished": False,
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
            "maximumServiceStartCount": 3,
            "conditionalStartChain": True,
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
    p.add_argument("--stage-verify-seconds", type=float, default=0.75)
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
                "maximumServiceStartCount": 3,
                "conditionalStartChain": True,
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
