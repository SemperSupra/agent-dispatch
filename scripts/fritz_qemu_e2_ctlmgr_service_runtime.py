#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-R2 exact ctlmgr.service supervisor runtime probe."""
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

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-ctlmgr-service-runtime/v1"
QEMU_GUEST_PATH = "/usr/bin/qemu-mips-static"
CPU_PROFILE = "24KEc"
SUPERVISOR = "/bin/supervisor"
CTLMGR = "/usr/bin/ctlmgr"
UNIT_ROOT = "/lib/systemd/system"
TARGET_UNIT = "ctlmgr.service"
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


def classify(result: dict) -> str:
    for attempt in result.get("httpAttempts", []):
        if (
            attempt.get("httpStatus") == 200
            and "session_info" in attempt.get("responseMarkers", [])
        ):
            return "E2_LOGIN_HTTP_SUPPORTED"
    if result.get("ctlmgrTcpListeners"):
        return "E2_CTLMGR_LISTENER_OBSERVED"
    if result.get("ctlmgrProcessObserved"):
        return "E2_CTLMGR_STARTED_NO_LISTENER"
    if result.get("supervisorProcessObserved"):
        return "E2_SUPERVISOR_RUNNING_CTLMGR_NOT_OBSERVED"
    exit_code = result.get("supervisorLauncherExitCode")
    if exit_code not in (None, 0):
        return "E2_SERVICE_TARGET_REJECTED_OR_DEPENDENCY"
    return "E2_SERVICE_TARGET_EXITED"


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

    supervisor_seen = False
    ctlmgr_seen = False
    max_supervisor_count = 0
    max_ctlmgr_count = 0
    tcp_seen: set[int] = set()
    unix_seen: set[str] = set()
    http_attempts: list[dict] = []

    started = time.monotonic()
    with supervisor_out.open("wb") as out, supervisor_err.open("wb") as err:
        supervisor_proc = subprocess.Popen(
            supervisor_cmd,
            stdout=out,
            stderr=err,
            env=env,
            start_new_session=True,
        )

        deadline = time.monotonic() + args.observe_seconds
        probed_ports: set[int] = set()
        while time.monotonic() < deadline:
            supervisor_count = r1.count_guest_processes(SUPERVISOR)
            ctlmgr_count = r1.count_guest_processes(CTLMGR)
            supervisor_seen = supervisor_seen or supervisor_count > 0
            ctlmgr_seen = ctlmgr_seen or ctlmgr_count > 0
            max_supervisor_count = max(max_supervisor_count, supervisor_count)
            max_ctlmgr_count = max(max_ctlmgr_count, ctlmgr_count)
            tcp_now, unix_now = r1.observe_sockets()
            tcp_seen.update(tcp_now)
            unix_seen.update(unix_now)
            new_ports = sorted(set(tcp_now) - probed_ports)
            if new_ports:
                http_attempts.extend(r1.http_probe(new_ports, response_dir))
                probed_ports.update(new_ports)
            time.sleep(args.sample_interval_seconds)

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

    elapsed = round(time.monotonic() - started, 3)
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
        "supervisorProcessObserved": supervisor_seen,
        "maxSupervisorProcessCount": max_supervisor_count,
        "ctlmgrProcessObserved": ctlmgr_seen,
        "maxCtlmgrProcessCount": max_ctlmgr_count,
        "supervisorStdoutBytes": supervisor_out.stat().st_size if supervisor_out.exists() else 0,
        "supervisorStderrBytes": supervisor_err.stat().st_size if supervisor_err.exists() else 0,
        "missingGuestPaths": r1.parse_missing_paths(supervisor_err_text),
        "ctlmgrTcpListeners": sorted(tcp_seen),
        "unixSocketPaths": sorted(unix_seen)[:100],
        "httpAttempts": _dedupe_http(http_attempts),
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
            "--observe-seconds", str(args.observe_seconds),
            "--sample-interval-seconds", str(args.sample_interval_seconds),
        ],
        timeout=max(45, int(args.observe_seconds) + 30),
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

    for guest in (SUPERVISOR, CTLMGR):
        path = root / guest.lstrip("/")
        header = base.parse_elf_header(path)
        if not header or header.get("machineName") != "MIPS":
            raise RuntimeError(f"candidate absent/not MIPS: {guest}")

    unit_path = root / UNIT_ROOT.lstrip("/") / TARGET_UNIT
    if not unit_path.is_file():
        raise RuntimeError("ctlmgr.service absent from exact root")

    preflight = {
        "ctlmgrUnitPresent": unit_path.is_file(),
        "avmipcdUnitPresent": (root / AVMIPCD_UNIT.lstrip("/")).is_file(),
        "psupportDataPresent": (root / PSUPPORT_DATA.lstrip("/")).exists(),
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
            "arguments": [UNIT_ROOT, TARGET_UNIT],
            "targetUnit": TARGET_UNIT,
            "preflightPathPresence": preflight,
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
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url")
    p.add_argument("--expected-size", type=int)
    p.add_argument("--expected-sha256")
    p.add_argument("--work-dir")
    p.add_argument("--receipt")
    p.add_argument("--observe-seconds", type=float, default=8.0)
    p.add_argument("--sample-interval-seconds", type=float, default=0.25)
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
                "rawHttpBodyPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
                "externalNetworkAvailableToTarget": False,
                "targetSpecificShimAdded": False,
                "psupportDataFabricated": False,
                "avmipcdStateFabricated": False,
            },
        }
        rc = 3
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": receipt["classification"], "oracleSatisfied": receipt["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
