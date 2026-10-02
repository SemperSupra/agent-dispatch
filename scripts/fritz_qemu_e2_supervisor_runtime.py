#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-R1 supervisor -> svctl -> ctlmgr falsification probe."""
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
EXPERIMENT = "fritz-qemu-e2-supervisor-runtime/v1"
QEMU_GUEST_PATH = "/usr/bin/qemu-mips-static"
CPU_PROFILE = "24KEc"
SUPERVISOR = "/bin/supervisor"
SVCTL = "/bin/svctl"
CTLMGR = "/usr/bin/ctlmgr"
LOGIN_PATH = "/login_sid.lua?version=2"

RESPONSE_MARKERS = {
    "session_info": b"SessionInfo",
    "sid": b"<SID>",
    "challenge": b"<Challenge>",
    "block_time": b"<BlockTime>",
}


def _run(argv: list[str], *, timeout: int = 60, env: dict | None = None):
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def fixed_response_markers(data: bytes) -> list[str]:
    return [name for name, marker in RESPONSE_MARKERS.items() if marker in data]


def parse_missing_paths(raw: str) -> list[dict]:
    counts: dict[str, int] = {}
    for line in raw.splitlines():
        if "errno=2" not in line and "No such file or directory" not in line:
            continue
        for quoted in re.findall(r'"([^"\n]{1,512})"', line):
            if not quoted.startswith("/") or "\x00" in quoted:
                continue
            counts[quoted] = counts.get(quoted, 0) + 1
    return [
        {"path": path, "count": counts[path]}
        for path in sorted(counts, key=lambda p: (-counts[p], p))[:100]
    ]


def extract_tcp_ports(ss_output: str) -> list[int]:
    ports: set[int] = set()
    for line in ss_output.splitlines():
        for match in re.finditer(
            r"(?:127\.0\.0\.1|0\.0\.0\.0|\[::\]|::1|\*):(\d+)",
            line,
        ):
            ports.add(int(match.group(1)))
    return sorted(ports)


def extract_unix_paths(ss_output: str) -> list[str]:
    paths: set[str] = set()
    for line in ss_output.splitlines():
        for token in line.split():
            if token.startswith("/") and len(token) <= 512:
                paths.add(token)
    return sorted(paths)[:100]


def count_guest_processes(guest_path: str) -> int:
    needle = guest_path.encode("utf-8")
    count = 0
    proc_root = pathlib.Path("/proc")
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            data = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if needle in data:
            count += 1
    return count


def observe_sockets() -> tuple[list[int], list[str]]:
    tcp = _run(["ss", "-ltnH"])
    unix = _run(["ss", "-lxnH"])
    return (
        extract_tcp_ports(tcp.stdout if tcp.returncode == 0 else ""),
        extract_unix_paths(unix.stdout if unix.returncode == 0 else ""),
    )


def http_probe(tcp_ports: list[int], response_dir: pathlib.Path) -> list[dict]:
    attempts: list[dict] = []
    response_dir.mkdir(parents=True, exist_ok=True)
    for port in tcp_ports[:20]:
        for scheme in ("http", "https"):
            response_path = response_dir / f"{scheme}-{port}.body"
            argv = [
                "curl", "--silent", "--show-error", "--max-time", "2",
                "--output", str(response_path), "--write-out", "%{http_code}",
            ]
            if scheme == "https":
                argv.append("--insecure")
            argv.append(f"{scheme}://127.0.0.1:{port}{LOGIN_PATH}")
            cp = _run(argv, timeout=5)
            body = response_path.read_bytes() if response_path.exists() else b""
            try:
                status = int(cp.stdout.strip() or "0")
            except ValueError:
                status = 0
            attempts.append({
                "scheme": scheme,
                "port": port,
                "curlExitCode": cp.returncode,
                "httpStatus": status,
                "bodyBytes": len(body),
                "responseMarkers": fixed_response_markers(body),
            })
    return attempts


def classify(result: dict) -> str:
    for attempt in result.get("httpAttempts", []):
        if (
            attempt.get("httpStatus") == 200
            and "session_info" in attempt.get("responseMarkers", [])
        ):
            return "E2_LOGIN_HTTP_SUPPORTED"
    if result.get("ctlmgrTcpListeners"):
        return "E2_CTLMGR_LISTENER_OBSERVED"
    if result.get("ctlmgrProcessCountAfterStart", 0) > 0:
        return "E2_CTLMGR_STARTED_NO_LISTENER"
    if result.get("svctlAttempted") and result.get("svctlExitCode") != 0:
        return "E2_SUPERVISOR_RUNNING_SVCTL_REJECTED"
    if result.get("supervisorProcessCountBeforeSvctl", 0) > 0:
        return "E2_SUPERVISOR_RUNNING_CTLMGR_NOT_OBSERVED"
    return "E2_SUPERVISOR_NOT_LIVE"


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
        "-strace", SUPERVISOR,
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
        supervisor_count_before = count_guest_processes(SUPERVISOR)
        tcp_before, unix_before = observe_sockets()

        svctl_attempted = supervisor_count_before > 0
        svctl_exit: int | None = None
        svctl_stdout_bytes = 0
        svctl_stderr_bytes = 0
        svctl_missing: list[dict] = []
        if svctl_attempted:
            svctl_cp = _run(
                [
                    "chroot", str(root), QEMU_GUEST_PATH, "-cpu", CPU_PROFILE,
                    "-strace", SVCTL, "start", "ctlmgr",
                ],
                timeout=10,
                env=env,
            )
            svctl_exit = svctl_cp.returncode
            svctl_stdout_bytes = len(svctl_cp.stdout.encode("utf-8", errors="replace"))
            svctl_stderr_bytes = len(svctl_cp.stderr.encode("utf-8", errors="replace"))
            svctl_missing = parse_missing_paths(svctl_cp.stderr)

        time.sleep(args.ctlmgr_settle_seconds)
        supervisor_count_after = count_guest_processes(SUPERVISOR)
        ctlmgr_count_after = count_guest_processes(CTLMGR)
        tcp_after, unix_after = observe_sockets()
        http_attempts = http_probe(tcp_after, response_dir) if tcp_after else []

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
        "supervisorLauncherExitCode": supervisor_proc.returncode,
        "supervisorProcessCountBeforeSvctl": supervisor_count_before,
        "supervisorProcessCountAfterSvctl": supervisor_count_after,
        "supervisorStdoutBytes": supervisor_out.stat().st_size if supervisor_out.exists() else 0,
        "supervisorStderrBytes": supervisor_err.stat().st_size if supervisor_err.exists() else 0,
        "supervisorMissingGuestPaths": parse_missing_paths(supervisor_err_text),
        "tcpListenersBeforeSvctl": tcp_before,
        "unixSocketPathsBeforeSvctl": unix_before,
        "svctlAttempted": svctl_attempted,
        "svctlInvocation": ["start", "ctlmgr"] if svctl_attempted else None,
        "svctlExitCode": svctl_exit,
        "svctlStdoutBytes": svctl_stdout_bytes,
        "svctlStderrBytes": svctl_stderr_bytes,
        "svctlMissingGuestPaths": svctl_missing,
        "ctlmgrProcessCountAfterStart": ctlmgr_count_after,
        "ctlmgrTcpListeners": tcp_after,
        "unixSocketPathsAfterSvctl": unix_after,
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
            "--ctlmgr-settle-seconds", str(args.ctlmgr_settle_seconds),
        ],
        timeout=max(40, int(args.supervisor_settle_seconds + args.ctlmgr_settle_seconds) + 25),
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
        "hypothesisTreatment": {
            "supervisorFirst": True,
            "svctlOnlyIfSupervisorProcessObserved": True,
            "svctlArguments": ["start", "ctlmgr"],
            "exactInvocationProvenByStaticDiscovery": False,
            "purpose": "falsify supervisor-mediated ctlmgr start hypothesis",
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
    p.add_argument("--ctlmgr-settle-seconds", type=float, default=4.0)
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
            },
        }
        rc = 3
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": receipt["classification"], "oracleSatisfied": receipt["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
