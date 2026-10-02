#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-R0 ctlmgr runtime probe.

The probe runs exact shipped /usr/bin/ctlmgr inside:
- a disposable extracted rootfs chroot;
- a fresh mount namespace;
- a fresh PID namespace;
- a fresh network namespace with loopback as the only interface.

Raw target stdout/stderr/QEMU strace remain ephemeral. Durable output is limited
to sanitized metadata such as process state, listener ports, fixed response
marker booleans, and missing guest paths.
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
import tempfile
import time

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location(
    "fritz_qemu_user_probe", _BASE_SCRIPT
)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_user_probe.py")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-ctlmgr-runtime/v1"
CANDIDATE = "/usr/bin/ctlmgr"
QEMU_GUEST_PATH = "/usr/bin/qemu-mips-static"
CPU_PROFILE = "24KEc"
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
    return [
        name for name, marker in RESPONSE_MARKERS.items()
        if marker in data
    ]


def parse_missing_paths(raw: str) -> list[dict]:
    counts: dict[str, int] = {}
    # QEMU -strace commonly reports quoted paths on errno=2 lines.
    for line in raw.splitlines():
        if "errno=2" not in line and "No such file or directory" not in line:
            continue
        for quoted in re.findall(r'"([^"\n]{1,512})"', line):
            if not quoted.startswith("/"):
                continue
            if "\x00" in quoted:
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


def classify_namespace_result(result: dict) -> str:
    for attempt in result.get("httpAttempts", []):
        if (
            attempt.get("httpStatus") == 200
            and "session_info" in attempt.get("responseMarkers", [])
        ):
            return "E2_LOGIN_HTTP_SUPPORTED"
    if result.get("tcpListeners"):
        return "E2_LISTENER_OBSERVED"
    if result.get("targetRunningAtObservation"):
        return "E2_PROCESS_RUNNING_NO_LISTENER"
    return "E2_PROCESS_EXITED"


def ensure_basic_mount_target(path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        return
    path.touch()


def namespace_helper(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root).resolve()
    result_path = pathlib.Path(args.namespace_result).resolve()

    # Fresh network namespace must contain loopback only.
    cp = _run(["ip", "link", "set", "lo", "up"])
    if cp.returncode != 0:
        raise RuntimeError("failed to bring loopback up")

    links = _run(["ip", "-o", "link", "show"])
    if links.returncode != 0:
        raise RuntimeError("failed to inventory namespace interfaces")
    interfaces: list[str] = []
    for line in links.stdout.splitlines():
        match = re.match(r"\d+:\s+([^:@]+)", line)
        if match:
            interfaces.append(match.group(1))
    interfaces = sorted(set(interfaces))
    if interfaces != ["lo"]:
        raise RuntimeError(
            f"unexpected network namespace interfaces: {interfaces!r}"
        )

    default_route = _run(["ip", "route", "show", "default"])
    if default_route.returncode != 0 or default_route.stdout.strip():
        raise RuntimeError("fresh network namespace unexpectedly has a default route")

    # Expose only the namespace-local procfs and minimum pseudo-devices.
    (root / "proc").mkdir(parents=True, exist_ok=True)
    mount_proc = _run(["mount", "--bind", "/proc", str(root / "proc")])
    if mount_proc.returncode != 0:
        raise RuntimeError("failed to bind namespace procfs into guest root")

    for dev_name in ("null", "zero", "random", "urandom"):
        target = root / "dev" / dev_name
        ensure_basic_mount_target(target)
        cp = _run(["mount", "--bind", f"/dev/{dev_name}", str(target)])
        if cp.returncode != 0:
            raise RuntimeError(f"failed to bind /dev/{dev_name}")

    raw_stdout = result_path.with_suffix(".stdout.raw")
    raw_stderr = result_path.with_suffix(".stderr.raw")
    response_dir = result_path.parent / "responses"
    response_dir.mkdir(parents=True, exist_ok=True)

    env = {
        "PATH": "/bin:/sbin:/usr/bin:/usr/sbin",
        "HOME": "/",
        "LANG": "C",
        "LC_ALL": "C",
    }
    cmd = [
        "chroot",
        str(root),
        QEMU_GUEST_PATH,
        "-cpu",
        CPU_PROFILE,
        "-strace",
        CANDIDATE,
    ]

    started = time.monotonic()
    with raw_stdout.open("wb") as out, raw_stderr.open("wb") as err:
        proc = subprocess.Popen(
            cmd,
            stdout=out,
            stderr=err,
            env=env,
            start_new_session=True,
        )
        time.sleep(args.observation_seconds)

        running = proc.poll() is None
        ss_tcp = _run(["ss", "-ltnH"])
        ss_unix = _run(["ss", "-lxnH"])
        tcp_ports = extract_tcp_ports(
            ss_tcp.stdout if ss_tcp.returncode == 0 else ""
        )
        unix_paths = extract_unix_paths(
            ss_unix.stdout if ss_unix.returncode == 0 else ""
        )

        http_attempts: list[dict] = []
        for port in tcp_ports[:20]:
            for scheme in ("http", "https"):
                response_path = response_dir / f"{scheme}-{port}.body"
                curl_cmd = [
                    "curl",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "2",
                    "--output",
                    str(response_path),
                    "--write-out",
                    "%{http_code}",
                ]
                if scheme == "https":
                    curl_cmd.append("--insecure")
                curl_cmd.append(
                    f"{scheme}://127.0.0.1:{port}{LOGIN_PATH}"
                )
                cp = _run(curl_cmd, timeout=5)
                body = (
                    response_path.read_bytes()
                    if response_path.exists()
                    else b""
                )
                try:
                    http_status = int(cp.stdout.strip() or "0")
                except ValueError:
                    http_status = 0
                http_attempts.append({
                    "scheme": scheme,
                    "port": port,
                    "curlExitCode": cp.returncode,
                    "httpStatus": http_status,
                    "bodyBytes": len(body),
                    "responseMarkers": fixed_response_markers(body),
                })

        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=2)

    elapsed = time.monotonic() - started
    stdout_bytes = raw_stdout.stat().st_size if raw_stdout.exists() else 0
    stderr_bytes = raw_stderr.stat().st_size if raw_stderr.exists() else 0
    stderr_text = (
        raw_stderr.read_text(encoding="utf-8", errors="replace")
        if raw_stderr.exists()
        else ""
    )

    result = {
        "probeCompleted": True,
        "interfaces": interfaces,
        "defaultRoutePresent": False,
        "candidate": CANDIDATE,
        "cpuProfile": CPU_PROFILE,
        "targetRunningAtObservation": running,
        "targetExitCode": proc.returncode,
        "elapsedSeconds": round(elapsed, 3),
        "stdoutBytes": stdout_bytes,
        "stderrBytes": stderr_bytes,
        "stderrClass": base.classify_qemu_stderr(stderr_text),
        "missingGuestPaths": parse_missing_paths(stderr_text),
        "tcpListeners": tcp_ports,
        "unixSocketPaths": unix_paths,
        "httpAttempts": http_attempts,
    }
    result["classification"] = classify_namespace_result(result)
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # Raw data stays ephemeral; remove it before returning.
    for p in (raw_stdout, raw_stderr):
        try:
            p.unlink()
        except OSError:
            pass
    shutil.rmtree(response_dir, ignore_errors=True)
    return 0


def prepare_qemu_in_root(root: pathlib.Path) -> None:
    source = shutil.which("qemu-mips-static")
    if not source:
        raise RuntimeError("qemu-mips-static not installed")
    target = root / QEMU_GUEST_PATH.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def run_namespace_probe(
    root: pathlib.Path,
    result_path: pathlib.Path,
    *,
    observation_seconds: float,
) -> dict:
    cmd = [
        "sudo",
        "-n",
        "unshare",
        "--net",
        "--pid",
        "--fork",
        "--kill-child",
        "--mount-proc",
        sys.executable,
        str(pathlib.Path(__file__).resolve()),
        "--namespace-helper",
        "--root",
        str(root),
        "--namespace-result",
        str(result_path),
        "--observation-seconds",
        str(observation_seconds),
    ]
    cp = _run(cmd, timeout=max(30, int(observation_seconds) + 20))
    if cp.returncode != 0:
        raise RuntimeError(
            "isolated namespace probe failed "
            f"(exit={cp.returncode}, stderrBytes={len(cp.stderr.encode())})"
        )
    if not result_path.exists():
        raise RuntimeError("namespace probe did not emit result")
    return json.loads(result_path.read_text(encoding="utf-8"))


def run_probe(args: argparse.Namespace) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    firmware = work / "original" / "firmware.image"
    payload = work / "payload"
    roots_dir = work / "roots"
    scratch = work / "scratch"
    namespace_result = work / "namespace-result.json"
    for p in (firmware.parent, payload, roots_dir, scratch):
        p.mkdir(parents=True, exist_ok=True)

    exact = base.download_exact(
        args.firmware_url,
        firmware,
        expected_size=args.expected_size,
        expected_sha256=args.expected_sha256,
    )
    outer_members = base.extract_outer(firmware, payload)
    roots = base.extract_squashfs_roots(payload, roots_dir, scratch)
    selected = base.select_root(roots)

    candidate_path = selected / CANDIDATE.lstrip("/")
    header = base.parse_elf_header(candidate_path)
    if not header or header.get("machineName") != "MIPS":
        raise RuntimeError("ctlmgr candidate is missing or not observed as MIPS ELF")

    symlinks = base.normalize_guest_absolute_symlinks(selected)
    prepare_qemu_in_root(selected)
    runtime = run_namespace_probe(
        selected,
        namespace_result,
        observation_seconds=args.observation_seconds,
    )

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
            "outerMemberCount": len(outer_members),
            "squashfsRootCount": len(roots),
            "selectedRootRegularFileCount": base.root_file_count(selected),
            "guestAbsoluteSymlinksTranslated": symlinks["rewrittenCount"],
        },
        "candidate": {
            "path": CANDIDATE,
            "elf": header,
            "dynamicInterpreter": base.dynamic_interpreter(candidate_path),
            "readelfFlags": base.readelf_flags(candidate_path),
            "cpuProfile": CPU_PROFILE,
        },
        "isolation": {
            "filesystemChroot": True,
            "freshMountNamespace": True,
            "freshPidNamespace": True,
            "freshNetworkNamespace": True,
            "loopbackOnlyRequired": True,
            "externalRouteRequiredAbsent": True,
            "procfs": "namespace-local-bind",
            "pseudoDevices": [
                "/dev/null",
                "/dev/zero",
                "/dev/random",
                "/dev/urandom",
            ],
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
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url")
    p.add_argument("--expected-size", type=int)
    p.add_argument("--expected-sha256")
    p.add_argument("--work-dir")
    p.add_argument("--receipt")
    p.add_argument("--observation-seconds", type=float, default=4.0)
    p.add_argument("--namespace-helper", action="store_true")
    p.add_argument("--root")
    p.add_argument("--namespace-result")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.namespace_helper:
        if not args.root or not args.namespace_result:
            raise SystemExit("namespace helper requires --root and --namespace-result")
        return namespace_helper(args)

    required = (
        args.firmware_url,
        args.expected_size,
        args.expected_sha256,
        args.work_dir,
        args.receipt,
    )
    if any(v is None for v in required):
        raise SystemExit("normal probe mode requires firmware/size/hash/work/receipt")

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
            "error": {
                "type": type(exc).__name__,
                "message": str(exc)[:1000],
            },
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
