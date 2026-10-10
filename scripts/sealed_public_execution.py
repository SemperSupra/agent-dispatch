#!/usr/bin/env python3
"""Execute a bounded public-safe capsule and return only sealed evidence.

The capsule is a gzip-compressed tar archive passed as base64. It must contain
`run.sh`. Task stdout/stderr and files written beneath SEALED_RESULT_DIR are
captured into the plaintext result bundle, encrypted with age to the caller's
recipient, then the plaintext is removed.

This worker deliberately owns no project semantics. The trusted/private side is
responsible for deciding whether a projection is public-safe before dispatch.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import ntpath
import os
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ASSIGNMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,95}$")
AGE_RECIPIENT_RE = re.compile(r"^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$")
MAX_CAPSULE_B64 = 60_000
MAX_MEMBER_COUNT = 256
MAX_UNPACKED_BYTES = 16 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 7_200
MAX_CAPTURED_STREAM_BYTES = 1 * 1024 * 1024
MAX_RESULT_FILE_BYTES = 8 * 1024 * 1024
MAX_RESULT_FILES = 252
MAX_RESULT_TOTAL_BYTES = 16 * 1024 * 1024
RESULT_BUDGET_EXIT_CODE = 125


class WorkerError(ValueError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_assignment_id(value: str) -> str:
    if not ASSIGNMENT_RE.fullmatch(value):
        raise WorkerError("assignment_id must be 3-96 safe identifier characters")
    return value


def _validate_recipient(value: str) -> str:
    if not AGE_RECIPIENT_RE.fullmatch(value):
        raise WorkerError("recipient must be an age X25519 recipient (age1...)")
    return value


def decode_capsule(encoded: str, expected_sha256: str, destination: Path) -> Path:
    if not encoded or len(encoded) > MAX_CAPSULE_B64:
        raise WorkerError(f"capsule_b64 must be 1-{MAX_CAPSULE_B64} characters")
    if not re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", encoded):
        raise WorkerError("capsule_b64 contains non-base64 characters")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise WorkerError("capsule_sha256 must be a lowercase SHA-256 hex digest")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:  # binascii.Error varies by Python version
        raise WorkerError("capsule_b64 is not valid base64") from exc
    capsule = destination / "capsule.tar.gz"
    capsule.write_bytes(raw)
    actual = _sha256(capsule)
    if actual != expected_sha256:
        raise WorkerError("capsule SHA-256 mismatch")
    return capsule


def safe_extract(capsule: Path, destination: Path, *, platform: str = "linux") -> None:
    if platform == "windows" and not hasattr(ntpath, "isreserved"):
        raise WorkerError("Windows capsule validation requires Python 3.13+")
    destination.mkdir(parents=True, exist_ok=False)
    total = 0
    with tarfile.open(capsule, mode="r:gz") as tf:
        members = tf.getmembers()
        if not members or len(members) > MAX_MEMBER_COUNT:
            raise WorkerError("capsule member count is outside the allowed bound")
        root = destination.resolve()
        windows_seen: set[str] = set()
        for member in members:
            if member.issym() or member.islnk() or member.isdev():
                raise WorkerError("capsule links/devices are prohibited")
            if platform == "windows":
                # Enforce one portable POSIX-style member namespace; Windows treats
                # backslashes, drive prefixes, streams and device names specially.
                if "\\" in member.name or ":" in member.name:
                    raise WorkerError("Windows capsule member contains a forbidden path character")
                member_name = member.name.rstrip("/") if member.isdir() else member.name
                parts = member_name.split("/")
                if any(part in ("", ".", "..") for part in parts):
                    raise WorkerError("Windows capsule member path is not canonical")
                identity = member_name.casefold()
                if identity in windows_seen:
                    raise WorkerError("Windows capsule contains a case-folded path collision")
                windows_seen.add(identity)
                # CPython owns the evolving Win32 reserved-name rules (3.13+).
                # Keep archive-specific path/case collision checks separate.
                for part in parts:
                    if ntpath.isreserved(part):
                        raise WorkerError("Windows capsule member has a reserved name")
            total += max(member.size, 0)
            if total > MAX_UNPACKED_BYTES:
                raise WorkerError("capsule exceeds unpacked-size limit")
            resolved = (destination / member.name).resolve()
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise WorkerError("capsule path escapes execution directory") from exc
        tf.extractall(destination, members=members, filter="data")
    entrypoint = "run.ps1" if platform == "windows" else "run.sh"
    if platform == "windows" and not any(
        member.name == entrypoint and member.isfile() for member in members
    ):
        raise WorkerError("Windows capsule must name its exact top-level run.ps1")
    runner = destination / entrypoint
    if not runner.is_file() or runner.is_symlink():
        raise WorkerError(f"capsule must contain a regular top-level {entrypoint}")


def _truncate_stream(path: Path, max_bytes: int = MAX_CAPTURED_STREAM_BYTES) -> dict[str, object]:
    """Bound captured stdout/stderr while retaining both ends for diagnostics."""
    original_bytes = path.stat().st_size
    if original_bytes <= max_bytes:
        return {"original_bytes": original_bytes, "stored_bytes": original_bytes, "truncated": False}

    marker = b"\n...[sealed-public-execution output truncated]...\n"
    payload_budget = max(0, max_bytes - len(marker))
    head_bytes = payload_budget // 2
    tail_bytes = payload_budget - head_bytes
    with path.open("rb") as fh:
        head = fh.read(head_bytes)
        if tail_bytes:
            fh.seek(-tail_bytes, os.SEEK_END)
            tail = fh.read(tail_bytes)
        else:
            tail = b""
    path.write_bytes(head + marker + tail)
    return {
        "original_bytes": original_bytes,
        "stored_bytes": path.stat().st_size,
        "truncated": True,
    }


def enforce_result_budget(result: Path) -> dict[str, object]:
    """Bound material that will be sealed/uploaded without constraining task scratch data.

    Streams are truncated to a diagnostic head+tail. If substantive result files
    exceed any hard bound, they are replaced by a small diagnostic rather than
    uploading a partial result that could be mistaken for complete evidence.
    """
    stdout_info = _truncate_stream(result / "stdout.txt")
    stderr_info = _truncate_stream(result / "stderr.txt")
    files_root = result / "files"

    violations: list[str] = []
    file_count = 0
    file_bytes = 0
    largest_file_bytes = 0

    for item in sorted(files_root.rglob("*")):
        if item.is_symlink():
            violations.append("result files contain a symbolic link")
            continue
        if item.is_dir():
            continue
        if not item.is_file():
            violations.append("result files contain a non-regular filesystem entry")
            continue
        size = item.stat().st_size
        file_count += 1
        file_bytes += size
        largest_file_bytes = max(largest_file_bytes, size)
        if size > MAX_RESULT_FILE_BYTES:
            violations.append("a result file exceeds the per-file byte limit")

    if file_count > MAX_RESULT_FILES:
        violations.append("result file count exceeds the allowed bound")

    captured_bytes = int(stdout_info["stored_bytes"]) + int(stderr_info["stored_bytes"])
    if file_bytes + captured_bytes > MAX_RESULT_TOTAL_BYTES:
        violations.append("result payload exceeds the total byte limit")

    budget = {
        "limits": {
            "captured_stream_bytes_each": MAX_CAPTURED_STREAM_BYTES,
            "result_file_bytes_each": MAX_RESULT_FILE_BYTES,
            "result_files": MAX_RESULT_FILES,
            "result_total_bytes": MAX_RESULT_TOTAL_BYTES,
        },
        "observed": {
            "result_files": file_count,
            "result_file_bytes": file_bytes,
            "largest_result_file_bytes": largest_file_bytes,
            "stdout": stdout_info,
            "stderr": stderr_info,
        },
        "exceeded": bool(violations),
        "violations": sorted(set(violations)),
    }

    if violations:
        shutil.rmtree(files_root, ignore_errors=True)
        files_root.mkdir()
        (files_root / "result-budget-exceeded.json").write_text(
            json.dumps(budget, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return budget


def package_result(source: Path, destination: Path) -> None:
    with tarfile.open(destination, mode="w:gz") as tf:
        for item in sorted(source.rglob("*")):
            if item.is_file() and not item.is_symlink():
                tf.add(item, arcname=item.relative_to(source), recursive=False)


def seal_result(plaintext: Path, recipient: str, ciphertext: Path) -> None:
    if shutil.which("age") is None:
        raise WorkerError("age executable is required")
    subprocess.run(
        ["age", "--encrypt", "--recipient", recipient, "--output", str(ciphertext), str(plaintext)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def native_windows_powershell() -> str:
    """Use the native system interpreter, not an executable from capsule cwd."""
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise WorkerError("Windows SystemRoot is unavailable")
    executable = (Path(system_root) / "System32" / "WindowsPowerShell"
                  / "v1.0" / "powershell.exe")
    if not executable.is_file():
        raise WorkerError("Native Windows PowerShell 5.1 is unavailable")
    return str(executable)


def _windows_job_object():
    """Create a kill-on-close Win32 Job Object with no breakaway allowance.

    Every PowerShell descendant inherits the job; none may outlive the
    execution boundary. Windows 2025 supports nested jobs under a runner job.
    """
    import ctypes

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", ctypes.c_uint32),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_uint32),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_uint32),
            ("SchedulingClass", ctypes.c_uint32),
        ]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimits),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    kernel.CreateJobObjectW.restype = ctypes.c_void_p
    kernel.SetInformationJobObject.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32,
    ]
    kernel.SetInformationJobObject.restype = ctypes.c_int
    kernel.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel.AssignProcessToJobObject.restype = ctypes.c_int
    kernel.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.TerminateJobObject.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int

    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise WorkerError(f"CreateJobObjectW failed: {ctypes.get_last_error()}")
    limits = ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
    if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits),
                                          ctypes.sizeof(limits)):
        error = ctypes.get_last_error()
        kernel.CloseHandle(handle)
        raise WorkerError(f"SetInformationJobObject failed: {error}")
    return kernel, handle



def _resume_suspended_windows_process(kernel, proc) -> None:
    """Resume the initial thread only after Win32 Job Object admission."""
    import ctypes

    class ThreadEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_uint32),
            ("cntUsage", ctypes.c_uint32),
            ("th32ThreadID", ctypes.c_uint32),
            ("th32OwnerProcessID", ctypes.c_uint32),
            ("tpBasePri", ctypes.c_long),
            ("tpDeltaPri", ctypes.c_long),
            ("dwFlags", ctypes.c_uint32),
        ]

    kernel.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    kernel.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel.Thread32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(ThreadEntry)]
    kernel.Thread32First.restype = ctypes.c_int
    kernel.Thread32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(ThreadEntry)]
    kernel.Thread32Next.restype = ctypes.c_int
    kernel.OpenThread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenThread.restype = ctypes.c_void_p
    kernel.ResumeThread.argtypes = [ctypes.c_void_p]
    kernel.ResumeThread.restype = ctypes.c_uint32

    # Popen's CREATE_SUSPENDED launch has not executed the initial thread.
    # No capsule code can fork descendants before Job Object assignment.
    snapshot = kernel.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
    if snapshot == ctypes.c_void_p(-1).value:
        raise WorkerError(f"Windows thread snapshot failed: {ctypes.get_last_error()}")
    try:
        entry = ThreadEntry()
        entry.dwSize = ctypes.sizeof(entry)
        found = kernel.Thread32First(snapshot, ctypes.byref(entry))
        while found:
            if entry.th32OwnerProcessID == proc.pid:
                thread = kernel.OpenThread(0x0002, False, entry.th32ThreadID)
                if not thread:
                    raise WorkerError(f"OpenThread failed: {ctypes.get_last_error()}")
                try:
                    previous = kernel.ResumeThread(thread)
                    if previous != 1:
                        raise WorkerError(
                            f"ResumeThread unexpected suspend count: {previous}"
                        )
                    return
                finally:
                    kernel.CloseHandle(thread)
            found = kernel.Thread32Next(snapshot, ctypes.byref(entry))
        raise WorkerError("suspended Windows task initial thread not found")
    finally:
        kernel.CloseHandle(snapshot)


def _run_bounded_task(
    command: list[str], *, cwd: Path, env: dict[str, str],
    stdout_fh, stderr_fh, timeout_seconds: int, platform: str,
) -> tuple[int, bool]:
    """Own the entire subprocess tree, even after the entrypoint exits.

    On Windows, Popen starts the initial thread suspended. Assign it to
    the job before resuming, so task code cannot spawn outside containment.
    Fail closed if nested job admission or thread resumption fails.
    """
    kernel = job = None
    proc = None
    if platform == "windows":
        kernel, job = _windows_job_object()
    try:
        proc = subprocess.Popen(
            command, cwd=cwd, env=env, stdout=stdout_fh, stderr=stderr_fh,
            start_new_session=(platform == "linux"),
            creationflags=(0x00000004 if platform == "windows" else 0),  # CREATE_SUSPENDED
        )
        if job is not None:
            import ctypes
            if not kernel.AssignProcessToJobObject(job, ctypes.c_void_p(int(proc._handle))):
                raise WorkerError(
                    f"AssignProcessToJobObject failed: {ctypes.get_last_error()}"
                )
            _resume_suspended_windows_process(kernel, proc)
        try:
            return int(proc.wait(timeout=timeout_seconds)), False
        except subprocess.TimeoutExpired:
            return 124, True
    finally:
        if job is not None:
            # TerminateJobObject also kills descendants after a normal parent
            # exit. No surviving child may observe the post-task seal phase.
            kernel.TerminateJobObject(job, 125)
            kernel.CloseHandle(job)
        elif proc is not None and platform == "linux":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if proc is not None and proc.poll() is None:
            proc.kill()
        if proc is not None:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired as exc:
                raise WorkerError("timed-out task process could not be reaped") from exc


def run_assignment(
    *, assignment_id: str, capsule_b64: str, capsule_sha256: str,
    recipient: str, timeout_seconds: int, out_dir: Path,
    platform: str = "linux",
) -> int:
    assignment_id = _validate_assignment_id(assignment_id)
    recipient = _validate_recipient(recipient)
    if platform not in ("linux", "windows"):
        raise WorkerError("platform must be linux or windows")
    if timeout_seconds < 1 or timeout_seconds > MAX_TIMEOUT_SECONDS:
        raise WorkerError(f"timeout_seconds must be 1-{MAX_TIMEOUT_SECONDS}")

    started_at = _utc_now()
    out_dir.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="sealed-public-exec-") as temp_name:
        temp = Path(temp_name)
        capsule = decode_capsule(capsule_b64, capsule_sha256, temp)
        work = temp / "work"
        safe_extract(capsule, work, platform=platform)
        result = temp / "result"
        result.mkdir()
        stdout_path = result / "stdout.txt"
        stderr_path = result / "stderr.txt"

        env = os.environ.copy()
        env.update({
            "SEALED_ASSIGNMENT_ID": assignment_id,
            "SEALED_RESULT_DIR": str(result / "files"),
        })
        (result / "files").mkdir()
        exit_code = 125
        timed_out = False
        with stdout_path.open("wb") as stdout_fh, stderr_path.open("wb") as stderr_fh:
            command = ([native_windows_powershell(), "-NoProfile", "-NonInteractive",
                        "-File", "run.ps1"] if platform == "windows"
                       else ["bash", "run.sh"])
            exit_code, timed_out = _run_bounded_task(
                command, cwd=work, env=env,
                stdout_fh=stdout_fh, stderr_fh=stderr_fh,
                timeout_seconds=timeout_seconds, platform=platform,
            )

        task_exit_code = exit_code
        result_budget = enforce_result_budget(result)
        if result_budget["exceeded"]:
            exit_code = RESULT_BUDGET_EXIT_CODE

        metadata = {
            "schema_version": 1,
            "assignment_id": assignment_id,
            "started_at": started_at,
            "ended_at": _utc_now(),
            "exit_code": exit_code,
            "task_exit_code": task_exit_code,
            "worker_platform": platform,
            "timed_out": timed_out,
            "result_budget": result_budget,
            "capsule_sha256": capsule_sha256,
            "worker_repository": os.getenv("GITHUB_REPOSITORY"),
            "worker_revision": os.getenv("GITHUB_SHA"),
            "run_id": os.getenv("GITHUB_RUN_ID"),
            "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        }
        (result / "execution.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

        plaintext = temp / "result.tar.gz"
        package_result(result, plaintext)
        ciphertext = out_dir / "result.age"
        seal_result(plaintext, recipient, ciphertext)
        plaintext.unlink(missing_ok=True)

        receipt = {
            "schema_version": 1,
            "assignment_id": assignment_id,
            "worker_platform": platform,
            "status": "completed" if exit_code == 0 else "failed",
            "sealed_sha256": _sha256(ciphertext),
            "sealed_bytes": ciphertext.stat().st_size,
            "worker_revision": os.getenv("GITHUB_SHA"),
            "run_id": os.getenv("GITHUB_RUN_ID"),
            "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        }
        (out_dir / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        return exit_code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assignment-id", required=True)
    parser.add_argument("--capsule-b64", required=True)
    parser.add_argument("--capsule-sha256", required=True)
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    parser.add_argument("--out-dir", default=".sealed")
    parser.add_argument("--platform", choices=("linux", "windows"), default="linux")
    args = parser.parse_args()
    try:
        return run_assignment(
            assignment_id=args.assignment_id,
            capsule_b64=args.capsule_b64,
            capsule_sha256=args.capsule_sha256,
            recipient=args.recipient,
            timeout_seconds=args.timeout_seconds,
            out_dir=Path(args.out_dir),
            platform=args.platform,
        )
    except WorkerError as exc:
        print(f"sealed public execution rejected: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
