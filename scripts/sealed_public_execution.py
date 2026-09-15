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
import os
import re
import shutil
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


def safe_extract(capsule: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    total = 0
    with tarfile.open(capsule, mode="r:gz") as tf:
        members = tf.getmembers()
        if not members or len(members) > MAX_MEMBER_COUNT:
            raise WorkerError("capsule member count is outside the allowed bound")
        root = destination.resolve()
        for member in members:
            if member.issym() or member.islnk() or member.isdev():
                raise WorkerError("capsule links/devices are prohibited")
            total += max(member.size, 0)
            if total > MAX_UNPACKED_BYTES:
                raise WorkerError("capsule exceeds unpacked-size limit")
            resolved = (destination / member.name).resolve()
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise WorkerError("capsule path escapes execution directory") from exc
        tf.extractall(destination, members=members, filter="data")
    run_sh = destination / "run.sh"
    if not run_sh.is_file() or run_sh.is_symlink():
        raise WorkerError("capsule must contain a regular top-level run.sh")


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


def run_assignment(
    *, assignment_id: str, capsule_b64: str, capsule_sha256: str,
    recipient: str, timeout_seconds: int, out_dir: Path,
) -> int:
    assignment_id = _validate_assignment_id(assignment_id)
    recipient = _validate_recipient(recipient)
    if timeout_seconds < 1 or timeout_seconds > MAX_TIMEOUT_SECONDS:
        raise WorkerError(f"timeout_seconds must be 1-{MAX_TIMEOUT_SECONDS}")

    started_at = _utc_now()
    out_dir.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="sealed-public-exec-") as temp_name:
        temp = Path(temp_name)
        capsule = decode_capsule(capsule_b64, capsule_sha256, temp)
        work = temp / "work"
        safe_extract(capsule, work)
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
            try:
                completed = subprocess.run(
                    ["bash", "run.sh"], cwd=work, env=env,
                    stdout=stdout_fh, stderr=stderr_fh,
                    timeout=timeout_seconds, check=False,
                )
                exit_code = int(completed.returncode)
            except subprocess.TimeoutExpired:
                exit_code = 124
                timed_out = True

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
    args = parser.parse_args()
    try:
        return run_assignment(
            assignment_id=args.assignment_id,
            capsule_b64=args.capsule_b64,
            capsule_sha256=args.capsule_sha256,
            recipient=args.recipient,
            timeout_seconds=args.timeout_seconds,
            out_dir=Path(args.out_dir),
        )
    except WorkerError as exc:
        print(f"sealed public execution rejected: {exc}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
