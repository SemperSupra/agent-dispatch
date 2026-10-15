"""Application-written completion receipt with independent archive re-verification.

A successful report means only APPLICATION_REPORTED_COMPLETE, never a trusted
process exit code or a signed statement. The independent consumer supplies the
expected manifest and fresh operation ID; no Docker RBAC is required.

Synthetic fixture only; do not ingest real Takeout URLs, cookies or file data.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

SCHEMA = "takeout-application-completion/v1"
NAME = "completion-v1.json"
OPERATION = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{7,127}\Z")
FILE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z")


class ReceiptBlocked(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ReceiptBlocked(reason)


def file_info(path: Path) -> dict:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "NONREGULAR_FILE")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return {"bytes": info.st_size, "sha256": digest.hexdigest()}


def inventory(root: Path, expected: dict) -> dict:
    require(root.is_dir() and not root.is_symlink(), "UNOWNED_ARCHIVE")
    require(isinstance(expected, dict) and 1 <= len(expected) <= 10000,
            "INVALID_EXPECTED_MANIFEST")
    require(all(isinstance(name, str) and FILE.fullmatch(name)
                for name in expected), "INVALID_EXPECTED_FILENAME")
    require(set(p.name for p in root.iterdir()) == set(expected),
            "ARCHIVE_INVENTORY_MISMATCH")
    observed = {}
    for name in sorted(expected):
        spec = expected[name]
        require(isinstance(spec, dict) and set(spec) == {"bytes", "sha256"} and
                type(spec["bytes"]) is int and spec["bytes"] >= 0 and
                isinstance(spec["sha256"], str) and
                re.fullmatch(r"[0-9a-f]{64}", spec["sha256"]),
                "EXPECTED_FILE_SPEC_INVALID")
        got = file_info(root / name)
        require(got == spec, "FILE_BYTES_OR_HASH_MISMATCH")
        observed[name] = got
    return observed


def validate(report_path: Path, archive_root: Path, *, operation_id: str,
             expected: dict, expected_source: str) -> dict:
    """Untrusted application receipt is never enough: independently hash bytes."""
    require(isinstance(operation_id, str) and OPERATION.fullmatch(operation_id),
            "OPERATION_ID_INVALID")
    require(isinstance(expected_source, str) and expected_source,
            "SOURCE_UNQUALIFIED")
    require(report_path.name == NAME and not report_path.is_symlink() and
            report_path.is_file(), "MISSING_OR_UNOWNED_RECEIPT")
    raw = report_path.read_bytes()
    require(len(raw) <= 2 * 1024 * 1024, "RECEIPT_TOO_LARGE")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ReceiptBlocked("RECEIPT_INVALID_JSON") from None
    require(isinstance(doc, dict) and
            set(doc) == {"schema", "classification", "scope",
                         "operation_id", "source", "files"},
            "RECEIPT_SCHEMA_FIELDS")
    require(doc["schema"] == SCHEMA and
            doc["classification"] == "APPLICATION_REPORTED_COMPLETE" and
            doc["scope"] == "synthetic-local-only", "RECEIPT_STATUS_MISMATCH")
    require(doc["operation_id"] == operation_id and doc["source"] == expected_source,
            "STALE_OR_FOREIGN_OPERATION")
    actual = inventory(archive_root, expected)
    require(doc["files"] == actual, "RECEIPT_INVENTORY_MISMATCH")
    return {"classification": "INDEPENDENT_OUTPUT_VERIFIED_WITH_APPLICATION_REPORT",
            "schema": SCHEMA, "operation_id": operation_id,
            "verified_count": len(actual), "process_exit_zero_verified": False,
            "app_report_trusted_as_exit_evidence": False,
            "guest_qualified": False, "physical_apply": "HOLD"}


def publish(state_dir: Path, archive_root: Path, *, operation_id: str,
            expected: dict, expected_source: str) -> Path:
    """Write last, atomically and without replacing an earlier success report.

    The host must establish an owned, fresh operation identity and state path.
    Failed prior operations must never be converted into success by stale files.
    """
    require(isinstance(operation_id, str) and OPERATION.fullmatch(operation_id),
            "OPERATION_ID_INVALID")
    require(isinstance(expected_source, str) and expected_source,
            "SOURCE_UNQUALIFIED")
    require(state_dir.is_dir() and not state_dir.is_symlink() and
            state_dir.resolve() != archive_root.resolve(), "UNOWNED_STATE")
    dest = state_dir / NAME
    require(not dest.exists() and not dest.is_symlink(), "PRIOR_RECEIPT_PRESENT")
    current = inventory(archive_root, expected)
    document = {"schema": SCHEMA,
                "classification": "APPLICATION_REPORTED_COMPLETE",
                "scope": "synthetic-local-only",
                "operation_id": operation_id, "source": expected_source,
                "files": current}
    data = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    tmp = state_dir / (".completion-" + secrets.token_hex(16) + ".tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        # Atomic no-replace publication: prior success cannot be overwritten.
        os.link(tmp, dest, follow_symlinks=False)
        with os.fdopen(os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY), "rb"):
            pass
    finally:
        tmp.unlink(missing_ok=True)
    # Directory metadata durability matters for a power-loss recovery path.
    dfd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return dest
