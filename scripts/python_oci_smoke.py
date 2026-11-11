#!/usr/bin/env python3
"""Public-synthetic, bounded Python/OCI disposable-runner qualification.

No private checkout, patient records, credentials, dynamically supplied code,
or persistent compute. This is an exploratory image/runner smoke test, NOT a
deployment image or a production workload.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile

PYTHON_PATCH = (3, 14, 10)
IMAGE_CANDIDATE = "python:3.14.10-slim"
FIXTURE = b"PUBLIC-SYNTHETIC-FIXTURE-NO-PRIVATE-DATA\n"
RECEIPT_SCHEMA = "public-python-oci-qualification/v1"
IMAGE_REF = re.compile(r"^[a-zA-Z0-9./_-]+@sha256:[a-f0-9]{64}$")


class Rejected(ValueError):
    pass


def _private_dir(path: Path) -> None:
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or (st.st_mode & 0o077):
        raise Rejected("unqualified directory")


def _read_fixed_source(path: Path) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size != len(FIXTURE):
        raise Rejected("unqualified source")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev, before.st_ino, before.st_size):
            raise Rejected("source changed")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(len(FIXTURE) + 1)
        ended = os.fstat(fd)
        after = path.lstat()
        if ((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) !=
                (ended.st_dev, ended.st_ino, ended.st_size, ended.st_mtime_ns)
                or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or raw != FIXTURE):
            raise Rejected("source changed or not synthetic")
        return raw
    finally:
        os.close(fd)


def _publish(root: Path, data: bytes) -> str:
    output = root / "outputs" / "result.json"
    expected = (json.dumps({
        "schema": RECEIPT_SCHEMA,
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "synthetic_output_sha256": hashlib.sha256(b"output\0" + data).hexdigest(),
    }, sort_keys=True) + "\n").encode("ascii")
    try:
        before = output.lstat()
    except FileNotFoundError:
        before = None
    if before is not None:
        if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077 or output.read_bytes() != expected:
            raise Rejected("conflicting output")
        return "REUSED"
    fd, temporary = tempfile.mkstemp(prefix=".part-", dir=root / "outputs")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(expected)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, output, follow_symlinks=False)
        except FileExistsError:
            if output.is_symlink() or output.read_bytes() != expected:
                raise Rejected("conflicting concurrent output")
            return "REUSED"
        return "PUBLISHED"
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def child(root: Path, scratch: Path, phase: str, crash: bool = False) -> str:
    _private_dir(root)
    _private_dir(root / "outputs")
    _private_dir(scratch)
    if root.resolve() == scratch.resolve() or scratch.resolve().is_relative_to(root.resolve()):
        raise Rejected("scratch overlaps durable store")
    data = _read_fixed_source(root / "input.bin")
    if phase == "prepare":
        (scratch / "plan.json").write_text(json.dumps({"sha256": hashlib.sha256(data).hexdigest()}))
        if crash:
            os._exit(75)
        return "PREPARED"
    if phase == "publish":
        if crash:
            raise Rejected("invalid phase")
        return _publish(root, data)
    raise Rejected("unknown phase")


def _subprocess(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, check=False, timeout=timeout)


def run_public_qualification(receipt_path: Path) -> dict:
    if os.environ.get("GITHUB_REPOSITORY") != "SemperSupra/agent-dispatch":
        raise Rejected("public executor identity unavailable")
    if os.environ.get("RUNNER_ARCH") not in ("X64", "ARM64"):
        raise Rejected("unsupported runner")
    expected_machine = "x86_64" if os.environ["RUNNER_ARCH"] == "X64" else "aarch64"
    if platform.machine() != expected_machine or not shutil.which("docker") or os.getuid() == 0:
        raise Rejected("unqualified runner")
    pull = _subprocess(["docker", "pull", "--quiet", IMAGE_CANDIDATE], 100)
    if pull.returncode:
        raise Rejected("candidate image pull failed")
    inspect = _subprocess(["docker", "image", "inspect", "--format",
                           "{{index .RepoDigests 0}}", IMAGE_CANDIDATE], 15)
    image_ref = inspect.stdout.strip()
    if inspect.returncode or not IMAGE_REF.fullmatch(image_ref):
        raise Rejected("immutable image identity unavailable")
    with tempfile.TemporaryDirectory(prefix="public-python-oci-") as td:
        base = Path(td)
        root, scratch = base / "external", base / "scratch"
        (root / "outputs").mkdir(parents=True, mode=0o700)
        scratch.mkdir(mode=0o700)
        root.chmod(0o700)
        scratch.chmod(0o700)
        (root / "outputs").chmod(0o700)
        (root / "input.bin").write_bytes(FIXTURE)
        image_call = [
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "64", "--memory", "512m", "--cpus", "1",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m",
            "--mount", f"type=bind,src={Path(__file__).resolve()},dst=/probe.py,readonly",
            "--mount", f"type=bind,src={root},dst=/external",
            "--mount", f"type=bind,src={scratch},dst=/scratch",
            image_ref, "python", "/probe.py", "--child",
            "--root", "/external", "--scratch", "/scratch",
        ]
        crash = _subprocess(image_call + ["--phase", "prepare", "--crash"], 30)
        if crash.returncode != 75 or list((root / "outputs").iterdir()) == [] is False:
            raise Rejected("forced termination oracle failed")
        shutil.rmtree(scratch)
        scratch.mkdir(mode=0o700)
        published = _subprocess(image_call + ["--phase", "publish"], 30)
        if published.returncode or json.loads(published.stdout).get("status") != "PUBLISHED":
            raise Rejected("recovery publication failed")
        target = root / "outputs" / "result.json"
        inode, initial = target.stat().st_ino, target.read_bytes()
        repeated = _subprocess(image_call + ["--phase", "publish"], 30)
        if repeated.returncode or json.loads(repeated.stdout).get("status") != "REUSED":
            raise Rejected("idempotent replay failed")
        if target.stat().st_ino != inode or target.read_bytes() != initial:
            raise Rejected("immutable replay changed output")
        (root / "input.bin").write_bytes(b"WRONG-PUBLIC-SYNTHETIC-CONTENT")
        denied = _subprocess(image_call + ["--phase", "publish"], 30)
        if denied.returncode != 2 or target.read_bytes() != initial:
            raise Rejected("negative source admission failed")
        if "WRONG-PUBLIC" in denied.stdout + denied.stderr:
            raise Rejected("source leaked in negative response")
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "status": "CANDIDATE_SMOKE_PASS",
            "public_synthetic": True,
            "source_sha": os.environ.get("GITHUB_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "runner_arch": os.environ["RUNNER_ARCH"],
            "machine": expected_machine,
            "python": ".".join(map(str, PYTHON_PATCH)),
            "image_candidate": IMAGE_CANDIDATE,
            "resolved_image_ref": image_ref,
            "source_only": True,
            "production_promotable": False,
            "clinical_qualification": False,
            "tested": ["forced-termination", "scratch-recreation", "immutable-publication",
                       "idempotent-replay", "non-synthetic-denial", "read-only-container"],
        }
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        return receipt


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--child", action="store_true")
    p.add_argument("--root", type=Path)
    p.add_argument("--scratch", type=Path)
    p.add_argument("--phase", choices=("prepare", "publish"))
    p.add_argument("--crash", action="store_true")
    p.add_argument("--receipt", type=Path)
    opts = p.parse_args(argv)
    try:
        if opts.child:
            if sys.version_info[:3] != PYTHON_PATCH or not opts.root or not opts.scratch:
                raise Rejected("python/runtime mismatch")
            status = child(opts.root, opts.scratch, opts.phase, opts.crash)
            print(json.dumps({"status": status}, sort_keys=True))
        else:
            if not opts.receipt:
                raise Rejected("receipt required")
            run_public_qualification(opts.receipt)
            print('{"status":"CANDIDATE_SMOKE_PASS"}')
        return 0
    except (Rejected, OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        print('{"status":"NOT_QUALIFIED"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
