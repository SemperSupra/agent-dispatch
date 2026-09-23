#!/usr/bin/env python3
"""Bounded Firecracker F0 RDTE probe for public GitHub-hosted runners.

F0 proves only:
- the expected KVM device/sudo boundary is observable;
- one exact Firecracker archive is acquired and SHA-256 verified;
- the Firecracker binary is callable and self-identifies as the pinned version.

It does NOT prove guest boot, workload execution, isolation strength, or sovereign
operational readiness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA = "github-runner-firecracker-rdte/v1"
RUNG = "F0"
FIRECRACKER_VERSION = "1.17.0"
FIRECRACKER_ARCHIVE = f"firecracker-v{FIRECRACKER_VERSION}-x86_64.tgz"
FIRECRACKER_URL = (
    "https://github.com/firecracker-microvm/firecracker/releases/download/"
    f"v{FIRECRACKER_VERSION}/{FIRECRACKER_ARCHIVE}"
)
FIRECRACKER_SHA256 = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(argv: list[str], timeout: int = 20) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "argv": argv,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip()[:4096],
            "stderr": proc.stderr.strip()[:4096],
        }
    except Exception as exc:  # receipt, not traceback, is the public evidence
        return {"argv": argv, "error": f"{type(exc).__name__}: {exc}"}


def observe_kvm() -> dict[str, Any]:
    path = Path("/dev/kvm")
    result: dict[str, Any] = {"path": str(path), "exists": path.exists()}
    if not path.exists():
        return result

    st = path.stat()
    result.update(
        {
            "mode": stat.filemode(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
        }
    )

    try:
        fd = os.open(path, os.O_RDWR)
    except OSError as exc:
        result["direct_open"] = {
            "ok": False,
            "errno": exc.errno,
            "error": exc.strerror,
        }
    else:
        os.close(fd)
        result["direct_open"] = {"ok": True}

    result["sudo_noninteractive"] = command(["sudo", "-n", "true"])
    result["sudo_rw_test"] = command(
        ["sudo", "-n", "sh", "-c", "test -r /dev/kvm && test -w /dev/kvm"]
    )
    return result


def safe_extract_firecracker(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as tf:
        candidates = []
        for member in tf.getmembers():
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise ValueError(f"unsafe archive member: {member.name}")
            if member.isfile() and name.name == f"firecracker-v{FIRECRACKER_VERSION}-x86_64":
                candidates.append(member)

        if len(candidates) != 1:
            raise ValueError(
                f"expected exactly one Firecracker binary, found {len(candidates)}"
            )

        member = candidates[0]
        tf.extract(member, destination)
        binary = destination / member.name
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
        return binary


def make_receipt() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "rung": RUNG,
        "purpose": "public-GHA RDTE for later sovereign/local microVM execution",
        "result": "INCONCLUSIVE",
        "portable_evidence": {
            "vmm": {
                "name": "firecracker",
                "version_expected": FIRECRACKER_VERSION,
                "archive": FIRECRACKER_ARCHIVE,
                "archive_url": FIRECRACKER_URL,
                "sha256_expected": FIRECRACKER_SHA256,
                "sha256_observed": None,
                "version_command": None,
            },
            "guest_boot": "UNTESTED",
            "work_capsule": "UNTESTED",
            "network_policy": "UNTESTED",
            "guest_destruction": "UNTESTED",
        },
        "gha_adapter_evidence": {
            "runner_os": os.environ.get("RUNNER_OS"),
            "runner_arch": os.environ.get("RUNNER_ARCH"),
            "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "kvm": None,
        },
        "claims": {
            "firecracker_acquisition_callable": False,
            "guest_boot_supported": False,
            "microvm_workload_supported": False,
            "sovereign_operational_ready": False,
        },
        "notes": [],
    }


def run(out: Path) -> int:
    receipt = make_receipt()
    receipt["gha_adapter_evidence"]["kvm"] = observe_kvm()

    if platform.machine() not in {"x86_64", "AMD64"}:
        receipt["result"] = "SKIPPED_GUARDRAIL"
        receipt["notes"].append("F0 is pinned to x86_64 only.")
        out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        return 0

    if not Path("/dev/kvm").exists():
        receipt["result"] = "ENVIRONMENT_FAILURE"
        receipt["notes"].append("/dev/kvm is absent; prerequisite drift from #223.")
        out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        return 2

    with tempfile.TemporaryDirectory(prefix="fc-rdte-f0-") as td:
        temp = Path(td)
        archive = temp / FIRECRACKER_ARCHIVE
        try:
            with urllib.request.urlopen(FIRECRACKER_URL, timeout=60) as response:
                with archive.open("wb") as handle:
                    shutil.copyfileobj(response, handle)
        except Exception as exc:
            receipt["result"] = "ENVIRONMENT_FAILURE"
            receipt["notes"].append(
                f"Firecracker release acquisition failed: {type(exc).__name__}: {exc}"
            )
            out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            return 2

        observed = sha256_file(archive)
        receipt["portable_evidence"]["vmm"]["sha256_observed"] = observed
        if observed != FIRECRACKER_SHA256:
            receipt["result"] = "ORACLE_FAILURE"
            receipt["notes"].append("Pinned Firecracker archive SHA-256 mismatch.")
            out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            return 2

        try:
            binary = safe_extract_firecracker(archive, temp / "extract")
        except Exception as exc:
            receipt["result"] = "HARNESS_FAILURE"
            receipt["notes"].append(
                f"Verified archive extraction failed: {type(exc).__name__}: {exc}"
            )
            out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            return 2

        version = command([str(binary), "--version"])
        receipt["portable_evidence"]["vmm"]["version_command"] = version
        identity = (version.get("stdout") or "") + "\n" + (version.get("stderr") or "")
        if version.get("returncode") != 0 or f"v{FIRECRACKER_VERSION}" not in identity:
            receipt["result"] = "ORACLE_FAILURE"
            receipt["notes"].append("Firecracker binary did not self-identify as pinned version.")
            out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            return 2

    receipt["result"] = "SUPPORTED"
    receipt["claims"]["firecracker_acquisition_callable"] = True
    receipt["notes"].append(
        "F0 proves pinned VMM acquisition/callability only; guest boot and sovereign readiness remain unproven."
    )
    out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    return run(args.out)


if __name__ == "__main__":
    raise SystemExit(main())
