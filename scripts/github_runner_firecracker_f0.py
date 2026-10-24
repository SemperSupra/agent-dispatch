#!/usr/bin/env python3
"""Bounded Firecracker F0 acquisition/version and KVM preflight oracle.

The portable VMM identity is kept separate from GitHub Actions adapter facts so
this experiment can later be reproduced on an ordinary sovereign KVM host.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

from firecracker_lifecycle_timing import LifecycleTimer

PROBE_VERSION = "firecracker-f0/1"
RECEIPT_SCHEMA = "firecracker-f0-receipt/v1"
KVM_GET_API_VERSION = 0xAE00
EXPECTED_KVM_API_VERSION = 12


def _run(argv: list[str], timeout: int = 20) -> tuple[int | None, str, str]:
    try:
        cp = subprocess.run(
            argv, check=False, capture_output=True, text=True, timeout=timeout
        )
        return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", str(exc)


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, destination: pathlib.Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "SemperSupra-agent-dispatch-firecracker-f0/1"},
    )
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as out:
        shutil.copyfileobj(response, out)


def _safe_extract(archive: pathlib.Path, destination: pathlib.Path) -> None:
    root = destination.resolve()
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf.getmembers():
            target = (destination / member.name).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f"archive member escapes extraction root: {member.name}")
        tf.extractall(destination)


def _find_firecracker_binary(root: pathlib.Path, version: str, arch: str) -> pathlib.Path:
    exact = f"firecracker-{version}-{arch}"
    candidates = [p for p in root.rglob(exact) if p.is_file()]
    if not candidates:
        candidates = [
            p
            for p in root.rglob("firecracker*")
            if p.is_file() and "jailer" not in p.name and ".debug" not in p.name
        ]
    if len(candidates) != 1:
        raise RuntimeError(
            f"expected exactly one Firecracker binary candidate, found {len(candidates)}"
        )
    return candidates[0]


def _kvm_user_probe() -> dict:
    path = pathlib.Path("/dev/kvm")
    if not path.exists():
        return {
            "present": False,
            "callable": False,
            "api_version": None,
            "error": "/dev/kvm not present",
        }
    try:
        fd = os.open(str(path), os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        try:
            version = fcntl.ioctl(fd, KVM_GET_API_VERSION, 0)
        finally:
            os.close(fd)
        return {
            "present": True,
            "callable": version == EXPECTED_KVM_API_VERSION,
            "api_version": version,
            "error": None,
        }
    except Exception as exc:
        return {
            "present": True,
            "callable": False,
            "api_version": None,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _kvm_sudo_probe() -> dict:
    sudo = shutil.which("sudo")
    if not sudo:
        return {
            "available": False,
            "callable": False,
            "api_version": None,
            "error": "sudo command not found",
        }

    snippet = (
        "import fcntl,os;"
        "fd=os.open('/dev/kvm',os.O_RDWR|getattr(os,'O_CLOEXEC',0));"
        f"v=fcntl.ioctl(fd,{KVM_GET_API_VERSION},0);"
        "os.close(fd);print(v)"
    )
    code, out, err = _run([sudo, "-n", sys.executable, "-c", snippet], timeout=15)
    api_version = None
    if code == 0:
        try:
            api_version = int(out.strip())
        except ValueError:
            pass
    return {
        "available": True,
        "callable": code == 0 and api_version == EXPECTED_KVM_API_VERSION,
        "api_version": api_version,
        "exit_code": code,
        "error": err[:1000] if err else None,
    }


def _classify(
    *,
    linux_x64: bool,
    digest_ok: bool,
    version_ok: bool,
    kvm_present: bool,
    kvm_sudo_ok: bool,
) -> tuple[str, str]:
    if not linux_x64:
        return "SETUP_REQUIRED", "F0 currently targets Linux x86_64 only"
    if not digest_ok:
        return "ORACLE_FAILURE", "downloaded Firecracker archive digest did not match manifest"
    if not version_ok:
        return "ORACLE_FAILURE", "Firecracker binary version oracle did not match manifest"
    if not kvm_present:
        return "SETUP_REQUIRED", "/dev/kvm is not present on this execution venue"
    if not kvm_sudo_ok:
        return "ENVIRONMENT_FAILURE", "KVM is present but the qualified sudo API boundary is unavailable"
    return "SUPPORTED", "pinned Firecracker binary and current KVM preflight satisfied F0"


def run_probe(label: str, manifest_path: pathlib.Path) -> dict:
    timer = LifecycleTimer()
    manifest = json.loads(manifest_path.read_text())
    expected_arch = manifest["architecture"]
    expected_digest = manifest["archive_sha256"]
    expected_version = manifest["expected_version_fragment"]
    version = manifest["version"]

    runner_os = platform.system()
    runner_arch = platform.machine()
    linux_x64 = runner_os == "Linux" and runner_arch in {"x86_64", "amd64"}

    with timer.stage("kvm_user_preflight", "venue"):
        user_kvm = _kvm_user_probe()
    with timer.stage("kvm_sudo_preflight", "venue"):
        sudo_kvm = _kvm_sudo_probe() if user_kvm["present"] else {
        "available": bool(shutil.which("sudo")),
        "callable": False,
        "api_version": None,
        "error": "KVM absent; sudo KVM oracle not attempted",
        }

    digest_ok = False
    version_ok = False
    actual_digest = None
    version_output = None
    binary_path = None
    acquisition_error = None

    if linux_x64 and expected_arch == "x86_64":
        try:
            with tempfile.TemporaryDirectory(prefix="firecracker-f0-") as td:
                td_path = pathlib.Path(td)
                archive = td_path / "firecracker.tgz"
                extract_dir = td_path / "extract"
                extract_dir.mkdir()
                with timer.stage("vmm_download", "venue"):
                    _download(manifest["archive_url"], archive)
                with timer.stage("vmm_digest_verify", "portable"):
                    actual_digest = _sha256(archive)
                    digest_ok = actual_digest == expected_digest
                if digest_ok:
                    with timer.stage("vmm_extract", "portable"):
                        _safe_extract(archive, extract_dir)
                        binary = _find_firecracker_binary(extract_dir, version, expected_arch)
                        binary.chmod(binary.stat().st_mode | 0o111)
                        binary_path = str(binary.relative_to(extract_dir))
                    with timer.stage("vmm_version_oracle", "portable"):
                        code, out, err = _run([str(binary), "--version"], timeout=15)
                        version_output = (out or err)[:2000] or None
                        version_ok = code == 0 and bool(version_output) and expected_version in version_output
        except Exception as exc:
            acquisition_error = f"{type(exc).__name__}: {exc}"

    classification, reason = _classify(
        linux_x64=linux_x64,
        digest_ok=digest_ok,
        version_ok=version_ok,
        kvm_present=bool(user_kvm["present"]),
        kvm_sudo_ok=bool(sudo_kvm["callable"]),
    )
    if acquisition_error and classification in {"ORACLE_FAILURE", "SUPPORTED"}:
        classification = "ENVIRONMENT_FAILURE"
        reason = f"Firecracker acquisition/execution failed before F0 completion: {acquisition_error}"

    return {
        "schema": RECEIPT_SCHEMA,
        "probe_version": PROBE_VERSION,
        "authority": "SemperSupra/agent-dispatch-private#280",
        "requested_label": label,
        "result": {
            "classification": classification,
            "reason": reason,
            "guest_boot_claimed": False,
        },
        "portable": {
            "vmm": {
                "name": manifest["name"],
                "version": version,
                "architecture": expected_arch,
                "release_url": manifest["release_url"],
                "archive_url": manifest["archive_url"],
                "expected_archive_sha256": expected_digest,
                "actual_archive_sha256": actual_digest,
                "archive_digest_verified": digest_ok,
                "binary_path_in_archive": binary_path,
                "expected_version_fragment": expected_version,
                "version_output": version_output,
                "version_oracle_satisfied": version_ok,
                "acquisition_error": acquisition_error,
            },
            "required_kvm_api_version": EXPECTED_KVM_API_VERSION,
        },
        "venue_adapter": {
            "venue": "github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "other",
            "runner": {
                "os": runner_os,
                "architecture": runner_arch,
                "image_os": os.environ.get("ImageOS"),
                "image_version": os.environ.get("ImageVersion"),
                "runner_name": os.environ.get("RUNNER_NAME"),
            },
            "kvm": {
                "user": user_kvm,
                "sudo": sudo_kvm,
                "sudo_boundary_is_venue_specific": True,
            },
        },
        "lifecycle_timing": timer.receipt(),
        "sovereign_transfer": {
            "portable_contract_depends_on_github_actions": False,
            "gha_specific_facts": [
                "runner image identity",
                "observed /dev/kvm exposure",
                "existing passwordless-sudo boundary",
                "temporary workspace and artifact transport",
            ],
            "next_transfer_question": (
                "Would the same pinned VMM identity and later guest/capsule artifacts work "
                "unchanged on an ordinary KVM-capable sovereign Linux host?"
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=pathlib.Path("experiments/firecracker/firecracker-v1.17.0-x86_64.json"),
    )
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()

    try:
        receipt = run_probe(args.label, args.manifest)
    except Exception as exc:
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "probe_version": PROBE_VERSION,
            "authority": "SemperSupra/agent-dispatch-private#280",
            "requested_label": args.label,
            "result": {
                "classification": "HARNESS_FAILURE",
                "reason": f"{type(exc).__name__}: {exc}",
                "guest_boot_claimed": False,
            },
        }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["result"]["classification"] == "SUPPORTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
