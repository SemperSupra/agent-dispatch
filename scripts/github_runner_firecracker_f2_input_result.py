#!/usr/bin/env python3
"""Firecracker F2 bounded input -> guest computation -> result oracle.

A host-provided bounded file is embedded into the deterministic initramfs.
The networkless/diskless guest reads it, computes a deterministic FNV-1a-64
result, emits a structured serial receipt, and shuts down. This is a transport
and reconciliation proof, not yet a general work-capsule abstraction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import shutil
import stat
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
from firecracker_lifecycle_timing import LifecycleTimer

RECEIPT_SCHEMA = "firecracker-f2-input-result-receipt/v1"
PROBE_VERSION = "firecracker-f2-input-result/1"
VMM_MANIFEST = pathlib.Path("experiments/firecracker/firecracker-v1.17.0-x86_64.json")
KERNEL_MANIFEST = pathlib.Path("experiments/firecracker/guest-kernel-6.18.48-x86_64.json")
INIT_SOURCE = pathlib.Path("experiments/firecracker/guest/f2-init-x86_64.c")
DEFAULT_INPUT = pathlib.Path("experiments/firecracker/guest/f2-input.txt")
MAX_INPUT_BYTES = 4096


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fnv1a64(data: bytes) -> int:
    value = 14695981039346656037
    for byte in data:
        value ^= byte
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def _expected_marker(data: bytes) -> str:
    return f"FIRECRACKER_F2_RESULT bytes={len(data)} fnv1a64={_fnv1a64(data):016x}"


def _build_initramfs(
    init_binary: pathlib.Path,
    input_bytes: bytes,
    output: pathlib.Path,
) -> None:
    payload = b"".join(
        [
            f1._newc_entry(".", mode=stat.S_IFDIR | 0o755, ino=1, nlink=2),
            f1._newc_entry("dev", mode=stat.S_IFDIR | 0o755, ino=2, nlink=2),
            f1._newc_entry(
                "dev/console",
                mode=stat.S_IFCHR | 0o600,
                ino=3,
                rdevmajor=5,
                rdevminor=1,
            ),
            f1._newc_entry("work", mode=stat.S_IFDIR | 0o555, ino=4, nlink=2),
            f1._newc_entry(
                "work/input.txt",
                mode=stat.S_IFREG | 0o444,
                data=input_bytes,
                ino=5,
            ),
            f1._newc_entry(
                "init",
                mode=stat.S_IFREG | 0o755,
                data=init_binary.read_bytes(),
                ino=6,
            ),
            f1._newc_entry("TRAILER!!!", mode=0, ino=7),
        ]
    )
    output.write_bytes(payload)


def _run_firecracker(
    binary: pathlib.Path,
    config: pathlib.Path,
    expected_marker: str,
) -> dict:
    sudo = shutil.which("sudo")
    timeout = shutil.which("timeout")
    if not sudo:
        return {"ok": False, "classification": "SETUP_REQUIRED", "reason": "sudo not found"}
    if not timeout:
        return {"ok": False, "classification": "SETUP_REQUIRED", "reason": "timeout not found"}

    binary = binary.resolve()
    config = config.resolve()
    config_payload = json.loads(config.read_text())
    required_paths = {
        "firecracker": binary,
        "config": config,
        "kernel": pathlib.Path(config_payload["boot-source"]["kernel_image_path"]).resolve(),
        "initrd": pathlib.Path(config_payload["boot-source"]["initrd_path"]).resolve(),
    }
    sudo_readable = {}
    for name, path in required_paths.items():
        code, _, err = f0._run([sudo, "-n", "test", "-r", str(path)], timeout=10)
        sudo_readable[name] = {
            "path": str(path),
            "readable": code == 0,
            "exit_code": code,
            "error": err[:1000] if err else None,
        }
    if not all(item["readable"] for item in sudo_readable.values()):
        return {
            "ok": False,
            "classification": "HARNESS_FAILURE",
            "reason": "sudo launch context cannot read all F2 input paths",
            "sudo_readable": sudo_readable,
        }

    command = [
        sudo,
        "-n",
        timeout,
        "--signal=TERM",
        "--kill-after=2s",
        "20s",
        str(binary),
        "--no-api",
        "--config-file",
        str(config),
    ]
    code, out, err = f0._run(command, timeout=25)
    combined = "\n".join(x for x in [out, err] if x)
    marker_seen = expected_marker in combined
    guest_error_seen = "FIRECRACKER_F2_ERROR=" in combined
    clean_exit = code == 0 and "Firecracker exiting successfully" in combined
    preboot_harness_failure = (
        "Unable to open or read from the configuration file" in combined
        or ("No such file or directory" in combined and not marker_seen)
        or "Arguments parsing error" in combined
        or "ParseArguments(" in combined
    )
    classification = (
        "SUPPORTED"
        if marker_seen and clean_exit and not guest_error_seen
        else "HARNESS_FAILURE"
        if preboot_harness_failure
        else "ORACLE_FAILURE"
    )
    return {
        "ok": classification == "SUPPORTED",
        "classification": classification,
        "reason": (
            "guest consumed bounded input, emitted expected result, and Firecracker exited cleanly"
            if classification == "SUPPORTED"
            else "pre-boot harness handoff failed before F2 guest oracle"
            if classification == "HARNESS_FAILURE"
            else "expected F2 result and clean VMM exit were not both observed"
        ),
        "exit_code": code,
        "expected_marker": expected_marker,
        "result_marker_observed": marker_seen,
        "guest_error_observed": guest_error_seen,
        "clean_vmm_exit_observed": clean_exit,
        "sudo_readable": sudo_readable,
        "output_tail": combined[-7000:],
    }


def run_probe(label: str, input_path: pathlib.Path) -> dict:
    timer = LifecycleTimer()
    runner_os = platform.system()
    runner_arch = platform.machine()
    if runner_os != "Linux" or runner_arch not in {"x86_64", "amd64"}:
        return _failure(label, "SETUP_REQUIRED", "F2 currently targets Linux x86_64")

    input_bytes = input_path.read_bytes()
    if not input_bytes or len(input_bytes) > MAX_INPUT_BYTES:
        return _failure(
            label,
            "SKIPPED_GUARDRAIL",
            f"input must contain 1..{MAX_INPUT_BYTES} bytes",
        )

    expected_marker = _expected_marker(input_bytes)
    vmm_manifest = f1._load_json(VMM_MANIFEST)
    kernel_manifest = f1._load_json(KERNEL_MANIFEST)

    with tempfile.TemporaryDirectory(prefix="firecracker-f2-") as td:
        work = pathlib.Path(td)
        vmm_archive = work / "firecracker.tgz"
        vmm_extract = work / "vmm"
        vmm_extract.mkdir()
        kernel = work / "vmlinux"
        init_binary = work / "init"
        initrd = work / "initrd.cpio"
        config_path = work / "vm-config.json"

        with timer.stage("vmm_download_and_verify", "venue"):
            vmm_verify = f1._download_and_verify(
                vmm_manifest["archive_url"], vmm_manifest["archive_sha256"], vmm_archive
            )
        if not vmm_verify["verified"]:
            return _failure(label, "ORACLE_FAILURE", "Firecracker archive digest mismatch")

        with timer.stage("vmm_extract", "portable"):
            f0._safe_extract(vmm_archive, vmm_extract)
            firecracker = f1._find_firecracker(
                vmm_extract, vmm_manifest["version"], vmm_manifest["architecture"]
            )

        with timer.stage("kernel_download_and_verify", "venue"):
            kernel_verify = f1._download_and_verify(
                kernel_manifest["kernel_url"], kernel_manifest["kernel_sha256"], kernel
            )
        if not kernel_verify["verified"]:
            return _failure(label, "ORACLE_FAILURE", "guest kernel digest mismatch")

        with timer.stage("guest_init_compile", "portable"):
            compile_result = f1._compile_init(INIT_SOURCE, init_binary)
        if not compile_result["ok"]:
            return _failure(
                label,
                "SETUP_REQUIRED" if compile_result["reason"] == "gcc not found" else "HARNESS_FAILURE",
                "F2 guest init did not compile",
            )

        with timer.stage("initramfs_build", "portable"):
            _build_initramfs(init_binary, input_bytes, initrd)
        with timer.stage("vm_config_build", "portable"):
            config = f1._build_config(kernel, initrd, config_path)
        with timer.stage("firecracker_guest_lifecycle", "portable"):
            execution = _run_firecracker(firecracker, config_path, expected_marker)

        return {
            "schema": RECEIPT_SCHEMA,
            "probe_version": PROBE_VERSION,
            "authority": "SemperSupra/agent-dispatch-private#280",
            "requested_label": label,
            "result": {
                "classification": execution["classification"],
                "reason": execution["reason"],
                "guest_execution_attempted": True,
                "input_result_oracle_satisfied": execution["ok"],
            },
            "portable": {
                "input": {
                    "source": str(input_path),
                    "size_bytes": len(input_bytes),
                    "sha256": _sha256_bytes(input_bytes),
                    "transport": "deterministic-initramfs-member:/work/input.txt",
                    "host_source_mutable_by_guest": False,
                },
                "computation": {
                    "algorithm": "FNV-1a-64",
                    "expected_fnv1a64": f"{_fnv1a64(input_bytes):016x}",
                    "expected_result_marker": expected_marker,
                },
                "guest_init": {
                    "source": str(INIT_SOURCE),
                    "source_sha256": f1._sha256(INIT_SOURCE),
                    "binary_sha256": f1._sha256(init_binary),
                    "initrd_sha256": f1._sha256(initrd),
                },
                "vmm": {
                    "version": vmm_manifest["version"],
                    "archive_sha256": vmm_verify["actual_sha256"],
                },
                "kernel": {
                    "version": kernel_manifest["kernel_version"],
                    "sha256": kernel_verify["actual_sha256"],
                },
                "machine": {
                    "vcpu_count": config["machine-config"]["vcpu_count"],
                    "mem_size_mib": config["machine-config"]["mem_size_mib"],
                    "drives": 0,
                    "network_interfaces": 0,
                },
                "result_transport": "serial-console",
            },
            "venue_adapter": {
                "venue": "github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "other",
                "runner": {
                    "image_os": os.environ.get("ImageOS"),
                    "image_version": os.environ.get("ImageVersion"),
                },
                "kvm_boundary": "existing passwordless sudo; venue-specific",
            },
            "execution_oracle": execution,
            "lifecycle_timing": timer.receipt(),
            "sovereign_transfer": {
                "portable_contract_depends_on_github_actions": False,
                "transfer_test": (
                    "Rebuild the same initramfs from the same input/init sources and run the "
                    "same pinned VMM/kernel/config on a sovereign KVM-capable Linux host."
                ),
            },
        }


def _failure(label: str, classification: str, reason: str) -> dict:
    return {
        "schema": RECEIPT_SCHEMA,
        "probe_version": PROBE_VERSION,
        "authority": "SemperSupra/agent-dispatch-private#280",
        "requested_label": label,
        "result": {
            "classification": classification,
            "reason": reason,
            "guest_execution_attempted": False,
            "input_result_oracle_satisfied": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--input", type=pathlib.Path, default=DEFAULT_INPUT)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = run_probe(args.label, args.input)
    except Exception as exc:
        receipt = _failure(args.label, "HARNESS_FAILURE", f"{type(exc).__name__}: {exc}")
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["result"]["classification"] == "SUPPORTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
