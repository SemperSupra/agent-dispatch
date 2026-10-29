#!/usr/bin/env python3
"""Firecracker F1 minimal guest boot oracle.

Boots one pinned x86_64 Linux kernel with a tiny repo-built initramfs. No drives,
network interfaces, package manager, SSH, snapshots, or private inputs are used.
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
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
from firecracker_lifecycle_timing import LifecycleTimer

RECEIPT_SCHEMA = "firecracker-f1-boot-receipt/v1"
PROBE_VERSION = "firecracker-f1-boot/1"
NONCE = "FIRECRACKER_F1_GUEST_NONCE=fcf1c0de"
FIRECRACKER_MANIFEST = pathlib.Path(
    "experiments/firecracker/firecracker-v1.17.0-x86_64.json"
)
KERNEL_MANIFEST = pathlib.Path(
    "experiments/firecracker/guest-kernel-6.18.48-x86_64.json"
)
INIT_SOURCE = pathlib.Path("experiments/firecracker/guest/f1-init-x86_64.c")


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _pad4(data: bytes) -> bytes:
    return data + (b"\0" * ((4 - (len(data) % 4)) % 4))


def _newc_entry(
    name: str,
    *,
    mode: int,
    data: bytes = b"",
    ino: int,
    nlink: int = 1,
    rdevmajor: int = 0,
    rdevminor: int = 0,
) -> bytes:
    name_bytes = name.encode("utf-8") + b"\0"
    fields = [
        ino,
        mode,
        0,  # uid
        0,  # gid
        nlink,
        0,  # mtime
        len(data),
        0,  # devmajor
        0,  # devminor
        rdevmajor,
        rdevminor,
        len(name_bytes),
        0,  # check
    ]
    header = b"070701" + b"".join(f"{value:08x}".encode("ascii") for value in fields)
    if len(header) != 110:
        raise AssertionError("invalid newc header length")
    record = _pad4(header + name_bytes)
    return record + _pad4(data)


def _build_initramfs(init_binary: pathlib.Path, output: pathlib.Path) -> None:
    init_bytes = init_binary.read_bytes()
    payload = b"".join(
        [
            _newc_entry(".", mode=stat.S_IFDIR | 0o755, ino=1, nlink=2),
            _newc_entry("dev", mode=stat.S_IFDIR | 0o755, ino=2, nlink=2),
            _newc_entry(
                "dev/console",
                mode=stat.S_IFCHR | 0o600,
                ino=3,
                rdevmajor=5,
                rdevminor=1,
            ),
            _newc_entry("init", mode=stat.S_IFREG | 0o755, data=init_bytes, ino=4),
            _newc_entry("TRAILER!!!", mode=0, ino=5),
        ]
    )
    output.write_bytes(payload)


def _compile_init(source: pathlib.Path, output: pathlib.Path) -> dict:
    gcc = shutil.which("gcc")
    if not gcc:
        return {"ok": False, "reason": "gcc not found", "command": None}
    command = [
        gcc,
        "-Os",
        "-ffreestanding",
        "-fno-pie",
        "-no-pie",
        "-fno-stack-protector",
        "-nostdlib",
        "-static",
        "-s",
        "-Wl,--build-id=none",
        "-Wl,-e,_start",
        "-o",
        str(output),
        str(source),
    ]
    code, out, err = f0._run(command, timeout=30)
    return {
        "ok": code == 0 and output.exists(),
        "reason": None if code == 0 else (err or out or f"gcc exit {code}")[:2000],
        "command": command,
        "exit_code": code,
    }


def _load_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def _download_and_verify(url: str, expected_sha256: str, destination: pathlib.Path) -> dict:
    f0._download(url, destination)
    actual = _sha256(destination)
    return {
        "expected_sha256": expected_sha256,
        "actual_sha256": actual,
        "verified": actual == expected_sha256,
        "size_bytes": destination.stat().st_size,
    }


def _find_firecracker(root: pathlib.Path, version: str, arch: str) -> pathlib.Path:
    binary = f0._find_firecracker_binary(root, version, arch)
    binary.chmod(binary.stat().st_mode | 0o111)
    return binary


def _build_config(kernel: pathlib.Path, initrd: pathlib.Path, output: pathlib.Path) -> dict:
    config = {
        "boot-source": {
            "kernel_image_path": str(kernel.resolve()),
            "initrd_path": str(initrd.resolve()),
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
        },
        "drives": [],
        "machine-config": {
            "vcpu_count": 1,
            "mem_size_mib": 128,
            "smt": False,
            "track_dirty_pages": False,
            "huge_pages": "None",
        },
        "network-interfaces": [],
    }
    output.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")
    return config


def _run_firecracker(binary: pathlib.Path, config: pathlib.Path) -> dict:
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
            "reason": "sudo launch context cannot read all F1 input paths",
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
    nonce_seen = NONCE in combined
    clean_exit = code == 0 and "Firecracker exiting successfully" in combined
    preboot_harness_failure = (
        "Unable to open or read from the configuration file" in combined
        or ("No such file or directory" in combined and not nonce_seen)
        or "Arguments parsing error" in combined
        or "ParseArguments(" in combined
    )
    classification = (
        "SUPPORTED"
        if nonce_seen and clean_exit
        else "HARNESS_FAILURE"
        if preboot_harness_failure
        else "ORACLE_FAILURE"
    )
    return {
        "ok": nonce_seen and clean_exit,
        "classification": classification,
        "reason": (
            "guest serial nonce observed and Firecracker exited cleanly"
            if nonce_seen and clean_exit
            else "pre-boot harness/argument handoff failed before a guest oracle"
            if preboot_harness_failure
            else "guest serial nonce and clean VMM exit were not both observed"
        ),
        "exit_code": code,
        "serial_nonce_observed": nonce_seen,
        "clean_vmm_exit_observed": clean_exit,
        "sudo_readable": sudo_readable,
        "output_tail": combined[-6000:],
        "command_shape": "sudo -n timeout 20s firecracker --no-api --config-file <resolved-config>",
    }


def run_probe(label: str) -> dict:
    timer = LifecycleTimer()
    runner_os = platform.system()
    runner_arch = platform.machine()
    if runner_os != "Linux" or runner_arch not in {"x86_64", "amd64"}:
        return {
            "schema": RECEIPT_SCHEMA,
            "probe_version": PROBE_VERSION,
            "authority": "SemperSupra/agent-dispatch-private#280",
            "requested_label": label,
            "result": {
                "classification": "SETUP_REQUIRED",
                "reason": "F1 boot currently targets Linux x86_64",
                "guest_boot_attempted": False,
                "guest_boot_oracle_satisfied": False,
            },
        }

    vmm_manifest = _load_json(FIRECRACKER_MANIFEST)
    kernel_manifest = _load_json(KERNEL_MANIFEST)

    with tempfile.TemporaryDirectory(prefix="firecracker-f1-") as td:
        work = pathlib.Path(td)
        vmm_archive = work / "firecracker.tgz"
        vmm_extract = work / "vmm"
        vmm_extract.mkdir()
        kernel = work / "vmlinux"
        init_binary = work / "init"
        initrd = work / "initrd.cpio"
        config_path = work / "vm-config.json"

        with timer.stage("vmm_download_and_verify", "venue"):
            vmm_verify = _download_and_verify(
                vmm_manifest["archive_url"],
                vmm_manifest["archive_sha256"],
                vmm_archive,
            )
        if not vmm_verify["verified"]:
            return _failure(label, "ORACLE_FAILURE", "Firecracker archive digest mismatch", vmm_verify)

        with timer.stage("vmm_extract", "portable"):
            f0._safe_extract(vmm_archive, vmm_extract)
            firecracker = _find_firecracker(
                vmm_extract, vmm_manifest["version"], vmm_manifest["architecture"]
            )

        with timer.stage("kernel_download_and_verify", "venue"):
            kernel_verify = _download_and_verify(
                kernel_manifest["kernel_url"],
                kernel_manifest["kernel_sha256"],
                kernel,
            )
        if not kernel_verify["verified"]:
            return _failure(label, "ORACLE_FAILURE", "guest kernel digest mismatch", kernel_verify)

        with timer.stage("guest_init_compile", "portable"):
            compile_result = _compile_init(INIT_SOURCE, init_binary)
        if not compile_result["ok"]:
            return _failure(
                label,
                "SETUP_REQUIRED" if compile_result["reason"] == "gcc not found" else "HARNESS_FAILURE",
                "minimal guest init did not compile",
                compile_result,
            )

        with timer.stage("initramfs_build", "portable"):
            _build_initramfs(init_binary, initrd)
        with timer.stage("vm_config_build", "portable"):
            config = _build_config(kernel, initrd, config_path)
        with timer.stage("firecracker_guest_lifecycle", "portable"):
            boot = _run_firecracker(firecracker, config_path)

        return {
            "schema": RECEIPT_SCHEMA,
            "probe_version": PROBE_VERSION,
            "authority": "SemperSupra/agent-dispatch-private#280",
            "requested_label": label,
            "result": {
                "classification": boot["classification"],
                "reason": boot["reason"],
                "guest_boot_attempted": True,
                "guest_boot_oracle_satisfied": boot["ok"],
            },
            "portable": {
                "vmm": {
                    "name": vmm_manifest["name"],
                    "version": vmm_manifest["version"],
                    "archive_url": vmm_manifest["archive_url"],
                    **vmm_verify,
                },
                "kernel": {
                    "version": kernel_manifest["kernel_version"],
                    "url": kernel_manifest["kernel_url"],
                    **kernel_verify,
                },
                "guest_init": {
                    "source": str(INIT_SOURCE),
                    "source_sha256": _sha256(INIT_SOURCE),
                    "binary_sha256": _sha256(init_binary),
                    "initrd_sha256": _sha256(initrd),
                    "serial_nonce": NONCE,
                },
                "machine": {
                    "vcpu_count": config["machine-config"]["vcpu_count"],
                    "mem_size_mib": config["machine-config"]["mem_size_mib"],
                    "drives": 0,
                    "network_interfaces": 0,
                    "boot_args": config["boot-source"]["boot_args"],
                },
            },
            "venue_adapter": {
                "venue": "github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "other",
                "runner": {
                    "os": runner_os,
                    "architecture": runner_arch,
                    "image_os": os.environ.get("ImageOS"),
                    "image_version": os.environ.get("ImageVersion"),
                },
                "kvm_boundary": "existing passwordless sudo; not part of portable guest contract",
            },
            "boot_oracle": boot,
            "lifecycle_timing": timer.receipt(),
            "sovereign_transfer": {
                "portable_contract_depends_on_github_actions": False,
                "portable_artifacts": [
                    "exact Firecracker release identity",
                    "exact guest kernel identity",
                    "guest init source/build recipe",
                    "initramfs format",
                    "machine configuration semantics",
                    "serial nonce oracle",
                ],
                "gha_specific_adapter": [
                    "runner image selection",
                    "passwordless sudo crossing for /dev/kvm",
                    "temporary workspace",
                    "workflow artifact transport",
                ],
            },
        }


def _failure(label: str, classification: str, reason: str, evidence: dict) -> dict:
    return {
        "schema": RECEIPT_SCHEMA,
        "probe_version": PROBE_VERSION,
        "authority": "SemperSupra/agent-dispatch-private#280",
        "requested_label": label,
        "result": {
            "classification": classification,
            "reason": reason,
            "guest_boot_attempted": False,
            "guest_boot_oracle_satisfied": False,
        },
        "evidence": evidence,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)

    try:
        receipt = run_probe(args.label)
    except Exception as exc:
        receipt = _failure(
            args.label,
            "HARNESS_FAILURE",
            f"{type(exc).__name__}: {exc}",
            {},
        )

    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["result"]["classification"] == "SUPPORTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
