#!/usr/bin/env python3
"""Bounded Firecracker RDTE probes for public GitHub-hosted runners.

GHA is the disposable learning/proving substrate. Operational readiness for
private workloads is intentionally withheld until the same portable contract is
reproduced on sovereign/local resources.
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

FIRECRACKER_VERSION = "1.17.0"
FIRECRACKER_ARCHIVE = f"firecracker-v{FIRECRACKER_VERSION}-x86_64.tgz"
FIRECRACKER_URL = (
    "https://github.com/firecracker-microvm/firecracker/releases/download/"
    f"v{FIRECRACKER_VERSION}/{FIRECRACKER_ARCHIVE}"
)
FIRECRACKER_SHA256 = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"

# Resolved by a discovery-only rep on 2026-09-23 from Firecracker's official CI
# demonstration-artifact bucket. F1 never follows a floating "latest" pointer.
KERNEL_OBJECT_KEY = (
    "firecracker-ci/20260923-6f82ac4cf331-0/x86_64/vmlinux-6.18.48"
)
KERNEL_URL = f"https://s3.amazonaws.com/spec.ccfc.min/{KERNEL_OBJECT_KEY}"
KERNEL_SHA256 = "9204218e8bcca6ac23848d74f45df2eb19d7f31e8277840a7d145a0df8b078d2"

F1_NONCE = "FC_RDTE_F1_NONCE=c0def11e"
F2_INPUT = "FC_RDTE_F2_INPUT=portable-block-contract"
F2_RESULT = "FC_RDTE_F2_RESULT=portable-block-contract"
F2_NONCE = "FC_RDTE_F2_NONCE=c0def22e"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(argv: list[str], timeout: int = 20, keep: int = 4096) -> dict[str, Any]:
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
            "stdout": proc.stdout[-keep:].strip(),
            "stderr": proc.stderr[-keep:].strip(),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {
            "argv": argv,
            "timeout": True,
            "stdout": stdout[-keep:].strip(),
            "stderr": stderr[-keep:].strip(),
        }
    except Exception as exc:
        return {"argv": argv, "error": f"{type(exc).__name__}: {exc}"}


def download_verified(url: str, expected_sha256: str, destination: Path) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:
        with destination.open("wb") as handle:
            shutil.copyfileobj(response, handle)
    observed = sha256_file(destination)
    if observed != expected_sha256:
        raise ValueError(
            f"SHA-256 mismatch for {url}: expected {expected_sha256}, observed {observed}"
        )
    return observed


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


def materialize_firecracker(temp: Path) -> tuple[Path, str, dict[str, Any]]:
    archive = temp / FIRECRACKER_ARCHIVE
    observed = download_verified(FIRECRACKER_URL, FIRECRACKER_SHA256, archive)
    binary = safe_extract_firecracker(archive, temp / "extract")
    version = command([str(binary), "--version"])
    identity = (version.get("stdout") or "") + "\n" + (version.get("stderr") or "")
    if version.get("returncode") != 0 or f"v{FIRECRACKER_VERSION}" not in identity:
        raise RuntimeError(f"Firecracker version oracle failed: {version}")
    return binary, observed, version


def _pad4(data: bytearray) -> None:
    while len(data) % 4:
        data.append(0)


def build_newc_single_file(name: str, payload: bytes, mode: int = 0o100755) -> bytes:
    """Build a deterministic newc initramfs containing one regular file."""
    out = bytearray()

    def add(entry_name: str, content: bytes, entry_mode: int, ino: int) -> None:
        name_bytes = entry_name.encode("utf-8") + b"\0"
        fields = [
            ino,
            entry_mode,
            0,  # uid
            0,  # gid
            1,  # nlink
            0,  # mtime
            len(content),
            0, 0, 0, 0,
            len(name_bytes),
            0,
        ]
        header = ("070701" + "".join(f"{field:08x}" for field in fields)).encode("ascii")
        if len(header) != 110:
            raise AssertionError("invalid newc header length")
        out.extend(header)
        out.extend(name_bytes)
        _pad4(out)
        out.extend(content)
        _pad4(out)

    add(name, payload, mode, 1)
    add("TRAILER!!!", b"", 0, 2)
    return bytes(out)


def compile_f1_init(temp: Path) -> tuple[Path, dict[str, Any]]:
    source = temp / "init.c"
    binary = temp / "init"
    source.write_text(
        r'''#include <unistd.h>
#include <sys/reboot.h>
int main(void) {
    const char msg[] = "FC_RDTE_F1_NONCE=c0def11e\n";
    (void)write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    sync();
    reboot(RB_AUTOBOOT);
    _exit(111);
}
'''
    )
    build = command(["cc", "-static", "-Os", "-s", "-o", str(binary), str(source)], timeout=30)
    if build.get("returncode") != 0 or not binary.exists():
        raise RuntimeError(f"static guest init build failed: {build}")

    initrd = temp / "initrd.cpio"
    initrd.write_bytes(build_newc_single_file("init", binary.read_bytes()))
    return initrd, build


def compile_f2_init(temp: Path) -> tuple[Path, dict[str, Any]]:
    source = temp / "init-f2.c"
    binary = temp / "init-f2"
    source.write_text(
        r'''#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(const char *msg) {
    dprintf(STDERR_FILENO, "FC_RDTE_F2_ERROR=%s\n", msg);
    sync();
    reboot(RB_AUTOBOOT);
    _exit(112);
}

int main(void) {
    char buf[256] = {0};
    const char expected[] = "FC_RDTE_F2_INPUT=portable-block-contract\n";
    const char result[] = "FC_RDTE_F2_RESULT=portable-block-contract\n";
    const char nonce[] = "FC_RDTE_F2_NONCE=c0def22e\n";

    mkdir("/dev", 0755);
    if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) != 0) return fail("mount-devtmpfs");
    mkdir("/input", 0755);
    mkdir("/output", 0755);
    if (mount("/dev/vda", "/input", "ext4", MS_RDONLY, NULL) != 0) return fail("mount-input");
    if (mount("/dev/vdb", "/output", "ext4", 0, NULL) != 0) return fail("mount-output");

    int in = open("/input/input.txt", O_RDONLY);
    if (in < 0) return fail("open-input");
    ssize_t n = read(in, buf, sizeof(buf) - 1);
    close(in);
    if (n < 0 || strcmp(buf, expected) != 0) return fail("input-mismatch");

    int out = open("/output/result.txt", O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (out < 0) return fail("open-output");
    if (write(out, result, sizeof(result) - 1) != (ssize_t)(sizeof(result) - 1)) return fail("write-output");
    fsync(out);
    close(out);
    sync();
    (void)write(STDOUT_FILENO, nonce, sizeof(nonce) - 1);
    reboot(RB_AUTOBOOT);
    _exit(113);
}
'''
    )
    build = command(["cc", "-static", "-Os", "-s", "-o", str(binary), str(source)], timeout=30)
    if build.get("returncode") != 0 or not binary.exists():
        raise RuntimeError(f"static F2 guest init build failed: {build}")

    initrd = temp / "initrd-f2.cpio"
    initrd.write_bytes(build_newc_single_file("init", binary.read_bytes()))
    return initrd, build


def mk_ext4_image(path: Path, source_dir: Path, uuid: str) -> dict[str, Any]:
    path.write_bytes(b"")
    with path.open("r+b") as handle:
        handle.truncate(8 * 1024 * 1024)
    result = command(
        [
            "mkfs.ext4",
            "-q",
            "-F",
            "-U",
            uuid,
            "-d",
            str(source_dir),
            str(path),
        ],
        timeout=30,
    )
    if result.get("returncode") != 0:
        raise RuntimeError(f"mkfs.ext4 failed: {result}")
    result["sha256_after_format"] = sha256_file(path)
    return result


def f2_drive(drive_id: str, path: Path, read_only: bool) -> dict[str, Any]:
    return {
        "drive_id": drive_id,
        "partuuid": None,
        "is_root_device": False,
        "cache_type": "Unsafe",
        "is_read_only": read_only,
        "discard": False,
        "path_on_host": str(path),
        "io_engine": "Sync",
        "rate_limiter": None,
        "blk_size": 512,
        "topology": {
            "physical_block_exp": 0,
            "alignment_offset": 0,
            "min_io_size": 0,
            "opt_io_size": 128,
        },
        "socket": None,
    }


def make_receipt(rung: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "rung": rung,
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
            "guest_kernel": {
                "object_key": KERNEL_OBJECT_KEY if rung in {"F1", "F2"} else None,
                "url": KERNEL_URL if rung in {"F1", "F2"} else None,
                "sha256_expected": KERNEL_SHA256 if rung in {"F1", "F2"} else None,
                "sha256_observed": None,
            },
            "initrd": None,
            "io_contract": None,
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


def preflight(receipt: dict[str, Any]) -> int | None:
    receipt["gha_adapter_evidence"]["kvm"] = observe_kvm()
    if platform.machine() not in {"x86_64", "AMD64"}:
        receipt["result"] = "SKIPPED_GUARDRAIL"
        receipt["notes"].append("This experiment rung is pinned to x86_64 only.")
        return 0
    if not Path("/dev/kvm").exists():
        receipt["result"] = "ENVIRONMENT_FAILURE"
        receipt["notes"].append("/dev/kvm is absent; prerequisite drift from #223.")
        return 2
    sudo_test = receipt["gha_adapter_evidence"]["kvm"].get("sudo_rw_test", {})
    if sudo_test.get("returncode") != 0:
        receipt["result"] = "ENVIRONMENT_FAILURE"
        receipt["notes"].append("Existing passwordless-sudo KVM boundary is unavailable.")
        return 2
    return None


def run_f0(out: Path) -> int:
    receipt = make_receipt("F0")
    early = preflight(receipt)
    if early is not None:
        out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        return early

    with tempfile.TemporaryDirectory(prefix="fc-rdte-f0-") as td:
        try:
            _, observed, version = materialize_firecracker(Path(td))
        except Exception as exc:
            receipt["result"] = "ORACLE_FAILURE"
            receipt["notes"].append(f"F0 VMM oracle failed: {type(exc).__name__}: {exc}")
            out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            return 2

        receipt["portable_evidence"]["vmm"]["sha256_observed"] = observed
        receipt["portable_evidence"]["vmm"]["version_command"] = version

    receipt["result"] = "SUPPORTED"
    receipt["claims"]["firecracker_acquisition_callable"] = True
    receipt["notes"].append(
        "F0 proves pinned VMM acquisition/callability only; guest boot and sovereign readiness remain unproven."
    )
    out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0


def run_f1(out: Path) -> int:
    receipt = make_receipt("F1")
    early = preflight(receipt)
    if early is not None:
        out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        return early

    with tempfile.TemporaryDirectory(prefix="fc-rdte-f1-") as td:
        temp = Path(td)
        try:
            binary, fc_sha, version = materialize_firecracker(temp)
            receipt["portable_evidence"]["vmm"]["sha256_observed"] = fc_sha
            receipt["portable_evidence"]["vmm"]["version_command"] = version
            receipt["claims"]["firecracker_acquisition_callable"] = True

            kernel = temp / "vmlinux-6.18.48"
            kernel_sha = download_verified(KERNEL_URL, KERNEL_SHA256, kernel)
            receipt["portable_evidence"]["guest_kernel"]["sha256_observed"] = kernel_sha

            initrd, build = compile_f1_init(temp)
            receipt["portable_evidence"]["initrd"] = {
                "format": "newc",
                "contents": ["/init"],
                "build_command": build,
                "sha256": sha256_file(initrd),
            }

            config = temp / "vm.json"
            config.write_text(
                json.dumps(
                    {
                        "boot-source": {
                            "kernel_image_path": str(kernel),
                            "initrd_path": str(initrd),
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
                        "cpu-config": None,
                        "balloon": None,
                        "network-interfaces": [],
                        "vsock": None,
                        "logger": None,
                        "metrics": None,
                        "mmds-config": None,
                        "entropy": None,
                        "pmem": [],
                        "memory-hotplug": None,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )

            boot = command(
                ["sudo", "-n", str(binary), "--no-api", "--config-file", str(config)],
                timeout=20,
                keep=16384,
            )
            receipt["portable_evidence"]["guest_boot"] = {
                "expected_serial_nonce": F1_NONCE,
                "command": boot,
                "network_interfaces_configured": 0,
            }
            serial = (boot.get("stdout") or "") + "\n" + (boot.get("stderr") or "")
            if F1_NONCE not in serial:
                receipt["result"] = "ORACLE_FAILURE"
                receipt["notes"].append(
                    "Firecracker started but deterministic F1 serial nonce was not observed."
                )
                out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
                return 2

        except ValueError as exc:
            receipt["result"] = "ORACLE_FAILURE"
            receipt["notes"].append(f"Pinned artifact integrity oracle failed: {exc}")
            out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            return 2
        except Exception as exc:
            receipt["result"] = "HARNESS_FAILURE"
            receipt["notes"].append(f"F1 harness failed: {type(exc).__name__}: {exc}")
            out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            return 2

    receipt["result"] = "SUPPORTED"
    receipt["claims"]["firecracker_acquisition_callable"] = True
    receipt["claims"]["guest_boot_supported"] = True
    receipt["portable_evidence"]["network_policy"] = "NO_GUEST_NETWORK_INTERFACE_CONFIGURED"
    receipt["notes"].append(
        "F1 proves a pinned kernel + deterministic custom initrd can execute a serial nonce in a Firecracker guest. Workload/capsule and sovereign operational readiness remain unproven."
    )
    out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0



def run_f2(out: Path) -> int:
    receipt = make_receipt("F2")
    early = preflight(receipt)
    if early is not None:
        out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        return early

    with tempfile.TemporaryDirectory(prefix="fc-rdte-f2-") as td:
        temp = Path(td)
        try:
            binary, fc_sha, version = materialize_firecracker(temp)
            receipt["portable_evidence"]["vmm"]["sha256_observed"] = fc_sha
            receipt["portable_evidence"]["vmm"]["version_command"] = version
            receipt["claims"]["firecracker_acquisition_callable"] = True

            kernel = temp / "vmlinux-6.18.48"
            kernel_sha = download_verified(KERNEL_URL, KERNEL_SHA256, kernel)
            receipt["portable_evidence"]["guest_kernel"]["sha256_observed"] = kernel_sha

            initrd, build = compile_f2_init(temp)
            receipt["portable_evidence"]["initrd"] = {
                "format": "newc",
                "contents": ["/init"],
                "build_command": build,
                "sha256": sha256_file(initrd),
            }

            input_dir = temp / "input-dir"
            output_dir = temp / "output-dir"
            input_dir.mkdir()
            output_dir.mkdir()
            (input_dir / "input.txt").write_text(F2_INPUT + "\n")
            input_image = temp / "input.ext4"
            output_image = temp / "output.ext4"
            input_build = mk_ext4_image(
                input_image,
                input_dir,
                "11111111-1111-1111-1111-111111111111",
            )
            output_build = mk_ext4_image(
                output_image,
                output_dir,
                "22222222-2222-2222-2222-222222222222",
            )

            config = temp / "vm-f2.json"
            config.write_text(
                json.dumps(
                    {
                        "boot-source": {
                            "kernel_image_path": str(kernel),
                            "initrd_path": str(initrd),
                            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
                        },
                        "drives": [
                            f2_drive("input", input_image, True),
                            f2_drive("output", output_image, False),
                        ],
                        "machine-config": {
                            "vcpu_count": 1,
                            "mem_size_mib": 128,
                            "smt": False,
                            "track_dirty_pages": False,
                            "huge_pages": "None",
                        },
                        "cpu-config": None,
                        "balloon": None,
                        "network-interfaces": [],
                        "vsock": None,
                        "logger": None,
                        "metrics": None,
                        "mmds-config": None,
                        "entropy": None,
                        "pmem": [],
                        "memory-hotplug": None,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )

            boot = command(
                ["sudo", "-n", str(binary), "--no-api", "--config-file", str(config)],
                timeout=20,
                keep=16384,
            )
            serial = (boot.get("stdout") or "") + "\n" + (boot.get("stderr") or "")
            readback = command(
                ["debugfs", "-R", "cat /result.txt", str(output_image)],
                timeout=10,
                keep=4096,
            )
            observed_result = readback.get("stdout", "").strip()

            receipt["portable_evidence"]["guest_boot"] = {
                "expected_serial_nonce": F2_NONCE,
                "command": boot,
                "network_interfaces_configured": 0,
            }
            receipt["portable_evidence"]["io_contract"] = {
                "input": {
                    "format": "ext4",
                    "mount_intent": "read-only",
                    "path": "/input/input.txt",
                    "value": F2_INPUT,
                    "image_sha256": input_build["sha256_after_format"],
                },
                "output": {
                    "format": "ext4",
                    "mount_intent": "read-write",
                    "path": "/output/result.txt",
                    "expected": F2_RESULT,
                    "observed": observed_result,
                    "readback_command": readback,
                    "image_sha256_after_guest": sha256_file(output_image),
                },
            }

            if F2_NONCE not in serial or observed_result != F2_RESULT:
                receipt["result"] = "ORACLE_FAILURE"
                receipt["notes"].append(
                    "F2 boot/input/output oracle did not satisfy both serial and independent result-readback checks."
                )
                out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
                return 2

        except ValueError as exc:
            receipt["result"] = "ORACLE_FAILURE"
            receipt["notes"].append(f"Pinned artifact integrity oracle failed: {exc}")
            out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            return 2
        except Exception as exc:
            receipt["result"] = "HARNESS_FAILURE"
            receipt["notes"].append(f"F2 harness failed: {type(exc).__name__}: {exc}")
            out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            return 2

    receipt["result"] = "SUPPORTED"
    receipt["claims"]["guest_boot_supported"] = True
    receipt["portable_evidence"]["network_policy"] = "NO_GUEST_NETWORK_INTERFACE_CONFIGURED"
    receipt["notes"].append(
        "F2 proves a read-only input block can be consumed by the guest and a deterministic result recovered from a separate writable block without guest networking. Useful workload and sovereign operational readiness remain unproven."
    )
    out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rung", choices=["f0", "f1", "f2"], default="f0")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.rung == "f2":
        return run_f2(args.out)
    if args.rung == "f1":
        return run_f1(args.out)
    return run_f0(args.out)


if __name__ == "__main__":
    raise SystemExit(main())
