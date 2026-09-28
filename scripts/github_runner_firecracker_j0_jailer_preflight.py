#!/usr/bin/env python3
"""Firecracker J0 jailer preflight and venue-mechanics characterization."""
from __future__ import annotations

import argparse
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

SCHEMA = "firecracker-j0-jailer-preflight/v1"
AUTHORITY = "SemperSupra/agent-dispatch-private#287"
MANIFEST = pathlib.Path("experiments/firecracker/firecracker-v1.17.0-x86_64.json")


def _run(argv: list[str], timeout: int = 20) -> dict:
    code, out, err = f0._run(argv, timeout=timeout)
    return {
        "exit_code": code,
        "stdout": out[-4000:] if out else "",
        "stderr": err[-4000:] if err else "",
        "ok": code == 0,
    }


def _sha256(path: pathlib.Path) -> str:
    return f0._sha256(path)


def _find_one(root: pathlib.Path, names: tuple[str, ...]) -> pathlib.Path:
    candidates = []
    for path in root.rglob("*"):
        if path.is_file() and path.name in names:
            candidates.append(path)
    if len(candidates) != 1:
        raise RuntimeError(f"expected exactly one of {names}, found {[str(p) for p in candidates]}")
    return candidates[0]


def _cgroup_inventory() -> dict:
    root = pathlib.Path("/sys/fs/cgroup")
    fs_type = None
    try:
        cp = subprocess.run(
            ["stat", "-fc", "%T", str(root)],
            check=False, capture_output=True, text=True, timeout=5,
        )
        if cp.returncode == 0:
            fs_type = cp.stdout.strip()
    except Exception:
        pass

    controllers = []
    subtree = []
    if (root / "cgroup.controllers").exists():
        controllers = (root / "cgroup.controllers").read_text().split()
    if (root / "cgroup.subtree_control").exists():
        subtree = (root / "cgroup.subtree_control").read_text().split()

    return {
        "filesystem_type": fs_type,
        "version": 2 if fs_type == "cgroup2fs" else 1 if fs_type else None,
        "controllers": sorted(controllers),
        "subtree_control": sorted(subtree),
        "root_writable_by_current_user": os.access(root, os.W_OK),
    }


def _mount_inventory() -> dict:
    mount_count = 0
    try:
        mount_count = sum(1 for _ in pathlib.Path("/proc/self/mountinfo").open())
    except OSError:
        pass
    return {
        "mount_count": mount_count,
        "mount_namespace": os.readlink("/proc/self/ns/mnt") if pathlib.Path("/proc/self/ns/mnt").exists() else None,
        "pid_namespace": os.readlink("/proc/self/ns/pid") if pathlib.Path("/proc/self/ns/pid").exists() else None,
        "net_namespace": os.readlink("/proc/self/ns/net") if pathlib.Path("/proc/self/ns/net").exists() else None,
    }


def _trusted_path_probe(sudo: str, base: pathlib.Path) -> dict:
    exec_dir = base / "bin"
    jail_dir = base / "jailer"
    commands = [
        [sudo, "-n", "mkdir", "-p", str(exec_dir), str(jail_dir)],
        [sudo, "-n", "chown", "root:root", str(base), str(exec_dir), str(jail_dir)],
        [sudo, "-n", "chmod", "0755", str(base), str(exec_dir), str(jail_dir)],
    ]
    results = [_run(cmd) for cmd in commands]
    ok = all(item["ok"] for item in results)
    stat_result = None
    if ok:
        st = base.stat()
        stat_result = {
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode": oct(stat.S_IMODE(st.st_mode)),
            "world_writable": bool(st.st_mode & stat.S_IWOTH),
            "group_writable": bool(st.st_mode & stat.S_IWGRP),
        }
    cleanup = _run([sudo, "-n", "rm", "-rf", str(base)])
    return {
        "ok": ok,
        "commands": results,
        "stat": stat_result,
        "cleanup_ok": cleanup["ok"],
    }


def run_probe(label: str) -> dict:
    timer = LifecycleTimer()
    manifest = json.loads(MANIFEST.read_text())

    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "result": {"classification": "SETUP_REQUIRED", "reason": "J0 targets Linux x86_64"},
        }

    sudo = shutil.which("sudo")
    if not sudo:
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "result": {"classification": "SETUP_REQUIRED", "reason": "non-interactive sudo unavailable"},
        }

    with tempfile.TemporaryDirectory(prefix="firecracker-j0-") as td:
        work = pathlib.Path(td)
        archive = work / "firecracker.tgz"
        extract = work / "extract"
        extract.mkdir()

        with timer.stage("vmm_archive_download", "venue"):
            f0._download(manifest["archive_url"], archive)
        with timer.stage("vmm_archive_digest_verify", "portable"):
            actual_sha = _sha256(archive)
        digest_ok = actual_sha == manifest["archive_sha256"]
        if not digest_ok:
            return {
                "schema": SCHEMA,
                "authority": AUTHORITY,
                "result": {"classification": "ORACLE_FAILURE", "reason": "pinned Firecracker archive digest mismatch"},
                "actual_sha256": actual_sha,
            }

        with timer.stage("archive_extract", "portable"):
            f0._safe_extract(archive, extract)

        firecracker = _find_one(
            extract,
            (f"firecracker-{manifest['version']}-{manifest['architecture']}",),
        )
        jailer = _find_one(
            extract,
            (
                f"jailer-{manifest['version']}-{manifest['architecture']}",
                "jailer",
            ),
        )
        firecracker.chmod(firecracker.stat().st_mode | 0o111)
        jailer.chmod(jailer.stat().st_mode | 0o111)

        with timer.stage("binary_identity_oracles", "portable"):
            fc_version = _run([str(firecracker), "--version"])
            jailer_version = _run([str(jailer), "--version"])
            jailer_help = _run([str(jailer), "--help"])

        cgroups = _cgroup_inventory()
        namespaces = _mount_inventory()
        sudo_probe = _run([sudo, "-n", "true"])

        trusted_base = pathlib.Path(f"/opt/agent-dispatch-firecracker-j0-{os.getpid()}")
        with timer.stage("trusted_root_path_probe", "venue"):
            trusted_path = _trusted_path_probe(sudo, trusted_base)

        required_tools = {
            name: bool(shutil.which(name))
            for name in ("sudo", "useradd", "groupadd", "getent", "stat", "mount", "umount", "curl")
        }

        jailer_identity_ok = (
            jailer_version["ok"]
            and manifest["version"].lstrip("v") in (jailer_version["stdout"] + jailer_version["stderr"])
        )
        supported = (
            digest_ok
            and fc_version["ok"]
            and jailer_identity_ok
            and jailer_help["ok"]
            and sudo_probe["ok"]
            and trusted_path["ok"]
            and trusted_path["cleanup_ok"]
        )

        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "requested_label": label,
            "result": {
                "classification": "SUPPORTED" if supported else "SETUP_REQUIRED",
                "jailer_mechanics_preflight_satisfied": supported,
                "guest_boot_claimed": False,
            },
            "portable": {
                "firecracker_version": manifest["version"],
                "archive_sha256": actual_sha,
                "firecracker_binary": firecracker.name,
                "jailer_binary": jailer.name,
                "firecracker_version_oracle": fc_version,
                "jailer_version_oracle": jailer_version,
                "jailer_help_oracle": {
                    "ok": jailer_help["ok"],
                    "mentions_new_pid_ns": "--new-pid-ns" in jailer_help["stdout"],
                    "mentions_resource_limit": "--resource-limit" in jailer_help["stdout"],
                    "mentions_cgroup_version": "--cgroup-version" in jailer_help["stdout"],
                    "mentions_chroot_base_dir": "--chroot-base-dir" in jailer_help["stdout"],
                },
            },
            "venue": {
                "kernel_release": platform.release(),
                "cgroup": cgroups,
                "namespaces": namespaces,
                "sudo_noninteractive": sudo_probe["ok"],
                "required_tools": required_tools,
                "trusted_root_path_probe": trusted_path,
                "current_uid": os.getuid(),
                "current_gid": os.getgid(),
                "dev_kvm": f0._kvm_user_probe(),
                "sudo_kvm": f0._kvm_sudo_probe(),
            },
            "lifecycle_timing": timer.receipt(),
            "next_gate": "J1 jailed F3 parity; no network or block devices",
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
        receipt = {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "result": {
                "classification": "HARNESS_FAILURE",
                "reason": f"{type(exc).__name__}: {exc}",
                "guest_boot_claimed": False,
            },
        }
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["result"]["classification"] == "SUPPORTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
