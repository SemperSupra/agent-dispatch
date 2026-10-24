#!/usr/bin/env python3
"""Venue-neutral Firecracker privilege/KVM execution adapter."""
from __future__ import annotations

import pathlib
import shutil
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0


def select_kvm_access() -> dict:
    user = f0._kvm_user_probe()
    if user.get("callable"):
        return {
            "classification": "SUPPORTED",
            "mode": "direct",
            "command_prefix": [],
            "kvm_api_version": user.get("api_version"),
            "user_probe": user,
            "sudo_probe": None,
        }

    sudo = f0._kvm_sudo_probe() if user.get("present") else {
        "available": bool(shutil.which("sudo")),
        "callable": False,
        "api_version": None,
        "error": "KVM absent; sudo probe not attempted",
    }
    if sudo.get("callable"):
        return {
            "classification": "SUPPORTED",
            "mode": "sudo",
            "command_prefix": [shutil.which("sudo") or "sudo", "-n"],
            "kvm_api_version": sudo.get("api_version"),
            "user_probe": user,
            "sudo_probe": sudo,
        }

    return {
        "classification": "SETUP_REQUIRED",
        "mode": "unavailable",
        "command_prefix": None,
        "kvm_api_version": None,
        "user_probe": user,
        "sudo_probe": sudo,
    }


def privileged_command(argv: list[str], access: dict | None = None) -> list[str]:
    access = access or select_kvm_access()
    if access.get("classification") != "SUPPORTED":
        raise RuntimeError("no qualified KVM execution boundary available")
    return list(access.get("command_prefix") or []) + list(argv)


def firecracker_command(binary: pathlib.Path, args: list[str], access: dict | None = None) -> list[str]:
    return privileged_command([str(binary.resolve()), *args], access)


def api_command(curl: str, socket_path: pathlib.Path, args: list[str], access: dict | None = None) -> list[str]:
    access = access or select_kvm_access()
    # Use the same privilege boundary that created the Firecracker API socket.
    return privileged_command([curl, "--unix-socket", str(socket_path.resolve()), *args], access)
