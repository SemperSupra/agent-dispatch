#!/usr/bin/env python3
"""Host fingerprint and bounded snapshot-compatibility gate for Firecracker RDTE."""
from __future__ import annotations

import hashlib
import os
import pathlib
import platform
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import firecracker_execution_adapter as exec_adapter


def fingerprint() -> dict:
    vendor_id = None
    model_name = None
    flags: list[str] = []
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as fh:
            block = fh.read().split("\n\n", 1)[0]
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, value = (part.strip() for part in line.split(":", 1))
            if key == "vendor_id":
                vendor_id = value
            elif key == "model name":
                model_name = value
            elif key in {"flags", "Features"}:
                flags = sorted(set(value.split()))
    except OSError:
        pass

    kvm = exec_adapter.select_kvm_access()
    flags_text = " ".join(flags)
    return {
        "architecture": platform.machine(),
        "cpu_vendor_id": vendor_id,
        "cpu_model_name": model_name,
        "cpu_flags": flags,
        "cpu_flags_sha256": hashlib.sha256(flags_text.encode()).hexdigest(),
        "logical_cpus": os.cpu_count(),
        "host_kernel_release": platform.release(),
        "image_os": os.environ.get("ImageOS"),
        "image_version": os.environ.get("ImageVersion"),
        "kvm_api_version": kvm.get("kvm_api_version"),
    }


def compare_for_initial_snapshot_restore(source: dict, destination: dict) -> dict:
    checks = {
        "architecture": source.get("architecture") == destination.get("architecture"),
        "cpu_vendor_id": source.get("cpu_vendor_id") == destination.get("cpu_vendor_id"),
        "cpu_model_name": source.get("cpu_model_name") == destination.get("cpu_model_name"),
        "cpu_flags_sha256": source.get("cpu_flags_sha256") == destination.get("cpu_flags_sha256"),
        "host_kernel_release": source.get("host_kernel_release") == destination.get("host_kernel_release"),
        "kvm_api_version": source.get("kvm_api_version") == destination.get("kvm_api_version"),
    }
    compatible = all(checks.values())
    return {
        "compatible_for_initial_restore_attempt": compatible,
        "checks": checks,
        "policy": (
            "Initial P4 gate requires exact architecture, CPU vendor/model/feature fingerprint, "
            "host kernel release, and KVM API match. Image version is recorded but not gated."
        ),
    }
