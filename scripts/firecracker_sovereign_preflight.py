#!/usr/bin/env python3
"""P6 host-admission and sovereign-transfer preflight.

This does not qualify a sovereign host by itself. It verifies prerequisites and
emits a host fingerprint/reproduction contract. Operational promotion requires
the portable experiment ladder to be rerun on the sovereign host.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import shutil
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import firecracker_execution_adapter as exec_adapter
from firecracker_host_fingerprint import fingerprint, compare_for_initial_snapshot_restore

ROOT = pathlib.Path(__file__).resolve().parents[1]
VMM_MANIFEST = ROOT / "experiments/firecracker/firecracker-v1.17.0-x86_64.json"
KERNEL_MANIFEST = ROOT / "experiments/firecracker/guest-kernel-6.18.48-x86_64.json"

PORTABLE_REPRODUCTION = [
    "scripts/github_runner_firecracker_f3_useful_work.py",
    "scripts/github_runner_firecracker_p1_concurrency.py",
    "scripts/github_runner_firecracker_p2_coexistence.py",
    "scripts/github_runner_firecracker_p3_same_host_handoff.py",
]

REQUIRED_TOOLS = ["python3", "gcc", "curl", "timeout"]
OPTIONAL_TOOLS = ["docker"]


def _meminfo() -> dict:
    values = {}
    try:
        for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
            if ":" not in line:
                continue
            key, rest = line.split(":", 1)
            if key in {"MemTotal", "MemAvailable"}:
                values[key] = int(rest.strip().split()[0]) * 1024
    except OSError:
        pass
    return {
        "total_bytes": values.get("MemTotal"),
        "available_bytes": values.get("MemAvailable"),
    }


def _load_manifest(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text())
    return {
        "path": str(path.relative_to(ROOT)),
        "exists": True,
        "content": data,
    }


def _tool_state(name: str) -> dict:
    path = shutil.which(name)
    return {"available": bool(path), "path": path}


def _docker_state() -> dict:
    state = _tool_state("docker")
    if not state["available"]:
        state["daemon_callable"] = False
        return state
    code, out, err = f0._run([state["path"], "info"], timeout=20)
    state["daemon_callable"] = code == 0
    state["error"] = None if code == 0 else (err or out or f"exit {code}")[-1000:]
    return state


def build_receipt(compare_to: pathlib.Path | None = None) -> dict:
    host = fingerprint()
    access = exec_adapter.select_kvm_access()
    direct_kvm = access.get("user_probe") or {
        "present": False,
        "callable": False,
        "api_version": None,
        "error": "direct KVM probe unavailable",
    }
    sudo_kvm = access.get("sudo_probe") or {
        "available": bool(shutil.which("sudo")),
        "callable": False,
        "api_version": None,
        "error": "sudo fallback not selected",
    }

    kvm_access = {
        "direct": "direct-user",
        "sudo": "passwordless-sudo",
    }.get(access.get("mode"), "unavailable")

    required_tools = {name: _tool_state(name) for name in REQUIRED_TOOLS}
    optional_tools = {"docker": _docker_state()}
    scripts = {
        rel: {
            "exists": (ROOT / rel).exists(),
            "sha256": f0._sha256(ROOT / rel) if (ROOT / rel).exists() else None,
        }
        for rel in PORTABLE_REPRODUCTION
    }

    vmm = _load_manifest(VMM_MANIFEST)
    kernel = _load_manifest(KERNEL_MANIFEST)
    temp_usage = shutil.disk_usage(tempfile.gettempdir())

    core_checks = {
        "linux": platform.system() == "Linux",
        "x86_64": platform.machine() in {"x86_64", "amd64"},
        "kvm_api_12_callable": access.get("kvm_api_version") == f0.EXPECTED_KVM_API_VERSION,
        "required_tools_available": all(item["available"] for item in required_tools.values()),
        "portable_scripts_present": all(item["exists"] for item in scripts.values()),
        "pinned_vmm_manifest_present": VMM_MANIFEST.exists(),
        "pinned_kernel_manifest_present": KERNEL_MANIFEST.exists(),
    }
    admitted = all(core_checks.values())
    venue = "github-actions-rdte" if os.environ.get("GITHUB_ACTIONS") == "true" else "non-github-linux"

    receipt = {
        "schema": "firecracker-sovereign-preflight/v1",
        "authority": "SemperSupra/agent-dispatch-private#280",
        "result": {
            "host_admission_prerequisites_pass": admitted,
            "classification": "ADMISSION_PREREQUISITES_PASS" if admitted else "SETUP_REQUIRED",
            "operationally_qualified": False,
            "reason": (
                "Prerequisites are present; execute the sovereign reproduction ladder before promotion."
                if admitted
                else "One or more host prerequisites are missing."
            ),
        },
        "venue": {
            "classification": venue,
            "github_actions_detected": os.environ.get("GITHUB_ACTIONS") == "true",
            "note": (
                "A pass on GitHub Actions validates this preflight only; it never constitutes sovereign qualification."
            ),
        },
        "host_fingerprint": host,
        "kvm": {
            "selected_access_path": kvm_access,
            "direct_user": direct_kvm,
            "sudo": sudo_kvm,
            "required_api_version": f0.EXPECTED_KVM_API_VERSION,
        },
        "tools": {
            "required": required_tools,
            "optional": optional_tools,
            "docker_required_only_for_p2": True,
        },
        "resources": {
            "memory": _meminfo(),
            "temp_storage": {
                "path": tempfile.gettempdir(),
                "total_bytes": temp_usage.total,
                "free_bytes": temp_usage.free,
            },
        },
        "pinned_artifacts": {
            "firecracker": {
                "version": vmm["content"].get("version"),
                "archive_sha256": vmm["content"].get("archive_sha256"),
                "architecture": vmm["content"].get("architecture"),
            },
            "kernel": {
                "version": kernel["content"].get("kernel_version"),
                "sha256": kernel["content"].get("kernel_sha256"),
                "architecture": kernel["content"].get("architecture"),
            },
        },
        "portable_reproduction_scripts": scripts,
        "core_checks": core_checks,
        "promotion_gate": {
            "required_before_operational_use": [
                "F3 fixed useful-work baseline passes on the sovereign host with lifecycle receipt",
                "P1 concurrency envelope is measured on the actual sovereign resource class",
                "P3 same-host snapshot continuity passes if stateful handoff is intended",
                "P2 coexistence is measured if microVMs will share hosts with native/container work",
                "cross-host snapshot movement is enabled only between fingerprint-qualified compatible hosts",
                "no GitHub Actions environment variable or artifact service is required for portable correctness",
            ],
        },
    }

    if compare_to is not None:
        other = json.loads(compare_to.read_text())
        other_fp = other.get("host_fingerprint", other)
        receipt["cross_host_snapshot_gate"] = compare_for_initial_snapshot_restore(
            other_fp, host
        )

    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--compare-to", type=pathlib.Path)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = build_receipt(args.compare_to)
    except Exception as exc:
        receipt = {
            "schema": "firecracker-sovereign-preflight/v1",
            "result": {
                "host_admission_prerequisites_pass": False,
                "classification": "HARNESS_FAILURE",
                "operationally_qualified": False,
                "reason": f"{type(exc).__name__}: {exc}",
            },
        }
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["result"].get("host_admission_prerequisites_pass") else 1


if __name__ == "__main__":
    raise SystemExit(main())
