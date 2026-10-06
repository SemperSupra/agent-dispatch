#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
from typing import Any

PROFILE_PATH = pathlib.Path("config/compute-guest-profiles.json")
WINDOWS_FIXTURE = "windows-11-enterprise-evaluation-26h2-x64-en-us"
WINDOWS_SHA256 = "bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38"
WINDOWS_SIZE = 8225329152
DISK_BYTES = 64 * 1024 * 1024 * 1024


class WindowsPlanError(RuntimeError):
    pass


def load_profile(path: pathlib.Path = PROFILE_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    fixture = data.get("fixtures", {}).get("windows_w1")
    if not isinstance(fixture, dict) or fixture.get("id") != WINDOWS_FIXTURE:
        raise WindowsPlanError("qualified Windows W1 fixture is not bound")
    source = fixture.get("source")
    if not isinstance(source, dict):
        raise WindowsPlanError("Windows W1 source binding missing")
    if source.get("sha256") != WINDOWS_SHA256 or source.get("size_bytes") != WINDOWS_SIZE:
        raise WindowsPlanError("Windows W1 media identity drift")
    if fixture.get("product_key_policy") != "none-embedded":
        raise WindowsPlanError("Windows W1 product-key policy drift")
    return data


def portable_intent(profile: dict[str, Any]) -> dict[str, Any]:
    fixture = profile["fixtures"]["windows_w1"]
    return {
        "schema": "agent-dispatch.windows-w1-intent/v1",
        "fixture": fixture["id"],
        "source": fixture["source"],
        "compute": {"vcpus": 2, "memory_mib": 4096},
        "storage": {"system_disk_bytes": DISK_BYTES, "installation_media": "qualified-fixture"},
        "firmware": {
            "uefi": True,
            "machine": "q35",
            "secure_boot": True,
            "tpm": "2.0",
        },
        "cpu": {
            "mode": "host-passthrough",
            "nested_virtualization_required_for_w1": False,
        },
        "network": {
            "installation_compatibility_first": True,
            "optimization_after_w1": True,
        },
        "guest_oracle": {
            "required": True,
            "boundary": fixture["oracle_boundary"],
        },
        "lifecycle": [
            "observe-absent",
            "materialize",
            "readback-security",
            "boot",
            "guest-readiness-nonce",
            "restart",
            "guest-readiness-nonce",
            "stop",
            "destroy",
            "absence",
        ],
        "claim_boundary": "W1 only; nested Hyper-V and WinBot provider admission are separate",
    }


def _truenas_plan(profile: dict[str, Any], version: str, name: str) -> dict[str, Any]:
    if version != "26.0.0-BETA.3":
        raise WindowsPlanError("first TrueNAS W1 lowering is bounded to 26.0.0-BETA.3")
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        raise WindowsPlanError("TrueNAS Windows W1 name must contain only letters, digits, or underscore")
    row = profile["truenas"][version]["windows11"]
    if row.get("source_status") != "CANDIDATE" or row.get("runtime_status") != "OPEN":
        raise WindowsPlanError("TrueNAS Windows source/runtime boundary drift")
    if row.get("fixture") != WINDOWS_FIXTURE:
        raise WindowsPlanError("TrueNAS Windows fixture binding drift")
    caps = row.get("capabilities", {})
    if any(caps.get(k, {}).get("source_proven") is not True for k in ("secure_boot", "tpm", "uefi_q35")):
        raise WindowsPlanError("TrueNAS Windows source capabilities incomplete")
    return {
        "schema": "agent-dispatch.windows-w1-provider-plan/v1",
        "provider": "truenas",
        "target_version": version,
        "adapter": profile["truenas"][version]["vm_adapter"],
        "fixture": WINDOWS_FIXTURE,
        "vm_create": {
            "name": name,
            "description": "Agent Dispatch disposable Windows W1 fixture",
            "vcpus": 2,
            "cores": 1,
            "threads": 1,
            "memory": 4096,
            "cpu_mode": "HOST-PASSTHROUGH",
            "autostart": False,
            "ensure_display_device": True,
            "time": "LOCAL",
            "bootloader": "UEFI",
            "bootloader_ovmf": "OVMF_CODE_4M.secboot.fd",
            "machine_type": "q35",
            "trusted_platform_module": True,
            "hyperv_enlightenments": True,
            "enable_secure_boot": True,
            "shutdown_timeout": 90,
        },
        "storage_intent": {
            "system_disk": {"bytes": DISK_BYTES, "preferred_bus": "AHCI", "owned": True},
            "install_media": {"fixture": WINDOWS_FIXTURE, "device": "CDROM"},
        },
        "network_intent": {
            "preferred_model": "E1000",
            "attachment": "must be selected from observed supported choices before apply",
        },
        "readback_required": [
            "cpu/memory",
            "bootloader/OVMF",
            "q35",
            "secure_boot",
            "TPM",
            "system disk",
            "installation media",
            "network adapter",
        ],
        "mutation_authorized": False,
        "runtime_status": "OPEN",
    }


def _proxmox_plan(profile: dict[str, Any], version: str, vmid: int) -> dict[str, Any]:
    if version != "9.2-1":
        raise WindowsPlanError("first PVE W1 lowering is bounded to 9.2-1")
    if vmid < 100:
        raise WindowsPlanError("PVE Windows W1 VMID must be >= 100")
    row = profile["proxmox"][version]["windows11"]
    if row.get("source_status") != "CANDIDATE" or row.get("runtime_status") != "OPEN":
        raise WindowsPlanError("PVE Windows source/runtime boundary drift")
    if row.get("fixture") != WINDOWS_FIXTURE:
        raise WindowsPlanError("PVE Windows fixture binding drift")
    if row.get("source_binding") != {
        "qemu_server_commit": "6785065b3f766f15f6f151af8ec27ec8bb5b07ab",
        "package_version": "9.1.15",
    }:
        raise WindowsPlanError("PVE Windows qemu-server binding drift")
    caps = row.get("capabilities", {})
    if any(caps.get(k, {}).get("source_proven") is not True for k in ("secure_boot", "tpm", "uefi_q35")):
        raise WindowsPlanError("PVE Windows source capabilities incomplete")
    return {
        "schema": "agent-dispatch.windows-w1-provider-plan/v1",
        "provider": "proxmox",
        "target_version": version,
        "adapter": profile["proxmox"][version]["vm_adapter"],
        "fixture": WINDOWS_FIXTURE,
        "create_path": "/nodes/{node}/qemu",
        "create_fields": {
            "vmid": vmid,
            "name": f"rdte-windows-w1-{vmid}",
            "memory": 4096,
            "cores": 2,
            "sockets": 1,
            "cpu": "host",
            "bios": "ovmf",
            "machine": "q35",
            "ostype": "win11",
            "net0": "e1000,bridge=vmbr0",
            "start": 0,
            "description": "Agent Dispatch disposable Windows W1 fixture",
        },
        "storage_intent": {
            "system_disk": {"bytes": DISK_BYTES, "preferred_bus": "sata", "owned": True},
            "efi": {"efitype": "4m", "pre_enrolled_keys": True, "owned": True},
            "tpm": {"version": "v2.0", "owned": True},
            "install_media": {"fixture": WINDOWS_FIXTURE, "device": "cdrom"},
        },
        "readback_required": [
            "cpu/memory",
            "bios=ovmf",
            "machine=q35",
            "efidisk pre-enrolled keys",
            "TPM 2.0",
            "system disk",
            "installation media",
            "network adapter",
        ],
        "source_binding": row["source_binding"],
        "mutation_authorized": False,
        "runtime_status": "OPEN",
    }


def provider_plan(
    profile: dict[str, Any], platform: str, version: str, *, name: str = "rdtewindowsw1", vmid: int = 9301
) -> dict[str, Any]:
    intent = portable_intent(profile)
    if platform == "truenas":
        lowering = _truenas_plan(profile, version, name)
    elif platform == "proxmox":
        lowering = _proxmox_plan(profile, version, vmid)
    else:
        raise WindowsPlanError(f"unsupported platform {platform!r}")
    return {
        "schema": "agent-dispatch.windows-w1-plan/v1",
        "intent": intent,
        "lowering": lowering,
        "claim_boundary": "plan/source qualification only; no Windows runtime or provider admission claim",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", type=pathlib.Path, default=PROFILE_PATH)
    ap.add_argument("--platform", choices=["truenas", "proxmox"], required=True)
    ap.add_argument("--target-version", required=True)
    ap.add_argument("--name", default="rdtewindowsw1")
    ap.add_argument("--vmid", type=int, default=9301)
    ap.add_argument("--out", type=pathlib.Path)
    args = ap.parse_args()
    try:
        result = provider_plan(
            load_profile(args.profile),
            args.platform,
            args.target_version,
            name=args.name,
            vmid=args.vmid,
        )
    except (OSError, json.JSONDecodeError, WindowsPlanError) as exc:
        result = {
            "schema": "agent-dispatch.windows-w1-plan/v1",
            "classification": "HARNESS_FAILURE",
            "mutation_authorized": False,
            "detail": f"{type(exc).__name__}: {exc}",
        }
        code = 2
    else:
        result["classification"] = "SUPPORTED"
        code = 0
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
