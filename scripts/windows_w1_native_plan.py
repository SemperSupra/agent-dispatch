#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
from typing import Any

from scripts.compute_guest_profile_contract import load, validate


class WindowsW1PlanError(RuntimeError):
    pass


FIXTURE_ID = "windows-11-enterprise-evaluation-26h2-x64-en-us"
MEDIA_SHA256 = "bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38"
MEDIA_SIZE = 8225329152
MEMORY_MIB = 4096
VCPUS = 2
SYSTEM_DISK_GIB = 64
SYSTEM_DISK_BYTES = SYSTEM_DISK_GIB * 1024**3

TRUENAS_SOURCE = {
    "middleware_commit": "81e1265a86083888ba94a2bdfc02ff5c9c5ef6a3",
    "vm_api_blob": "0944382fedc0a8cbcfc55fb8a653a9e5758e88fd",
    "vm_device_api_blob": "67603b6e2048da6235b802f970559b627857efc9",
    "vm_service_blob": "43ed4b532b40da02ad885039d954c99a93ea22ed",
}
PROXMOX_SOURCE = {
    "qemu_server_commit": "6785065b3f766f15f6f151af8ec27ec8bb5b07ab",
    "qemu_server_blob": "118f26bc94d9ee8e8c4c39a3d710e67c14f61bc0",
    "api2_qemu_blob": "e029a204d121f3c8b104457ef14eb6d5ce029464",
    "secure_boot_tpm_fixture_blob": "51e525b34ab3e670af887260e436973bdb2f1755",
    "package_version": "9.1.15",
}


def _nonempty(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WindowsW1PlanError(f"{label} must be non-empty")
    return value.strip()


def _safe_binding(value: str, label: str) -> str:
    value = _nonempty(value, label)
    if any(c in value for c in "\r\n\x00"):
        raise WindowsW1PlanError(f"{label} contains invalid control characters")
    return value


def _profile(path: pathlib.Path) -> dict[str, Any]:
    profile = load(path)
    validate(profile)
    fixture = profile.get("fixtures", {}).get("windows_w1")
    if not isinstance(fixture, dict) or fixture.get("id") != FIXTURE_ID:
        raise WindowsW1PlanError("qualified Windows W1 fixture is absent")
    source = fixture.get("source")
    if not isinstance(source, dict):
        raise WindowsW1PlanError("qualified Windows W1 source is absent")
    if source.get("sha256") != MEDIA_SHA256 or source.get("size_bytes") != MEDIA_SIZE:
        raise WindowsW1PlanError("Windows W1 media identity drift")
    return profile


def portable_intent(profile: dict[str, Any]) -> dict[str, Any]:
    fixture = profile["fixtures"]["windows_w1"]
    return {
        "schema": "windows-w1-portable-intent/v1",
        "fixture": FIXTURE_ID,
        "media": {
            "product": fixture["product"],
            "version": fixture["version"],
            "build": fixture["build"],
            "edition": fixture["edition"],
            "architecture": fixture["architecture"],
            "language": fixture["language"],
            "sha256": MEDIA_SHA256,
            "size_bytes": MEDIA_SIZE,
            "qualification_authority": fixture["source"]["qualification_authority"],
            "product_key_policy": fixture["product_key_policy"],
        },
        "requirements": {
            "virtual_processors": VCPUS,
            "memory_mib": MEMORY_MIB,
            "system_disk_gib": SYSTEM_DISK_GIB,
            "firmware": "UEFI",
            "secure_boot": True,
            "tpm_version": "2.0",
            "cpu_semantics": "host-passthrough",
            "install_storage_semantics": "inbox-driver-compatible-ahci-sata",
            "install_network_semantics": "inbox-driver-compatible-e1000",
            "guest_readiness_oracle": "serial-com1-exact-nonce",
        },
        "lifecycle": [
            "observe-preconditions",
            "create",
            "readback",
            "start-install",
            "unattended-install",
            "guest-readiness-oracle",
            "restart",
            "detach-install-and-seed-media",
            "system-disk-boot-oracle",
            "stop",
            "delete",
            "absence",
        ],
        "claim_boundary": (
            "Windows W1 native VM install/readiness/restart/cleanup only; "
            "nested virtualization, Hyper-V and WinBot-provider admission remain separate"
        ),
    }


def truenas_plan(
    profile: dict[str, Any],
    *,
    pool: str,
    iso_path: str,
    seed_path: str,
    bridge: str,
    name: str = "rdtewindowsw1",
) -> dict[str, Any]:
    row = profile["truenas"]["26.0.0-BETA.3"]["windows11"]
    if row.get("fixture") != FIXTURE_ID or row.get("runtime_status") != "OPEN":
        raise WindowsW1PlanError("TrueNAS BETA.3 Windows W1 profile is not source-bound OPEN")
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        raise WindowsW1PlanError("TrueNAS VM name violates exact product name grammar")
    pool = _safe_binding(pool, "pool")
    if "/" in pool:
        raise WindowsW1PlanError("TrueNAS pool binding must be a pool name, not a dataset path")
    iso_path = _safe_binding(iso_path, "iso-path")
    if not iso_path.startswith("/mnt/"):
        raise WindowsW1PlanError("TrueNAS ISO binding must be a staged /mnt path")
    seed_path = _safe_binding(seed_path, "seed-path")
    if not seed_path.startswith("/mnt/"):
        raise WindowsW1PlanError("TrueNAS seed binding must be a staged /mnt path")
    if seed_path == iso_path:
        raise WindowsW1PlanError("TrueNAS installer and unattended seed must be distinct media")
    bridge = _safe_binding(bridge, "bridge")

    zvol_name = f"{pool}/{name}system"
    return {
        "schema": "windows-w1-native-plan/v1",
        "platform": "truenas",
        "target": "26.0.0-BETA.3",
        "portable_intent": portable_intent(profile),
        "source_binding": TRUENAS_SOURCE,
        "external_bindings": {
            "install_media_path": iso_path,
            "install_media_required_sha256": MEDIA_SHA256,
            "unattended_seed_path": seed_path,
            "unattended_seed_contract": "windows-w1-unattend-seed/v1",
            "unattended_seed_volume_label": "ADW1SEED",
            "network_attach": bridge,
            "system_zvol": zvol_name,
        },
        "vm_create": {
            "name": name,
            "description": "Agent Dispatch disposable Windows W1 fixture",
            "vcpus": 1,
            "cores": 2,
            "threads": 1,
            "memory": MEMORY_MIB,
            "cpu_mode": "HOST-PASSTHROUGH",
            "autostart": False,
            "ensure_display_device": True,
            "time": "LOCAL",
            "bootloader": "UEFI",
            "bootloader_ovmf": "OVMF_CODE_4M.secboot.fd",
            "arch_type": "x86_64",
            "machine_type": "pc-q35-6.2",
            "trusted_platform_module": True,
            "hyperv_enlightenments": True,
            "enable_secure_boot": True,
            "shutdown_timeout": 90,
        },
        "device_templates": [
            {
                "role": "install-media",
                "vm_binding": "created_vm_id",
                "order": 100,
                "attributes": {"dtype": "CDROM", "path": iso_path},
            },
            {
                "role": "unattended-seed",
                "vm_binding": "created_vm_id",
                "order": 110,
                "attributes": {"dtype": "CDROM", "path": seed_path},
            },
            {
                "role": "system-disk",
                "vm_binding": "created_vm_id",
                "order": 200,
                "attributes": {
                    "dtype": "DISK",
                    "path": None,
                    "type": "AHCI",
                    "create_zvol": True,
                    "zvol_name": zvol_name,
                    "zvol_volsize": SYSTEM_DISK_BYTES,
                },
            },
            {
                "role": "network",
                "vm_binding": "created_vm_id",
                "attributes": {"dtype": "NIC", "type": "E1000", "nic_attach": bridge},
            },
        ],
        "guest_oracle": {
            "guest_device": "COM1",
            "transport": "truenas-vm-console",
            "surface": "vm.get_console -> /websocket/shell",
            "serial_binding": "native VM domain automatic PTY serial",
            "seed_volume_label": "ADW1SEED",
            "nonce_prefix": "AGENT_DISPATCH_W1_NONCE=",
        },
        "post_install_transition": {
            "action": "delete-owned-removable-media-devices",
            "owned_roles": ["install-media", "unattended-seed"],
            "reason": "force restart/boot proof from the installed system disk without installer/seed media ambiguity",
        },
        "mutation_authorized": False,
    }


def proxmox_plan(
    profile: dict[str, Any],
    *,
    vmid: int,
    storage: str,
    iso_volume: str,
    seed_volume: str,
    bridge: str,
    name: str = "rdte-windows-w1",
) -> dict[str, Any]:
    row = profile["proxmox"]["9.2-1"]["windows11"]
    if (
        row.get("fixture") != FIXTURE_ID
        or row.get("runtime_status") != "OPEN"
        or row.get("source_status") != "CANDIDATE"
    ):
        raise WindowsW1PlanError("PVE 9.2-1 Windows W1 profile is not source-bound CANDIDATE/OPEN")
    if not isinstance(vmid, int) or isinstance(vmid, bool) or vmid < 100:
        raise WindowsW1PlanError("PVE vmid must be an integer >= 100")
    storage = _safe_binding(storage, "storage")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", storage):
        raise WindowsW1PlanError("PVE storage binding contains unsupported characters")
    iso_volume = _safe_binding(iso_volume, "iso-volume")
    if ":" not in iso_volume:
        raise WindowsW1PlanError("PVE ISO binding must be a storage volume id")
    seed_volume = _safe_binding(seed_volume, "seed-volume")
    if ":" not in seed_volume:
        raise WindowsW1PlanError("PVE seed binding must be a storage volume id")
    if seed_volume == iso_volume:
        raise WindowsW1PlanError("PVE installer and unattended seed must be distinct media")
    bridge = _safe_binding(bridge, "bridge")
    if "," in bridge:
        raise WindowsW1PlanError("PVE bridge binding must not contain commas")
    name = _safe_binding(name, "name")

    return {
        "schema": "windows-w1-native-plan/v1",
        "platform": "proxmox",
        "target": "9.2-1",
        "portable_intent": portable_intent(profile),
        "source_binding": PROXMOX_SOURCE,
        "external_bindings": {
            "install_media_volume": iso_volume,
            "install_media_required_sha256": MEDIA_SHA256,
            "unattended_seed_volume": seed_volume,
            "unattended_seed_contract": "windows-w1-unattend-seed/v1",
            "unattended_seed_volume_label": "ADW1SEED",
            "vm_storage": storage,
            "network_bridge": bridge,
        },
        "create_path": "/nodes/{node}/qemu",
        "create_fields": {
            "vmid": vmid,
            "name": name,
            "memory": MEMORY_MIB,
            "cores": 2,
            "sockets": 1,
            "cpu": "host",
            "bios": "ovmf",
            "machine": "q35",
            "ostype": "win11",
            "start": 0,
            "net0": f"e1000,bridge={bridge}",
            "serial0": "socket",
            "sata0": f"{storage}:64",
            "ide1": f"{seed_volume},media=cdrom",
            "ide2": f"{iso_volume},media=cdrom",
            "efidisk0": f"{storage}:1,efitype=4m,pre-enrolled-keys=1",
            "tpmstate0": f"{storage}:1,version=v2.0",
            "boot": "order=ide2;sata0",
            "description": "Agent Dispatch disposable Windows W1 fixture",
        },
        "guest_oracle": {
            "guest_device": "COM1",
            "transport": "pve-termproxy",
            "serial": "serial0",
            "create_surface": "POST /nodes/{node}/qemu/{vmid}/termproxy",
            "seed_volume_label": "ADW1SEED",
            "nonce_prefix": "AGENT_DISPATCH_W1_NONCE=",
        },
        "post_install_transition": {
            "operations": [
                {
                    "method": "PUT",
                    "path": "/nodes/{node}/qemu/{vmid}/config",
                    "fields": {"delete": "ide2"},
                    "role": "detach-install-media",
                },
                {
                    "method": "PUT",
                    "path": "/nodes/{node}/qemu/{vmid}/config",
                    "fields": {"delete": "ide1"},
                    "role": "detach-unattended-seed",
                },
                {
                    "method": "PUT",
                    "path": "/nodes/{node}/qemu/{vmid}/config",
                    "fields": {"boot": "order=sata0"},
                    "role": "system-disk-only-boot",
                },
            ],
            "reason": "force restart/boot proof from the installed system disk without installer/seed media ambiguity",
        },
        "mutation_authorized": False,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--profile", type=pathlib.Path, default=pathlib.Path("config/compute-guest-profiles.json"))
    p.add_argument("--platform", choices=["truenas", "proxmox"], required=True)
    p.add_argument("--storage", required=True)
    p.add_argument("--media-ref", required=True)
    p.add_argument("--seed-ref", required=True)
    p.add_argument("--network", required=True)
    p.add_argument("--name")
    p.add_argument("--vmid", type=int, default=9301)
    p.add_argument("--out", type=pathlib.Path)
    a = p.parse_args()
    try:
        profile = _profile(a.profile)
        if a.platform == "truenas":
            result = truenas_plan(
                profile,
                pool=a.storage,
                iso_path=a.media_ref,
                seed_path=a.seed_ref,
                bridge=a.network,
                name=a.name or "rdtewindowsw1",
            )
        else:
            result = proxmox_plan(
                profile,
                vmid=a.vmid,
                storage=a.storage,
                iso_volume=a.media_ref,
                seed_volume=a.seed_ref,
                bridge=a.network,
                name=a.name or "rdte-windows-w1",
            )
    except (OSError, ValueError, KeyError, WindowsW1PlanError) as exc:
        result = {
            "schema": "windows-w1-native-plan/v1",
            "classification": "PLAN_FAILURE",
            "mutation_authorized": False,
            "detail": f"{type(exc).__name__}: {exc}",
        }
        code = 2
    else:
        result["classification"] = "SUPPORTED"
        result["oracleSatisfied"] = True
        code = 0
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if a.out:
        a.out.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
