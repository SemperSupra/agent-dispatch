#!/usr/bin/env python3
"""Non-mutating Windows 11 W1 plan for standalone Linux libvirt/KVM.

Consumes the existing portable Windows W1 fixture and pinned media contract.
It does NOT install Windows, run a VM or authorize unattended disk wiping.
Authority: WinBot#108 / Agent Dispatch-private#426.
"""
from __future__ import annotations

import pathlib
import re
import uuid
from typing import Any

from scripts.compute_guest_profile_contract import validate
from scripts.windows_w1_native_plan import (
    FIXTURE_ID, MEDIA_SHA256, MEDIA_SIZE, MEMORY_MIB, VCPUS,
    SYSTEM_DISK_GIB, portable_intent,
)


class LibvirtW1PlanError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LibvirtW1PlanError(message)


def _observed(obs: dict[str, Any], key: str) -> Any:
    _require(key in obs, f"missing observed {key}")
    return obs[key]


def libvirt_w1_plan(profile: dict[str, Any], observed: dict[str, Any], run_uuid: str) -> dict[str, Any]:
    """Pure, strict lowering to an owned libvirt KVM Windows W1 plan.

    The caller must freshly independently verify all observed fields again
    before Apply, including actual libvirt domain and disk identities.
    """
    validate(profile)
    fixture = profile["fixtures"]["windows_w1"]
    _require(fixture["id"] == FIXTURE_ID, "Windows 11 fixture not source qualified")
    _require(fixture["source"]["sha256"] == MEDIA_SHA256, "Windows media digest drift")
    _require(fixture["source"]["size_bytes"] == MEDIA_SIZE, "Windows media size drift")
    try:
        parsed = uuid.UUID(run_uuid)
    except (ValueError, AttributeError, TypeError) as exc:
        raise LibvirtW1PlanError("exact canonical UUIDv4 required") from exc
    _require(parsed.version == 4 and str(parsed) == run_uuid, "noncanonical run UUID")
    root = f"/var/lib/libvirt/images/ad-w1-{parsed.hex}"
    _require(_observed(observed, "owned_root") == root, "storage is not exact run-owned path")
    _require(_observed(observed, "libvirt_uri") == "qemu:///system", "wrong libvirt session/control")
    for field in ("kvm_vcpu_exercised", "host_passthrough_supported",
                  "secureboot_firmware_observed", "enrolled_keys_observed",
                  "swtpm2_startup_exercised", "owned_isolated_network_observed",
                  "domain_uuid_absent", "owned_root_absent",
                  "installer_media_digest_verified", "unattended_seed_secret_free",
                  "windows_wipe_target_is_single_run_owned_disk"):
        _require(_observed(observed, field) is True, f"{field} unverified")
    _require(_observed(observed, "installer_media_sha256") == MEDIA_SHA256, "ISO digest drift")
    _require(_observed(observed, "installer_media_size_bytes") == MEDIA_SIZE, "ISO size drift")
    net = _observed(observed, "network")
    _require(net == "ad-w1-" + parsed.hex, "network not exact isolated run ownership")
    seed_sha = _observed(observed, "unattended_seed_sha256")
    _require(isinstance(seed_sha, str) and re.fullmatch(r"[0-9a-f]{64}", seed_sha) is not None,
             "seed ISO digest missing")

    # These are STAGING INTENTS, not claims that media or volumes already exist.
    iso_path = root + "/windows11-install.iso"
    seed_path = root + "/unattended-seed.iso"
    disk_path = root + "/system.qcow2"
    for path in (iso_path, seed_path, disk_path):
        _require(pathlib.PurePosixPath(path).is_relative_to(root), "non-owned resource path")

    return {
        "schema": "windows-w1-native-plan/v1",
        "platform": "libvirt-kvm",
        "target": "linux-qemu-system-libvirt-kvm-v1",
        "portable_intent": portable_intent(profile),
        "source_binding": {
            "source": "SemperSupra/agent-dispatch-private#426",
            "winbot_provider": "mark-e-deyoung/WinBot#108",
            "w0_evidence_required": "run-39302382045",
            "kvm_substrate_evidence_required": "run-39300776646",
        },
        "resource_owner": {"uuid": run_uuid, "root": root,
                           "network": net, "not_preexisting": True},
        "vm_create": {
            "domain_type": "kvm",
            "vcpus": VCPUS,
            "memory_mib": MEMORY_MIB,
            "machine": "q35",
            "cpu": "host-passthrough",
            "firmware": "UEFI",
            "secure_boot": True,
            "enrolled_keys": True,
            "tpm_backend": "swtpm-emulator-v2",
            "storage": {"driver": "qcow2", "role": "single-run-owned-blank-writable-system",
                        "path": disk_path, "size_gib": SYSTEM_DISK_GIB,
                        "bus": "sata"},
            "installer_cdrom": {"path": iso_path, "readonly": True, "boot_priority": 1,
                                "sha256": MEDIA_SHA256, "size_bytes": MEDIA_SIZE},
            "seed_cdrom": {"path": seed_path, "readonly": True, "boot_priority": 2,
                           "volume_label": "ADW1SEED", "sha256": seed_sha},
            "network": {"model": "e1000", "type": "owned-isolated-network",
                        "binding": net},
            "serial": {"device": "COM1", "path": root + "/serial.log",
                       "oracle": "AGENT_DISPATCH_W1_NONCE="},
        },
        "post_install_transition": {
            "before_disk_boot": ["detach-install-media", "detach-unattended-seed"],
            "system_disk_only_boot": True,
            "guest_nonce_before_and_after_restart": True,
        },
        "cleanup_required": {
            "domain_absent": True, "system_disk_absent": True,
            "firmware_nvram_absent": True, "tpm_state_absent": True,
            "media_absent": True, "owned_network_absent": True,
        },
        "mutation_authorized": False,
        "windows_guest_qualified": False,
        "winbot_guest_qualified": False,
        "claim_boundary": "Nonmutating W1 source plan only; no WinBot guest/API/GUI claims",
    }
