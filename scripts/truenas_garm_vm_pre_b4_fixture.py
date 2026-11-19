#!/usr/bin/env python3
"""Fail-closed, source-only consumer for the exact TrueNAS BETA.3 GARM VM fixture.

This module does not contact TrueNAS, create a guest, or admit runtime support.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re

SCHEMA = "semper-supra.garm-provider-truenas-vm-pre-b4-fixture/1"
TARGET = "TrueNAS-26.0.0-BETA.3"
MIDDLEWARE = "81e1265a86083888ba94a2bdfc02ff5c9c5ef6a3"
TEMPLATE_NAME = "garm_tpl_ubuntu_2404_20260926_amd64"
IMAGE_URL = "https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.img"
IMAGE_SHA256 = "6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2"
TOKEN_PLACEHOLDER = "__RUN_LOCAL_INSTANCE_TOKEN__"
MARKER_PREFIX = "GARM_VM_BOOTSTRAP_CONSUMED_V1:"
REQUIRED_METHODS = {
    "system.version", "vm.query", "vm.create", "vm.update",
    "vm.clone", "vm.delete", "vm.start", "vm.stop",
    "vm.poweroff", "vm.status", "vm.device.query",
    "vm.device.create", "vm.device.delete",
}
REQUIRED_TRUE = {
    "exact_version_required",
    "25_04_1_not_admitted",
    "foreign_ownership_rejected",
    "classic_vm_name_safe",
    "fixed_cpu_memory_profile_required",
    "autostart_forbidden",
    "zvol_template_clone_required",
    "supported_filesystem_put_required",
    "stock_template_source_exact",
    "self_contained_nocloud_bootstrap",
    "unprivileged_runner_required",
    "owned_seed_dataset_required",
    "owned_cdrom_required",
    "active_seed_detach_forbidden",
    "bootstrap_consumption_signal_required",
    "console_consumption_marker_required",
    "seed_device_absence_required",
    "seed_dataset_absence_required",
    "final_vm_absence_required",
}
REQUIRED_FALSE = {
    "runtime_admission_claimed",
    "guest_boot_claimed",
    "bootstrap_consumption_claimed",
    "github_jit_boundary_claimed",
    "docker_or_container_actions_claimed",
    "windows_or_gpu_claimed",
}


class FixtureError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise FixtureError(reason)


def validate_fixture(doc: dict, producer: str) -> dict:
    """Return only non-secret source/static evidence. Never log user-data."""
    require(re.fullmatch(r"[0-9a-f]{40}", producer) is not None, "invalid producer SHA")
    require(isinstance(doc, dict), "fixture must be an object")
    require(doc.get("schema") == SCHEMA, "fixture schema drift")
    require(doc.get("producer_source") == producer, "producer ref drift")
    require(doc.get("authority") == "SemperSupra/garm-provider-truenas-private#43", "owner authority drift")

    target = doc.get("target") or {}
    require(target.get("version") == "26.0.0-BETA.3", "version drift")
    require(target.get("system_version") == TARGET, "system version drift")
    require(target.get("middleware_commit") == MIDDLEWARE, "middleware source drift")
    require(target.get("driver") == "vm-v1", "driver drift")
    require(target.get("control_surface") == "vm.*", "VM API drift")
    require(target.get("status") == "OPEN", "unearned runtime admission")
    require(REQUIRED_METHODS.issubset(set(target.get("required_methods") or [])), "missing VM API methods")

    require(doc.get("profile") == "truenas-vm-linux-general", "profile drift")
    require(doc.get("template_family") == "ubuntu-24.04-amd64-template", "template family drift")
    require(doc.get("template_version") == "ubuntu-24.04-release-20260926-amd64", "template version drift")
    require(doc.get("template_runtime_name") == TEMPLATE_NAME, "runtime template name drift")
    require(doc.get("template_source_url") == IMAGE_URL, "stock image URL drift")
    require(doc.get("template_source_sha256") == IMAGE_SHA256, "stock image digest drift")

    name = doc.get("expected_name")
    require(isinstance(name, str) and re.fullmatch(r"[a-zA-Z0-9_]{1,150}", name) is not None,
            "classic VM name illegal")
    owner = doc.get("expected_ownership") or {}
    require(owner.get("schema") == "semper-supra.garm-vm-owner/1", "ownership schema drift")
    require(owner.get("managed_by") == "garm-provider-truenas", "foreign management")
    require(owner.get("profile") == doc["profile"], "ownership profile drift")
    for key in ("controller_id", "pool_id", "runner_name"):
        require(isinstance(owner.get(key), str) and bool(owner[key]), "missing ownership field " + key)

    clone = doc.get("clone") or {}
    require(clone.get("vcpus") == 4 and type(clone.get("vcpus")) is int, "CPU profile drift")
    require(clone.get("memory_bytes") == 8 * 1024**3 and type(clone.get("memory_bytes")) is int,
            "memory profile drift")
    require(clone.get("autostart") is False, "autostart forbidden")
    require(isinstance(clone.get("description"), str) and owner["managed_by"] in clone["description"],
            "ownership not encoded in description")

    seed = doc.get("seed") or {}
    require(seed.get("run_local_token_placeholder") == TOKEN_PLACEHOLDER, "token placeholder drift")
    require(seed.get("transport") == "provider-owned child dataset + public filesystem.put input pipe",
            "seed transport drift")
    require(seed.get("attach_device") == "owned vm.device CDROM", "seed attachment drift")
    require(seed.get("retain_while_active") is True and seed.get("delete_only_when_stopped") is True,
            "unsafe active seed retirement")
    require(seed.get("consumption_signal_required") is True, "missing consumption signal")
    marker = MARKER_PREFIX + name
    require(seed.get("consumption_marker") == marker, "console consumption marker drift")
    user_data = seed.get("user_data")
    require(isinstance(user_data, str) and TOKEN_PLACEHOLDER in user_data and marker in user_data,
            "NoCloud bootstrap material incomplete")
    for needle in ("path: /usr/local/libexec/garm-runner-bootstrap",
                   "path: /usr/local/libexec/garm-bootstrap",
                   "name: garm-runner", "/usr/sbin/runuser -u garm-runner",
                   'rm -f "$env_file"', "/dev/console"):
        require(needle in user_data, "NoCloud self-contained/bootstrap invariant absent")
    require(TOKEN_PLACEHOLDER not in str(seed.get("meta_data") or ""), "token leaked to meta-data")
    require(TOKEN_PLACEHOLDER not in clone["description"], "token leaked to ownership")

    flags = doc.get("source_oracles") or {}
    for flag in REQUIRED_TRUE:
        require(flags.get(flag) is True, "unproven source invariant: " + flag)
    for flag in REQUIRED_FALSE:
        require(flags.get(flag) is False, "forbidden support claim: " + flag)
    retirement = doc.get("retirement") or []
    require(isinstance(retirement, list) and len(retirement) >= 7, "missing retirement steps")
    require(any("vm.stop" in s for s in retirement), "VM stop absent")
    require(any("seed dataset absence" in s for s in retirement), "seed cleanup absent")
    require(any("final VM absence" in s for s in retirement), "final VM cleanup absent")

    runner = doc.get("runner") or {}
    require(re.fullmatch(r"[0-9a-f]{64}", str(runner.get("tool_sha256", ""))) is not None,
            "unpinned runner tool")
    require(str(runner.get("tool_url", "")).startswith("https://github.com/actions/runner/releases/download/"),
            "unexpected runner tool origin")
    return {
        "schema": "truenas-garm-vm-pre-b4-consumer-static/v1",
        "classification": "STATIC_CONTRACT_PASS",
        "oracleSatisfied": True,
        "source_only": True,
        "producer_source": producer,
        "target": TARGET,
        "driver": "vm-v1",
        "template_runtime_name": TEMPLATE_NAME,
        "expected_name": name,
        "vm_runtime_admitted": False,
        "guest_boot_observed": False,
        "bootstrap_consumption_observed": False,
        "github_jit_exercised": False,
        "zero_residue_runtime_proven": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=pathlib.Path, required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        doc = json.loads(args.fixture.read_text(encoding="utf-8"))
        receipt = validate_fixture(doc, args.producer_commit)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        receipt = {
            "schema": "truenas-garm-vm-pre-b4-consumer-static/v1",
            "classification": "STATIC_CONTRACT_FAILURE",
            "oracleSatisfied": False,
            "source_only": True,
            "reason": str(exc)[:180],
            "vm_runtime_admitted": False,
        }
    args.out.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in receipt.items() if k != "reason"}, sort_keys=True))
    return 0 if receipt["oracleSatisfied"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
