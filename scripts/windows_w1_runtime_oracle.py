#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

FIXTURE_ID = "windows-11-enterprise-evaluation-26h2-x64-en-us"
MEDIA_SHA256 = "bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38"
NONCE_PREFIX = "AGENT_DISPATCH_W1_NONCE="
SEED_SCHEMA = "windows-w1-unattend-seed/v1"
SEED_LABEL = "ADW1SEED"
PLATFORMS = {"truenas", "proxmox"}


class WindowsW1RuntimeOracleError(RuntimeError):
    pass


def _get(mapping: dict[str, Any], *path: str) -> Any:
    value: Any = mapping
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def evaluate(receipt: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise WindowsW1RuntimeOracleError("receipt must be an object")

    checks: dict[str, bool] = {}

    def check(name: str, condition: bool) -> None:
        checks[name] = bool(condition)

    platform = receipt.get("platform")
    check("schema", receipt.get("schema") == "windows-w1-runtime-evidence/v1")
    check("platform", platform in PLATFORMS)
    check("source_profile_bound", receipt.get("source_profile_bound") is True)
    check("fixture_identity", receipt.get("fixture") == FIXTURE_ID)
    check("media_identity", receipt.get("media_sha256") == MEDIA_SHA256)

    check("vcpus", _get(receipt, "resources", "virtual_processors") == 2)
    check("memory", _get(receipt, "resources", "memory_mib") == 4096)
    check("system_disk", _get(receipt, "resources", "system_disk_gib") == 64)
    check("cpu_semantics", _get(receipt, "resources", "cpu_semantics") == "host-passthrough")
    check(
        "storage_semantics",
        _get(receipt, "resources", "install_storage_semantics")
        == "inbox-driver-compatible-ahci-sata",
    )
    check(
        "network_semantics",
        _get(receipt, "resources", "install_network_semantics")
        == "inbox-driver-compatible-e1000",
    )

    check("firmware", _get(receipt, "security", "firmware") == "UEFI")
    check("secure_boot", _get(receipt, "security", "secure_boot") is True)
    check("tpm", _get(receipt, "security", "tpm_version") == "2.0")

    check("seed_schema", _get(receipt, "seed", "schema") == SEED_SCHEMA)
    check("seed_label", _get(receipt, "seed", "volume_label") == SEED_LABEL)
    check("seed_no_product_key", _get(receipt, "seed", "embedded_product_key") is False)
    check("seed_no_password", _get(receipt, "seed", "embedded_password") is False)

    expected_nonce = _get(receipt, "guest_oracle", "expected_nonce")
    initial_nonce = _get(receipt, "guest_oracle", "initial_nonce")
    restart_nonce = _get(receipt, "guest_oracle", "restart_nonce")
    check(
        "nonce_shape",
        isinstance(expected_nonce, str)
        and expected_nonce.startswith(NONCE_PREFIX)
        and len(expected_nonce) > len(NONCE_PREFIX),
    )
    check("initial_guest_nonce", initial_nonce == expected_nonce)
    check("restart_guest_nonce", restart_nonce == expected_nonce)
    check("initial_observer_external", _get(receipt, "guest_oracle", "initial_external") is True)
    check("restart_observer_external", _get(receipt, "guest_oracle", "restart_external") is True)

    check("install_completed", _get(receipt, "lifecycle", "install_completed") is True)
    check("restart_completed", _get(receipt, "lifecycle", "restart_completed") is True)
    check("install_media_absent", _get(receipt, "lifecycle", "install_media_absent") is True)
    check("seed_media_absent", _get(receipt, "lifecycle", "seed_media_absent") is True)
    check("system_disk_booted", _get(receipt, "lifecycle", "system_disk_booted") is True)

    check("vm_absent", _get(receipt, "cleanup", "vm_absent") is True)
    check("system_storage_absent", _get(receipt, "cleanup", "system_storage_absent") is True)
    check("staged_media_absent", _get(receipt, "cleanup", "staged_media_absent") is True)
    check("owned_residue_absent", _get(receipt, "cleanup", "owned_residue_absent") is True)

    failures = [name for name, passed in checks.items() if not passed]
    supported = not failures
    return {
        "schema": "windows-w1-portable-runtime-oracle/v1",
        "classification": "SUPPORTED" if supported else "ORACLE_FAILURE",
        "oracleSatisfied": supported,
        "platform": platform,
        "fixture": FIXTURE_ID,
        "checks": checks,
        "failures": failures,
        "claim_boundary": (
            "W1 proves the same portable Windows 11 install/readiness/restart/system-disk-boot/"
            "cleanup semantics on an admitted native VM backend only; nested virtualization, "
            "Hyper-V and WinBot-provider admission remain separate"
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--receipt", type=pathlib.Path, required=True)
    p.add_argument("--out", type=pathlib.Path)
    a = p.parse_args()
    try:
        receipt = json.loads(a.receipt.read_text(encoding="utf-8"))
        result = evaluate(receipt)
    except (OSError, json.JSONDecodeError, WindowsW1RuntimeOracleError) as exc:
        result = {
            "schema": "windows-w1-portable-runtime-oracle/v1",
            "classification": "ORACLE_FAILURE",
            "oracleSatisfied": False,
            "failures": [f"{type(exc).__name__}: {exc}"],
        }
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if a.out:
        a.out.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if result.get("oracleSatisfied") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
