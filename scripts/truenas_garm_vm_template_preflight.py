#!/usr/bin/env python3
"""Bounded, read-only VM template preflight for the exact GARM TrueNAS BETA.3 cell.

Never creates/clones/starts/deletes VM, media, or datasets; never claims runtime
admission. VM name/readback is not proof of stock-image SHA or Foundry provenance.
"""
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any, Callable

from truenas_garm_vm_pre_b4_fixture import (
    TARGET, REQUIRED_METHODS, validate_fixture, FixtureError,
)

SNAPSHOT_SCHEMA = "truenas-garm-vm-template-readonly-snapshot/v1"
RECEIPT_SCHEMA = "truenas-garm-vm-template-readonly-preflight/v1"
READ_METHODS = frozenset({
    "system.version", "core.get_methods", "vm.query", "vm.status", "vm.device.query"
})


class PreflightError(ValueError):
    pass


def _base_receipt() -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "classification": "BLOCKED",
        "oracleSatisfied": False,
        "read_only": True,
        "runtime_mutation_performed": False,
        "runtime_support_admitted": False,
        "template_source_provenance_verified": False,
        "guest_boot_observed": False,
        "github_jit_exercised": False,
        "zero_residue_runtime_proven": False,
    }


def collect_snapshot(call: Callable[[str, list], Any], template_name: str) -> dict[str, Any]:
    """Issue only explicit supported middleware reads, returning a narrow snapshot.

    Authentication is performed outside this function. Raw VM descriptions, API
    errors, credentials and guest console text are never retained as evidence.
    """
    if not isinstance(template_name, str) or not template_name.startswith("garm_tpl_"):
        raise PreflightError("unexpected template identity")
    observed_methods: list[str] = []

    def read(method: str, args: list) -> Any:
        if method not in READ_METHODS:
            raise PreflightError("non-read method forbidden")
        observed_methods.append(method)
        return call(method, args)

    version = read("system.version", [])
    methods = read("core.get_methods", [])
    if not isinstance(methods, dict):
        raise PreflightError("method census not a map")
    rows = read("vm.query", [[["name", "=", template_name]]])
    if not isinstance(rows, list):
        raise PreflightError("vm.query did not return a list")

    template_rows: list[dict[str, Any]] = []
    status = None
    devices: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise PreflightError("invalid vm.query row")
        if row.get("name") != template_name:
            raise PreflightError("vm.query returned an unrelated VM")
        ident = row.get("id")
        if not isinstance(ident, int) or isinstance(ident, bool) or ident <= 0:
            raise PreflightError("missing VM ID")
        template_rows.append({"name": row["name"], "id": ident})

    if len(template_rows) == 1:
        ident = template_rows[0]["id"]
        status_raw = read("vm.status", [ident])
        if not isinstance(status_raw, dict):
            raise PreflightError("vm.status response not a map")
        status = status_raw.get("state")
        device_rows = read("vm.device.query", [[["vm", "=", ident]]])
        if not isinstance(device_rows, list):
            raise PreflightError("vm.device.query did not return a list")
        for row in device_rows:
            if not isinstance(row, dict):
                raise PreflightError("VM device row not a map")
            attrs = row.get("attributes") or {}
            if not isinstance(attrs, dict):
                raise PreflightError("VM device attributes not a map")
            # No opaque device configuration or sensitive paths in evidence.
            path = attrs.get("path")
            devices.append({
                "dtype": attrs.get("dtype"),
                "zvol_backed": isinstance(path, str) and path.startswith("/dev/zvol/"),
                "raw_backed": attrs.get("dtype") == "RAW",
            })

    return {
        "schema": SNAPSHOT_SCHEMA,
        "version": version,
        "available_methods": sorted(methods.keys()),
        "template_rows": template_rows,
        "template_state": status,
        "template_devices": devices,
        "read_methods_used": observed_methods,
        "source_provenance_receipt": None,  # deliberately not fabricated
    }


def evaluate(fixture: dict[str, Any], producer: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Evaluate an independently collected observation; never infer template SHA."""
    static = validate_fixture(fixture, producer)
    out = _base_receipt()
    out["producer_source"] = producer
    out["target"] = TARGET
    out["template_runtime_name"] = static["template_runtime_name"]

    def block(reason: str) -> dict[str, Any]:
        out["reason_code"] = reason
        return out

    if not isinstance(snapshot, dict) or snapshot.get("schema") != SNAPSHOT_SCHEMA:
        return block("INVALID_SNAPSHOT_SCHEMA")
    if snapshot.get("version") != TARGET:
        return block("EXACT_TARGET_MISMATCH")
    methods = snapshot.get("available_methods")
    if not isinstance(methods, list) or not all(isinstance(m, str) for m in methods):
        return block("INVALID_METHOD_CENSUS")
    if not REQUIRED_METHODS.issubset(set(methods)):
        return block("VM_METHODS_ABSENT")
    sequence = snapshot.get("read_methods_used")
    if not isinstance(sequence, list) or any(m not in READ_METHODS for m in sequence):
        return block("UNTRUSTED_OBSERVER")
    if sequence[:3] != ["system.version", "core.get_methods", "vm.query"]:
        return block("INCOMPLETE_OBSERVER")
    rows = snapshot.get("template_rows")
    if not isinstance(rows, list):
        return block("INVALID_VM_QUERY")
    if len(rows) == 0:
        return block("TEMPLATE_MISSING")
    if len(rows) != 1:
        return block("TEMPLATE_AMBIGUOUS")
    row = rows[0]
    if not isinstance(row, dict) or row.get("name") != static["template_runtime_name"]:
        return block("TEMPLATE_NAME_DRIFT")
    if not isinstance(row.get("id"), int) or isinstance(row["id"], bool) or row["id"] <= 0:
        return block("INVALID_VM_ID")
    if sequence[-2:] != ["vm.status", "vm.device.query"]:
        return block("INCOMPLETE_TEMPLATE_READBACK")
    if snapshot.get("template_state") != "STOPPED":
        return block("TEMPLATE_NOT_STOPPED")
    devices = snapshot.get("template_devices")
    if not isinstance(devices, list):
        return block("INVALID_DEVICE_READBACK")
    if any(not isinstance(dev, dict) for dev in devices):
        return block("INVALID_DEVICE_ROW")
    if any(d.get("raw_backed") is True or d.get("dtype") == "RAW" for d in devices):
        return block("RAW_DISK_NOT_CLONEABLE")
    boot = [d for d in devices if d.get("dtype") == "DISK"]
    if len(boot) != 1 or boot[0].get("zvol_backed") is not True:
        return block("ZVOL_BOOT_DISK_NOT_EXACT")
    # This is a *preflight observation*, not an immutable-image verification.
    # vm.query/name/status/device data alone cannot establish a specific
    # downloaded cloud image SHA, boot-disk content or bootstrap consumption.
    out["classification"] = "TEMPLATE_OBSERVED_SOURCE_UNVERIFIED"
    out["oracleSatisfied"] = True
    out["reason_code"] = "STOCK_IMAGE_PROVENANCE_SEPARATELY_REQUIRED"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", type=pathlib.Path, required=True)
    ap.add_argument("--producer-commit", required=True)
    ap.add_argument("--snapshot", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    args = ap.parse_args()
    try:
        fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
        result = evaluate(fixture, args.producer_commit, snapshot)
    except (OSError, json.JSONDecodeError, FixtureError, PreflightError, TypeError, KeyError):
        result = _base_receipt()
        result["reason_code"] = "INPUT_OR_FIXTURE_VALIDATION_FAILED"
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("oracleSatisfied") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
