#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
from typing import Any

from truenas_session_manifest import SessionError, validate_manifest
from truenas_session_state import (
    CAPSULE_VERDICTS,
    CapsuleOutcome,
    decide_after_capsule,
    finalize_session,
)

RECEIPT_SCHEMA = "truenas-capsule-execution/v1"
SESSION_SCHEMA = "truenas-session-execution/v1"


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SessionError(f"{path}: top-level value must be an object")
    return value


def provider_map(path: pathlib.Path) -> dict[str, dict[str, Any]]:
    doc = load_json(path)
    if doc.get("schema") != "truenas-capsule-providers/v1":
        raise SessionError("unsupported capsule provider registry schema")
    rows = doc.get("providers")
    if not isinstance(rows, list):
        raise SessionError("provider registry requires providers list")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise SessionError("provider registry contains invalid row")
        if row["id"] in result:
            raise SessionError(f"duplicate provider: {row['id']}")
        result[row["id"]] = row
    return result


def stable_topological_capsules(capsules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    remaining = list(capsules)
    emitted: list[dict[str, Any]] = []
    emitted_ids: set[str] = set()
    while remaining:
        found = None
        for index, capsule in enumerate(remaining):
            deps = set(capsule.get("dependencies") or [])
            if deps.issubset(emitted_ids):
                found = index
                break
        if found is None:
            raise SessionError("capsule dependency graph cannot be scheduled")
        capsule = remaining.pop(found)
        emitted.append(capsule)
        emitted_ids.add(capsule["id"])
    return emitted


def validate_capsule_receipt(
    receipt: dict[str, Any],
    capsule: dict[str, Any],
    provider: dict[str, Any],
    manifest_sha256: str,
) -> CapsuleOutcome:
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise SessionError(f"{capsule['id']}: unsupported capsule receipt schema")
    if receipt.get("capsule_id") != capsule["id"]:
        raise SessionError(f"{capsule['id']}: receipt capsule identity mismatch")
    if receipt.get("provider") != capsule["provider"]:
        raise SessionError(f"{capsule['id']}: receipt provider identity mismatch")
    if receipt.get("manifest_sha256") != manifest_sha256:
        raise SessionError(f"{capsule['id']}: receipt manifest identity mismatch")
    verdict = receipt.get("verdict")
    if verdict not in CAPSULE_VERDICTS:
        raise SessionError(f"{capsule['id']}: invalid receipt verdict {verdict!r}")
    if receipt.get("mutating") is not capsule.get("mutating"):
        raise SessionError(f"{capsule['id']}: mutating contract drift")
    if receipt.get("cleanup_required") is not capsule.get("cleanup_required"):
        raise SessionError(f"{capsule['id']}: cleanup contract drift")
    for field in (
        "cleanup_satisfied",
        "platform_healthy",
        "authority_satisfied",
        "resource_guardrail_satisfied",
    ):
        if not isinstance(receipt.get(field), bool):
            raise SessionError(f"{capsule['id']}: receipt missing boolean {field}")
    if receipt.get("provider_probe") != provider.get("probe"):
        raise SessionError(f"{capsule['id']}: provider probe identity drift")
    return CapsuleOutcome(
        capsule_id=capsule["id"],
        verdict=verdict,
        mutating=capsule["mutating"],
        cleanup_required=capsule["cleanup_required"],
        cleanup_satisfied=receipt["cleanup_satisfied"],
        platform_healthy=receipt["platform_healthy"],
        authority_satisfied=receipt["authority_satisfied"],
        resource_guardrail_satisfied=receipt["resource_guardrail_satisfied"],
    )


def not_executed_receipt(
    capsule: dict[str, Any],
    provider: dict[str, Any],
    manifest_sha256: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "capsule_id": capsule["id"],
        "provider": capsule["provider"],
        "provider_probe": provider.get("probe"),
        "manifest_sha256": manifest_sha256,
        "verdict": "NOT_EXECUTED",
        "mutating": capsule["mutating"],
        "cleanup_required": capsule["cleanup_required"],
        "cleanup_satisfied": True,
        "platform_healthy": True,
        "authority_satisfied": True,
        "resource_guardrail_satisfied": True,
        "reason": reason,
    }


def harness_failure_receipt(
    capsule: dict[str, Any],
    provider: dict[str, Any],
    manifest_sha256: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "capsule_id": capsule["id"],
        "provider": capsule["provider"],
        "provider_probe": provider.get("probe"),
        "manifest_sha256": manifest_sha256,
        "verdict": "HARNESS_FAILURE",
        "mutating": capsule["mutating"],
        "cleanup_required": capsule["cleanup_required"],
        "cleanup_satisfied": not capsule["mutating"],
        "platform_healthy": False,
        "authority_satisfied": True,
        "resource_guardrail_satisfied": True,
        "reason": detail,
    }


def execute_capsule(
    executor: pathlib.Path,
    capsule: dict[str, Any],
    provider: dict[str, Any],
    manifest_sha256: str,
    context: pathlib.Path,
    receipt_path: pathlib.Path,
) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        descriptor_path = pathlib.Path(handle.name)
        json.dump(
            {
                "schema": "truenas-capsule-dispatch/v1",
                "manifest_sha256": manifest_sha256,
                "capsule": capsule,
                "provider": provider,
            },
            handle,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")
    try:
        cp = subprocess.run(
            [
                str(executor),
                "--capsule",
                str(descriptor_path),
                "--context",
                str(context),
                "--out",
                str(receipt_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if receipt_path.is_file():
            receipt = load_json(receipt_path)
            receipt.setdefault("executor_returncode", cp.returncode)
            return receipt
        return harness_failure_receipt(
            capsule,
            provider,
            manifest_sha256,
            f"executor exited {cp.returncode} without receipt",
        )
    finally:
        descriptor_path.unlink(missing_ok=True)


def run_session(
    manifest_path: pathlib.Path,
    targets_path: pathlib.Path,
    providers_path: pathlib.Path,
    executor: pathlib.Path,
    context: pathlib.Path,
    out_dir: pathlib.Path,
) -> dict[str, Any]:
    validated = validate_manifest(manifest_path, targets_path, providers_path)
    manifest = load_json(manifest_path)
    providers = provider_map(providers_path)
    ordered = stable_topological_capsules(manifest["capsules"])
    out_dir.mkdir(parents=True, exist_ok=True)

    receipts: list[dict[str, Any]] = []
    outcomes: dict[str, CapsuleOutcome] = {}
    stop_reason: str | None = None
    stop_classification: str | None = None

    for capsule in ordered:
        provider = providers[capsule["provider"]]
        receipt_path = out_dir / f"{capsule['id']}.json"

        if stop_reason is not None:
            receipt = not_executed_receipt(
                capsule,
                provider,
                validated["manifest_sha256"],
                f"session stopped: {stop_classification}: {stop_reason}",
            )
            receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            receipts.append(receipt)
            continue

        failed_dependencies = [
            dep
            for dep in capsule.get("dependencies") or []
            if dep not in outcomes or outcomes[dep].verdict != "SUPPORTED"
        ]
        if failed_dependencies:
            receipt = not_executed_receipt(
                capsule,
                provider,
                validated["manifest_sha256"],
                "unsatisfied dependencies: " + ", ".join(failed_dependencies),
            )
            receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            receipts.append(receipt)
            outcomes[capsule["id"]] = validate_capsule_receipt(
                receipt, capsule, provider, validated["manifest_sha256"]
            )
            continue

        receipt = execute_capsule(
            executor,
            capsule,
            provider,
            validated["manifest_sha256"],
            context,
            receipt_path,
        )
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        outcome = validate_capsule_receipt(
            receipt, capsule, provider, validated["manifest_sha256"]
        )
        receipts.append(receipt)
        outcomes[capsule["id"]] = outcome
        decision = decide_after_capsule(outcome)
        if not decision.continue_mutation:
            stop_reason = decision.reason
            stop_classification = decision.session_classification

    executed_outcomes = [
        outcomes[c["id"]]
        for c in ordered
        if c["id"] in outcomes and outcomes[c["id"]].verdict != "NOT_EXECUTED"
    ]
    classification = stop_classification or finalize_session(executed_outcomes)
    return {
        "schema": SESSION_SCHEMA,
        "session_id": validated["session_id"],
        "version": validated["version"],
        "manifest_sha256": validated["manifest_sha256"],
        "classification": classification,
        "session_clean": classification == "SESSION_CLEAN",
        "capsules": receipts,
        "product_acceptance_inferred": False,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--manifest", type=pathlib.Path, required=True)
    p.add_argument("--targets", type=pathlib.Path, default=pathlib.Path("config/truenas-rdte-targets.json"))
    p.add_argument("--providers", type=pathlib.Path, default=pathlib.Path("config/truenas-capsule-providers.json"))
    p.add_argument("--executor", type=pathlib.Path, required=True)
    p.add_argument("--context", type=pathlib.Path, required=True)
    p.add_argument("--out-dir", type=pathlib.Path, required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    a = p.parse_args()
    try:
        result = run_session(a.manifest, a.targets, a.providers, a.executor, a.context, a.out_dir)
        a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (SessionError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
