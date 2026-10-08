#!/usr/bin/env python3
"""Validate the GHA-compatible sovereign runner runtime-template contract."""
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

SCHEMA = "semper-supra.runner-runtime-templates/v1"
REQUIRED_GHA_CLASSES = {
    "ubuntu-24.04",
    "ubuntu-26.04",
    "ubuntu-24.04-arm",
    "ubuntu-26.04-arm",
    "ubuntu-slim",
    "macos-26",
    "macos-26-intel",
    "xcode-27",
    "windows-2025",
    "windows-11-arm",
}
CLASSIFICATIONS = {
    "GHA_EQUIVALENT",
    "GHA_COMPATIBLE_DELTA",
    "SOVEREIGN_ENHANCED",
}
STATUSES = {"DISCOVERY", "OPEN", "CANDIDATE", "QUALIFIED", "ADMITTED"}


class ContractError(ValueError):
    pass


def load(path: pathlib.Path) -> dict[str, Any]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    validate(doc)
    return doc


def _nonempty_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(x, str) and x for x in value):
        raise ContractError(f"{label} must be a non-empty string list")
    if len(value) != len(set(value)):
        raise ContractError(f"{label} contains duplicates")
    return value


def validate(doc: dict[str, Any]) -> None:
    if doc.get("schema") != SCHEMA:
        raise ContractError(f"unexpected schema: {doc.get('schema')!r}")
    if doc.get("authority") != "SemperSupra/agent-dispatch-private#514":
        raise ContractError("runtime-template authority drifted")

    policy = doc.get("policy")
    if not isinstance(policy, dict):
        raise ContractError("policy missing")
    for key in (
        "gha_reference_is_compatibility_contract_not_hardware_clone",
        "passive_census_is_not_admission",
        "performance_observation_is_not_functional_support",
        "cross_architecture_inheritance_prohibited",
        "cross_provider_runtime_inheritance_prohibited",
        "representative_workload_oracle_required_for_placement",
        "sovereign_enhancement_requires_independent_oracle",
    ):
        if policy.get(key) is not True:
            raise ContractError(f"policy must fail closed: {key}")

    refs = doc.get("gha_reference_classes")
    if not isinstance(refs, dict):
        raise ContractError("gha_reference_classes missing")
    if set(refs) != REQUIRED_GHA_CLASSES:
        raise ContractError(
            f"GHA reference class drift: got {sorted(refs)} expected {sorted(REQUIRED_GHA_CLASSES)}"
        )
    for name, row in refs.items():
        if row.get("platform") not in {"linux", "macos", "windows"}:
            raise ContractError(f"{name}: invalid platform")
        if row.get("architecture") not in {"x64", "arm64"}:
            raise ContractError(f"{name}: invalid architecture")
        _nonempty_list(row.get("required_predicates"), f"{name}.required_predicates")
        limits = row.get("known_limits")
        if not isinstance(limits, list) or not all(isinstance(x, str) and x for x in limits):
            raise ContractError(f"{name}.known_limits must be a string list")

    candidates = doc.get("sovereign_template_candidates")
    if not isinstance(candidates, dict) or not candidates:
        raise ContractError("sovereign_template_candidates missing")

    enhanced: set[str] = set()
    compat: set[str] = set()
    for name, row in candidates.items():
        classification = row.get("classification")
        if classification not in CLASSIFICATIONS:
            raise ContractError(f"{name}: invalid classification {classification!r}")
        status = row.get("status")
        if status not in STATUSES:
            raise ContractError(f"{name}: invalid status {status!r}")
        if not isinstance(row.get("host_class"), str) or not row["host_class"]:
            raise ContractError(f"{name}: host_class missing")
        _nonempty_list(row.get("required_local_oracles"), f"{name}.required_local_oracles")
        if not isinstance(row.get("claim_boundary"), str) or not row["claim_boundary"]:
            raise ContractError(f"{name}: claim_boundary missing")

        if classification == "SOVEREIGN_ENHANCED":
            enhanced.add(name)
            if "reference" in row:
                raise ContractError(f"{name}: enhanced profiles must derive through compatible_base")
            base = row.get("compatible_base")
            if not isinstance(base, str) or not base:
                raise ContractError(f"{name}: compatible_base missing")
            _nonempty_list(row.get("enhancements"), f"{name}.enhancements")
        else:
            compat.add(name)
            ref = row.get("reference")
            if ref not in refs:
                raise ContractError(f"{name}: unknown GHA reference {ref!r}")
            _nonempty_list(row.get("materialization_candidates"), f"{name}.materialization_candidates")

    for name in enhanced:
        base = candidates[name]["compatible_base"]
        if base not in candidates:
            raise ContractError(f"{name}: unknown compatible_base {base!r}")
        if candidates[base].get("classification") == "SOVEREIGN_ENHANCED":
            raise ContractError(f"{name}: enhanced-on-enhanced inheritance is prohibited")

    rungs = doc.get("acceptance_rungs")
    if not isinstance(rungs, dict) or list(rungs) != [f"T{i}" for i in range(9)]:
        raise ContractError("acceptance_rungs must contain ordered T0..T8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--catalog",
        type=pathlib.Path,
        default=pathlib.Path("config/runner-runtime-templates.json"),
    )
    args = parser.parse_args()
    doc = load(args.catalog)
    print(
        json.dumps(
            {
                "schema": "semper-supra.runner-runtime-template-validation/v1",
                "catalog": str(args.catalog),
                "classification": "SUPPORTED",
                "oracleSatisfied": True,
                "gha_reference_classes": len(doc["gha_reference_classes"]),
                "sovereign_template_candidates": len(doc["sovereign_template_candidates"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
