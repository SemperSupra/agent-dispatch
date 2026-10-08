#!/usr/bin/env python3
"""Portable passive probe for one sovereign runner-template candidate.

This reuses the public GitHub-hosted runner census schema inside a local/private
candidate runtime. Passive agreement is discovery evidence only; it never admits
a template or satisfies primitive/workload rungs.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import platform
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_census as census
import runner_runtime_template_contract as contract

SCHEMA = "semper-supra.runner-runtime-template-passive/v1"


class ProbeError(ValueError):
    pass


def _normalized_platform(system: str) -> str:
    value = system.strip().lower()
    return {"darwin": "macos", "linux": "linux", "windows": "windows"}.get(value, value)


def _normalized_arch(machine: str) -> str:
    value = machine.strip().lower()
    if value in {"x86_64", "amd64"}:
        return "x64"
    if value in {"arm64", "aarch64"}:
        return "arm64"
    return value


def resolve_reference(catalog: dict[str, Any], candidate_id: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    candidates = catalog["sovereign_template_candidates"]
    if candidate_id not in candidates:
        raise ProbeError(f"unknown candidate: {candidate_id}")
    candidate = candidates[candidate_id]
    if candidate["classification"] == "SOVEREIGN_ENHANCED":
        base_id = candidate["compatible_base"]
        base = candidates[base_id]
        reference_id = base["reference"]
    else:
        base_id = candidate_id
        base = candidate
        reference_id = candidate["reference"]
    return candidate, base, reference_id


def evaluate_passive(
    catalog: dict[str, Any], candidate_id: str, receipt: dict[str, Any]
) -> dict[str, Any]:
    candidate, base, reference_id = resolve_reference(catalog, candidate_id)
    reference = catalog["gha_reference_classes"][reference_id]
    runner = receipt.get("runner") or {}
    observed_platform = _normalized_platform(str(runner.get("system") or ""))
    observed_arch = _normalized_arch(
        str(runner.get("architecture") or runner.get("machine") or "")
    )
    platform_match = observed_platform == reference["platform"]
    arch_match = observed_arch == reference["architecture"]
    passive_match = platform_match and arch_match
    resolved_base_id = (
        candidate["compatible_base"]
        if candidate["classification"] == "SOVEREIGN_ENHANCED"
        else candidate_id
    )
    return {
        "schema": SCHEMA,
        "candidate_id": candidate_id,
        "candidate_classification": candidate["classification"],
        "compatible_base": resolved_base_id,
        "reference": reference_id,
        "expected": {
            "platform": reference["platform"],
            "architecture": reference["architecture"],
            "required_predicates": reference["required_predicates"],
        },
        "observed": {
            "platform": observed_platform,
            "architecture": observed_arch,
            "census_schema": receipt.get("schema"),
        },
        "passive_platform_arch_match": passive_match,
        "classification": "INCONCLUSIVE" if passive_match else "NEGATIVE_OBSERVATION",
        "oracleSatisfied": False,
        "t2_passive_observation_complete": receipt.get("schema") == census.SCHEMA,
        "t3_primitive_oracles_claimed": False,
        "t4_representative_workloads_claimed": False,
        "placement_admitted": False,
        "required_local_oracles": candidate["required_local_oracles"],
        "claim_boundary": (
            "Passive census may establish local platform/architecture agreement and inventory only; "
            "it cannot satisfy primitive, representative-workload, lifecycle, GARM execution, "
            "sovereign-enhancement, or placement-admission rungs."
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--catalog", type=pathlib.Path, default=pathlib.Path("config/runner-runtime-templates.json"))
    p.add_argument("--candidate", required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    args = p.parse_args()

    catalog = contract.load(args.catalog)
    candidate, _base, reference_id = resolve_reference(catalog, args.candidate)
    receipt = census.build_receipt(reference_id)
    result = evaluate_passive(catalog, args.candidate, receipt)
    result["census"] = receipt

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"RUNNER_TEMPLATE_PASSIVE_RECEIPT={args.out}")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
