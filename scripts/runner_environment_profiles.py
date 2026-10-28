#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import pathlib

SCHEMA = "semper-supra.runner-environment-profiles/v1"
ENV_CLASSES = {"GHA_PARITY", "SOVEREIGN_EXTENSION", "REFERENCE_ONLY"}
RESOURCE_CLASSES = {"SCALED_LOCAL", "LOCAL_ACCELERATED", "CLOUD_ONLY"}
STATUSES = {"OPEN", "NOT_LOCAL_MATERIALIZABLE", "PASS", "FAIL", "HOLD"}


class RegistryError(RuntimeError):
    pass


def load(path: pathlib.Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    validate(doc)
    return doc


def validate(doc: dict) -> None:
    if doc.get("schema") != SCHEMA:
        raise RegistryError("unexpected schema")
    policy = doc.get("policy")
    if not isinstance(policy, dict):
        raise RegistryError("policy missing")
    for key in (
        "environment_equivalence_is_not_hardware_identity",
        "resource_scaling_may_exceed_reference",
        "support_inheritance_allowed",
        "census_receipt_required_before_parity_claim",
        "workload_oracle_required_before_workload_claim",
        "sovereign_extensions_must_be_declared",
        "provider_independent_profile_ids",
        "placement_must_match_environment_and_capabilities",
    ):
        if key not in policy:
            raise RegistryError(f"policy missing {key}")
    if policy["support_inheritance_allowed"] is not False:
        raise RegistryError("support inheritance must fail closed")
    for key in (
        "environment_equivalence_is_not_hardware_identity",
        "resource_scaling_may_exceed_reference",
        "census_receipt_required_before_parity_claim",
        "workload_oracle_required_before_workload_claim",
        "sovereign_extensions_must_be_declared",
        "provider_independent_profile_ids",
        "placement_must_match_environment_and_capabilities",
    ):
        if policy[key] is not True:
            raise RegistryError(f"policy {key} must be true")

    refs = doc.get("gha_references")
    if not isinstance(refs, list) or not refs:
        raise RegistryError("gha_references missing")
    ref_ids = set()
    labels = set()
    for row in refs:
        rid = row.get("id")
        label = row.get("label")
        if not isinstance(rid, str) or not rid:
            raise RegistryError("reference id missing")
        if rid in ref_ids:
            raise RegistryError(f"duplicate reference id {rid}")
        if not isinstance(label, str) or not label:
            raise RegistryError(f"reference {rid}: label missing")
        if label in labels:
            raise RegistryError(f"duplicate GHA label {label}")
        ref_ids.add(rid)
        labels.add(label)

    templates = doc.get("local_templates")
    if not isinstance(templates, list) or not templates:
        raise RegistryError("local_templates missing")
    template_ids = set()
    for row in templates:
        tid = row.get("id")
        if not isinstance(tid, str) or not tid:
            raise RegistryError("template id missing")
        if tid in template_ids:
            raise RegistryError(f"duplicate template id {tid}")
        template_ids.add(tid)
        if row.get("reference") not in ref_ids:
            raise RegistryError(f"{tid}: unknown GHA reference")
        if row.get("environment_class") not in ENV_CLASSES:
            raise RegistryError(f"{tid}: invalid environment_class")
        if row.get("resource_class") not in RESOURCE_CLASSES:
            raise RegistryError(f"{tid}: invalid resource_class")
        if row.get("status") not in STATUSES:
            raise RegistryError(f"{tid}: invalid status")
        substrates = row.get("candidate_substrates")
        deltas = row.get("required_capability_deltas")
        if not isinstance(substrates, list) or not all(isinstance(x, str) and x for x in substrates):
            raise RegistryError(f"{tid}: candidate_substrates invalid")
        if not isinstance(deltas, list) or not all(isinstance(x, str) and x for x in deltas):
            raise RegistryError(f"{tid}: required_capability_deltas invalid")
        if row["environment_class"] == "GHA_PARITY" and deltas:
            raise RegistryError(f"{tid}: GHA_PARITY cannot require sovereign capability deltas")
        if row["environment_class"] == "SOVEREIGN_EXTENSION" and not deltas:
            raise RegistryError(f"{tid}: sovereign extension must declare capability deltas")
        if row["environment_class"] == "REFERENCE_ONLY":
            if substrates or row["resource_class"] != "CLOUD_ONLY" or row["status"] != "NOT_LOCAL_MATERIALIZABLE":
                raise RegistryError(f"{tid}: REFERENCE_ONLY must be cloud-only and non-materializable")

    rungs = doc.get("qualification_rungs")
    if not isinstance(rungs, dict) or set(rungs) != {"P0","P1","P2","P3","P4","P5","S1"}:
        raise RegistryError("qualification_rungs must define exactly P0-P5 and S1")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--registry", type=pathlib.Path, default=pathlib.Path("config/runner-environment-profiles.json"))
    args = p.parse_args()
    doc = load(args.registry)
    print(json.dumps({
        "schema": doc["schema"],
        "gha_reference_count": len(doc["gha_references"]),
        "local_template_count": len(doc["local_templates"]),
        "status": "VALID"
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
