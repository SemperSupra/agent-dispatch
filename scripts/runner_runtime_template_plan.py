#!/usr/bin/env python3
"""Derive a bounded T2-T4 replay plan for one sovereign runner-template candidate."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import runner_runtime_template_contract as contract

SCHEMA="semper-supra.runner-runtime-template-plan/v1"

ORACLES={
    "primitive:docker-container-bind":{
        "rung":"T3","kind":"portable-script",
        "command":["python3","scripts/github_runner_primitive.py","--probe","docker-container"],
    },
    "primitive:kvm-vcpu-sudo":{
        "rung":"T3","kind":"portable-script",
        "command":["python3","scripts/github_runner_frontier.py","--probe","kvm-vcpu-nonce"],
    },
    "primitive:rosetta-x86_64":{
        "rung":"T3","kind":"portable-script",
        "command":["python3","scripts/github_runner_primitive.py","--probe","rosetta"],
    },
    "primitive:simulator-boot-service-spawn":{
        "rung":"T3","kind":"portable-script",
        "command":["python3","scripts/github_runner_primitive.py","--probe","simulator-boot"],
    },
    "workload:agent-dispatch-contract-native":{
        "rung":"T4","kind":"portable-script",
        "command":["python3","scripts/runner_runtime_agent_contract.py","--mode","native"],
    },
    "workload:agent-dispatch-contract-docker":{
        "rung":"T4","kind":"portable-script",
        "command":["python3","scripts/runner_runtime_agent_contract.py","--mode","docker"],
    },
    "workload:native-arm64-c-artifact":{
        "rung":"T4","kind":"portable-script",
        "command":["python3","scripts/github_runner_placement_workloads.py","--workload","arm-native-artifact"],
    },
    "workload:android-api35-emulator-setup-boot":{
        "rung":"T4","kind":"portable-script",
        "command":["python3","scripts/github_runner_workload_frontier.py","--workload","android-emulator"],
    },
    "workload:ios-simulator-sdk-compile":{
        "rung":"T4","kind":"portable-script",
        "command":["python3","scripts/github_runner_workload_frontier.py","--workload","ios-sdk-compile"],
    },
}
PLATFORM_PREFIX="platform:"


class PlanError(ValueError):
    pass


def resolve(catalog:dict[str,Any],candidate_id:str)->tuple[dict[str,Any],dict[str,Any],str]:
    candidates=catalog["sovereign_template_candidates"]
    if candidate_id not in candidates:
        raise PlanError(f"unknown candidate: {candidate_id}")
    candidate=candidates[candidate_id]
    base=candidate
    if candidate["classification"]=="SOVEREIGN_ENHANCED":
        base=candidates[candidate["compatible_base"]]
    ref_id=base.get("reference")
    if not ref_id:
        raise PlanError(f"{candidate_id}: compatible base lacks GHA reference")
    return candidate,base,ref_id


def build_plan(catalog:dict[str,Any],candidate_id:str)->dict[str,Any]:
    candidate,base,ref_id=resolve(catalog,candidate_id)
    predicates=catalog["gha_reference_classes"][ref_id]["required_predicates"]
    steps=[{
        "rung":"T2",
        "predicate":"platform-and-architecture-passive-census",
        "kind":"portable-script",
        "command":["python3","scripts/runner_runtime_template_probe.py","--candidate",candidate_id],
        "admission_effect":"none",
    }]
    unresolved=[]
    for predicate in predicates:
        if predicate.startswith(PLATFORM_PREFIX):
            continue
        recipe=ORACLES.get(predicate)
        if recipe is None:
            steps.append({
                "rung":"T3" if predicate.startswith("primitive:") else "T4",
                "predicate":predicate,
                "kind":"external-authority",
                "command":None,
                "admission_effect":"none",
            })
            unresolved.append(predicate)
            continue
        steps.append({
            "rung":recipe["rung"],
            "predicate":predicate,
            "kind":recipe["kind"],
            "command":recipe["command"],
            "admission_effect":"none",
        })
    return {
        "schema":SCHEMA,
        "candidate_id":candidate_id,
        "classification":candidate["classification"],
        "compatible_base":candidate.get("compatible_base",candidate_id),
        "gha_reference":ref_id,
        "runner_agent_version":catalog["runner_agent_reference"]["version"],
        "steps":steps,
        "external_oracles_required":unresolved,
        "t5_lifecycle_required":True,
        "t6_garm_runner_required":True,
        "t7_enhancement_required":candidate["classification"]=="SOVEREIGN_ENHANCED",
        "t8_placement_admission":False,
        "claim_boundary":"This plan selects existing public-safe oracles. Successful steps remain evidence inputs; only a separate reducer may advance the exact candidate rung or placement state."
    }


def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--catalog",type=pathlib.Path,default=pathlib.Path("config/runner-runtime-templates.json"))
    p.add_argument("--candidate",required=True)
    p.add_argument("--out",type=pathlib.Path)
    a=p.parse_args()
    plan=build_plan(contract.load(a.catalog),a.candidate)
    raw=json.dumps(plan,indent=2,sort_keys=True)+"\n"
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(raw,encoding="utf-8")
    print(raw,end="")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
