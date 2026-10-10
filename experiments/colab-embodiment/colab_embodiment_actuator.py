#!/usr/bin/env python3
"""Colab embodiment actuator classification.

This is a deterministic planning boundary, not a provider actuator. It keeps
consumer Colab and Colab Enterprise from being conflated.

- consumer Colab: current project path, human/provider activation still required;
- Colab Enterprise: supported provider lifecycle APIs exist, but this project has
  not qualified the Google Cloud authority/cost/runtime-template boundary.

No Google API call is made here.
"""

from __future__ import annotations

from typing import Any

CONSUMER_COLAB = "colab-managed-workcell"
COLAB_ENTERPRISE = "colab-enterprise-workcell"


def plan_colab_materialization(capability_class: str) -> dict[str, Any]:
    if capability_class == CONSUMER_COLAB:
        return {
            "schema": "colab-embodiment-plan/v1",
            "capability_class": capability_class,
            "classification": "BLOCKED",
            "reason": "human_provider_activation_required",
            "provider_materialization_actuator_qualified": False,
            "provider_runtime_created": False,
            "fabric_transition": "ADMITTED->BLOCKED",
            "retry_same_body_instance": False,
            "fresh_body_instance_required_for_later_attempt": True,
            "inside_runtime_lifecycle": "scripts/colab/vscode_remote.py",
            "inside_runtime_identity_boundary": "interactive",
            "generic_remote_command_admitted": False,
            "enterprise_fallback_implicit": False,
        }

    if capability_class == COLAB_ENTERPRISE:
        return {
            "schema": "colab-embodiment-plan/v1",
            "capability_class": capability_class,
            "classification": "NOT_QUALIFIED",
            "reason": "distinct_google_cloud_product_and_authority_boundary",
            "provider_materialization_actuator_qualified": False,
            "provider_runtime_created": False,
            "candidate_provider_surface": "Google Cloud Colab Enterprise notebookRuntimes",
            "candidate_lifecycle_operations": ["create", "start", "stop", "delete"],
            "qualification_required": [
                "explicit Google Cloud project",
                "region",
                "runtime template",
                "IAM permissions",
                "billing/resource budget authority",
                "credential boundary",
                "create/start/stop/delete receipts",
                "zero-residue teardown",
                "registration/readiness integration",
            ],
            "generic_remote_command_admitted": False,
            "consumer_colab_equivalence_claimed": False,
        }

    raise ValueError(f"unsupported Colab capability class: {capability_class}")
