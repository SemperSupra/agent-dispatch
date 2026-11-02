#!/usr/bin/env python3
"""Dependency-free check for Colab embodiment planning boundary."""

from colab_embodiment_actuator import (
    COLAB_ENTERPRISE,
    CONSUMER_COLAB,
    plan_colab_materialization,
)


def main():
    consumer = plan_colab_materialization(CONSUMER_COLAB)
    assert consumer["classification"] == "BLOCKED"
    assert consumer["reason"] == "human_provider_activation_required"
    assert consumer["fabric_transition"] == "ADMITTED->BLOCKED"
    assert consumer["provider_runtime_created"] is False
    assert consumer["enterprise_fallback_implicit"] is False

    enterprise = plan_colab_materialization(COLAB_ENTERPRISE)
    assert enterprise["classification"] == "NOT_QUALIFIED"
    assert enterprise["provider_materialization_actuator_qualified"] is False
    assert set(enterprise["candidate_lifecycle_operations"]) == {
        "create", "start", "stop", "delete"
    }
    assert enterprise["consumer_colab_equivalence_claimed"] is False

    print("colab embodiment planning boundary: PASS")


if __name__ == "__main__":
    main()
