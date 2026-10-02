#!/usr/bin/env python3
"""Dependency-free public-safe checks for Agent Dispatch GHA embodiment adapter."""

from agent_dispatch_gha_actuator import (
    SidecarAssignmentBinding,
    materialization_call_plan,
    normalize_observation,
    opaque_provider_ref,
)


def binding():
    return SidecarAssignmentBinding(
        workset_ref="github-file:private/repo@branch:worksets/example.json",
        delegation_id="delegation-private",
        assignment_id="assignment-001",
    )


def effect():
    return {
        "schema": "embodiment-control-effect/v1",
        "effect_id": "effect-001",
        "body_instance_id": "body-001",
        "body_generation": 7,
        "kind": "materialize",
        "state": "REQUESTED",
        "generic_remote_command_admitted": False,
    }


def observation(status, conclusion):
    return {
        "projection_ref": "opaque-projection",
        "assignment": {"assignment_id": "assignment-001"},
        "binding": {"target_name": "github-actions-proof", "target_kind": "github-actions"},
        "runs": [{"status": status, "conclusion": conclusion}],
    }


def expect(exc_type, fragment, fn):
    try:
        fn()
    except exc_type as exc:
        assert fragment in str(exc), (fragment, str(exc))
    else:
        raise AssertionError(f"expected {exc_type.__name__}: {fragment}")


def main():
    b = binding()
    plan = materialization_call_plan(effect(), b)
    assert [item["operation"] for item in plan["calls"]] == [
        "plan_execution",
        "dispatch_execution",
        "observe_execution",
    ]
    assert plan["selected_executor_owns_queue"] is True
    assert plan["new_scheduler_or_queue_required"] is False
    assert plan["arbitrary_workflow_inputs_admitted"] is False
    assert plan["provider_cancel_exposed_by_current_sidecar"] is False

    ref = opaque_provider_ref(b)
    assert b.workset_ref not in ref
    assert b.delegation_id not in ref
    assert b.assignment_id not in ref

    running = normalize_observation(observation("in_progress", None), b)
    assert running["provider_state"] == "RUNNING"
    assert running["effect_ack"] is None
    assert running["provider_runtime_observed"] is True
    assert running["provider_present_now"] is True
    assert running["provider_exit_observed"] is False

    succeeded = normalize_observation(observation("completed", "success"), b)
    assert succeeded["provider_state"] == "SUCCEEDED"
    assert succeeded["effect_ack"] == "succeeded"
    assert succeeded["reconciliation"] == "converged"
    assert succeeded["execution_success_is_durable_work_acceptance"] is False
    assert succeeded["execution_success_is_validator_acceptance"] is False
    assert succeeded["provider_runtime_observed"] is True
    assert succeeded["provider_present_now"] is False
    assert succeeded["provider_exit_observed"] is True
    assert succeeded["provider_exit_outcome"] == "success"

    failed = normalize_observation(observation("completed", "failure"), b)
    assert failed["provider_state"] == "FAILED"
    assert failed["reconciliation"] == "blocked"
    assert failed["provider_runtime_observed"] is True
    assert failed["provider_present_now"] is False
    assert failed["provider_exit_observed"] is True
    assert failed["provider_exit_outcome"] == "failure"

    duplicate = observation("completed", "success")
    duplicate["runs"].append(dict(duplicate["runs"][0]))
    blocked = normalize_observation(duplicate, b)
    assert blocked["provider_state"] == "BLOCKED_DUPLICATE_EXECUTION"

    wrong = effect()
    wrong["kind"] = "dematerialize"
    expect(
        ValueError,
        "only accepts materialize",
        lambda: materialization_call_plan(wrong, b),
    )

    print("agent dispatch GHA embodiment adapter: PASS")


if __name__ == "__main__":
    main()
