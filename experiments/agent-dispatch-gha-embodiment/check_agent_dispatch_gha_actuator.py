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


def observation(
    status,
    conclusion,
    *,
    strong_runtime_evidence=False,
    legacy_result_started_at=False,
):
    payload = {
        "projection_ref": "opaque-projection",
        "assignment": {"assignment_id": "assignment-001"},
        "binding": {"target_name": "github-actions-proof", "target_kind": "github-actions"},
        "runs": [{"status": status, "conclusion": conclusion}],
    }
    if status == "completed" and legacy_result_started_at:
        # This matches the current Sidecar normalized result shape.  It is
        # intentionally NOT accepted as strong runtime-start evidence because
        # Sidecar currently derives it from workflow_run.created_at.
        payload["result"] = {
            "assignment_id": "assignment-001",
            "status": "completed",
            "started_at": "2026-10-02T20:00:00Z",
            "ended_at": "2026-10-02T20:00:30Z",
        }
    if strong_runtime_evidence:
        payload["runtime_evidence"] = {
            "assignment_id": "assignment-001",
            "started": True,
            "started_at": "2026-10-02T20:00:05Z",
            "source": "github-actions-job",
        }
    return payload


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
    assert plan["generic_remote_command_admitted"] is False
    assert plan["provider_cancel_exposed_by_current_sidecar"] is False

    ref = opaque_provider_ref(b)
    assert b.workset_ref not in ref
    assert b.delegation_id not in ref
    assert b.assignment_id not in ref

    queued = normalize_observation(observation("queued", None), b)
    assert queued["provider_state"] == "QUEUED"
    assert queued["native_execution_observed"] is True
    assert queued["provider_runtime_observed"] is False
    assert queued["provider_present_now"] is False
    assert queued["provider_exit_observed"] is False

    running = normalize_observation(observation("in_progress", None), b)
    assert running["provider_state"] == "RUNNING"
    assert running["effect_ack"] is None
    assert running["provider_runtime_observed"] is True
    assert running["provider_present_now"] is True
    assert running["provider_exit_observed"] is False

    # Current Sidecar terminal result.started_at is run.created_at and therefore
    # cannot prove terminal-first embodiment start.
    current_terminal = normalize_observation(
        observation("completed", "success", legacy_result_started_at=True),
        b,
    )
    assert current_terminal["provider_state"] == "SUCCEEDED_UNCONFIRMED_BODY"
    assert current_terminal["effect_ack"] == "succeeded"
    assert current_terminal["reconciliation"] == "converged"
    assert current_terminal["provider_runtime_observed"] is False
    assert current_terminal["provider_present_now"] is False
    assert current_terminal["provider_exit_observed"] is True
    assert current_terminal["provider_exit_outcome"] == "success"
    assert current_terminal["execution_success_is_durable_work_acceptance"] is False
    assert current_terminal["execution_success_is_validator_acceptance"] is False

    strong_terminal = normalize_observation(
        observation("completed", "success", strong_runtime_evidence=True),
        b,
    )
    assert strong_terminal["provider_state"] == "SUCCEEDED"
    assert strong_terminal["provider_runtime_observed"] is True
    assert strong_terminal["provider_exit_observed"] is True

    failed = normalize_observation(
        observation("completed", "failure", legacy_result_started_at=True),
        b,
    )
    assert failed["provider_state"] == "FAILED_UNCONFIRMED_BODY"
    assert failed["effect_ack"] == "failed"
    assert failed["reconciliation"] == "blocked"
    assert failed["provider_runtime_observed"] is False
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
