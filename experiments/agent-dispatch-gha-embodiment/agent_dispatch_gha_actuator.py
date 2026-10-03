#!/usr/bin/env python3
"""Agent Dispatch Sidecar adapter contract for public GitHub Actions embodiment.

The adapter maps one typed E3 materialization effect onto the existing Sidecar
plan_execution -> dispatch_execution -> observe_execution surface.

It does not create a scheduler, queue, workflow-input template engine, or new
work-authority plane.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any


@dataclass(frozen=True)
class SidecarAssignmentBinding:
    workset_ref: str
    delegation_id: str
    assignment_id: str

    def validate(self) -> None:
        for field, value in (
            ("workset_ref", self.workset_ref),
            ("delegation_id", self.delegation_id),
            ("assignment_id", self.assignment_id),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be non-empty")


def materialization_call_plan(
    effect_receipt: dict[str, Any],
    binding: SidecarAssignmentBinding,
) -> dict[str, Any]:
    """Return the exact bounded Sidecar call sequence for one materialization effect."""

    binding.validate()
    _materialize_effect(effect_receipt)
    args = {
        "workset_ref": binding.workset_ref,
        "delegation_id": binding.delegation_id,
        "assignment_id": binding.assignment_id,
    }
    return {
        "schema": "agent-dispatch-gha-materialization-plan/v1",
        "classification": "SIDECAR_BINDING_PLAN",
        "effect_id": effect_receipt["effect_id"],
        "body_instance_id": effect_receipt["body_instance_id"],
        "body_generation": effect_receipt["body_generation"],
        "provider_ref": opaque_provider_ref(binding),
        "calls": [
            {
                "operation": "plan_execution",
                "args": args,
                "mutation": False,
            },
            {
                "operation": "dispatch_execution",
                "args": args,
                "mutation": True,
                "precondition": "plan_execution admits the existing assignment binding",
            },
            {
                "operation": "observe_execution",
                "args": args,
                "mutation": False,
                "precondition": "after dispatch or when reconciling ambiguous provider state",
            },
        ],
        "selected_executor_owns_queue": True,
        "arbitrary_workflow_inputs_admitted": False,
        "free_form_prompt_admitted": False,
        "generic_remote_command_admitted": False,
        "new_scheduler_or_queue_required": False,
        "retry_policy": "observe canonical executor state before any redispatch decision",
        "stop_mode": "fence-now-drain-provider-to-terminal",
        "provider_cancel_exposed_by_current_sidecar": False,
        "durable_work_authority": "github",
    }


def normalize_observation(
    observation: dict[str, Any],
    binding: SidecarAssignmentBinding,
) -> dict[str, Any]:
    """Normalize Sidecar observe_execution output into E3 provider-effect evidence."""

    binding.validate()
    assignment = observation.get("assignment")
    if not isinstance(assignment, dict):
        raise ValueError("observation lacks normalized assignment")
    if assignment.get("assignment_id") != binding.assignment_id:
        raise ValueError("observation assignment_id mismatch")

    target = observation.get("binding")
    if not isinstance(target, dict) or target.get("target_kind") != "github-actions":
        raise ValueError("observation is not bound to github-actions")

    runs = observation.get("runs")
    if not isinstance(runs, list):
        raise ValueError("observation runs must be a list")
    if len(runs) > 1:
        return _observation_receipt(
            binding,
            provider_state="BLOCKED_DUPLICATE_EXECUTION",
            effect_ack=None,
            reconciliation="blocked",
            terminal=False,
            run_count=len(runs),
        )
    if not runs:
        return _observation_receipt(
            binding,
            provider_state="AWAITING_EXECUTION",
            effect_ack=None,
            reconciliation=None,
            terminal=False,
            run_count=0,
        )

    run = runs[0]
    if not isinstance(run, dict):
        raise ValueError("run entry must be an object")
    status = str(run.get("status") or "").lower()
    conclusion = run.get("conclusion")
    conclusion = str(conclusion).lower() if conclusion is not None else None

    if status in {"queued", "pending", "requested", "waiting"}:
        return _observation_receipt(
            binding,
            provider_state="QUEUED",
            effect_ack=None,
            reconciliation=None,
            terminal=False,
            run_count=1,
            runtime_started=False,
        )

    if status == "in_progress":
        return _observation_receipt(
            binding,
            provider_state="RUNNING",
            effect_ack=None,
            reconciliation=None,
            terminal=False,
            run_count=1,
            runtime_started=True,
        )

    if status != "completed":
        raise ValueError("unsupported github-actions run status")

    runtime_evidence = observation.get("runtime_evidence")
    runtime_started = (
        isinstance(runtime_evidence, dict)
        and runtime_evidence.get("assignment_id") in {None, binding.assignment_id}
        and runtime_evidence.get("started") is True
        and runtime_evidence.get("source") in {"github-actions-job", "executor"}
        and isinstance(runtime_evidence.get("started_at"), str)
        and bool(runtime_evidence.get("started_at").strip())
    )

    if conclusion == "success":
        return _observation_receipt(
            binding,
            provider_state=(
                "SUCCEEDED" if runtime_started else "SUCCEEDED_UNCONFIRMED_BODY"
            ),
            effect_ack="succeeded",
            reconciliation="converged",
            terminal=True,
            run_count=1,
            runtime_started=runtime_started,
            exit_observed=True,
            exit_outcome="success",
        )

    if conclusion in {
        "failure",
        "cancelled",
        "timed_out",
        "startup_failure",
        "action_required",
        "skipped",
        "stale",
    }:
        return _observation_receipt(
            binding,
            provider_state="FAILED" if runtime_started else "FAILED_UNCONFIRMED_BODY",
            effect_ack="failed",
            reconciliation="blocked",
            terminal=True,
            run_count=1,
            runtime_started=runtime_started,
            exit_observed=True,
            exit_outcome=conclusion,
        )

    raise ValueError("unsupported github-actions terminal conclusion")


def opaque_provider_ref(binding: SidecarAssignmentBinding) -> str:
    """Return a correlation ref that does not reveal private workset/delegation names."""

    binding.validate()
    digest = hashlib.sha256(
        (
            binding.workset_ref
            + "\x00"
            + binding.delegation_id
            + "\x00"
            + binding.assignment_id
        ).encode("utf-8")
    ).hexdigest()[:20]
    return f"agent-dispatch-gha:{digest}"


def _materialize_effect(effect_receipt: dict[str, Any]) -> None:
    if effect_receipt.get("schema") != "embodiment-control-effect/v1":
        raise ValueError("unsupported embodiment effect schema")
    if effect_receipt.get("kind") != "materialize":
        raise ValueError("Sidecar GHA adapter only accepts materialize effects")
    if effect_receipt.get("state") != "REQUESTED":
        raise ValueError("materialization effect must be REQUESTED before dispatch planning")
    if effect_receipt.get("generic_remote_command_admitted") is not False:
        raise ValueError("effect must preserve no-generic-command invariant")
    if not effect_receipt.get("effect_id") or not effect_receipt.get("body_instance_id"):
        raise ValueError("effect identity is incomplete")
    if not isinstance(effect_receipt.get("body_generation"), int):
        raise ValueError("effect body_generation is required")


def _observation_receipt(
    binding: SidecarAssignmentBinding,
    *,
    provider_state: str,
    effect_ack: str | None,
    reconciliation: str | None,
    terminal: bool,
    run_count: int,
    runtime_started: bool = False,
    exit_observed: bool = False,
    exit_outcome: str | None = None,
) -> dict[str, Any]:
    provider_runtime_observed = runtime_started
    provider_exit_observed = terminal and exit_observed
    return {
        "schema": "agent-dispatch-gha-observation/v1",
        "classification": "GHA_EXECUTOR_OBSERVATION",
        "provider_ref": opaque_provider_ref(binding),
        "provider_state": provider_state,
        "effect_ack": effect_ack,
        "reconciliation": reconciliation,
        "terminal": terminal,
        "matching_run_count": run_count,
        "native_execution_observed": run_count == 1,
        "provider_runtime_observed": provider_runtime_observed,
        "provider_present_now": provider_state == "RUNNING" and runtime_started,
        "provider_exit_observed": provider_exit_observed,
        "provider_exit_outcome": exit_outcome if provider_exit_observed else None,
        "selected_executor_owns_queue": True,
        "execution_success_is_durable_work_acceptance": False,
        "execution_success_is_validator_acceptance": False,
        "provider_cancel_exposed_by_current_sidecar": False,
        "stop_mode": "fence-now-drain-provider-to-terminal",
        "raw_workset_ref_projected": False,
        "raw_delegation_id_projected": False,
        "arbitrary_workflow_inputs_admitted": False,
    }
