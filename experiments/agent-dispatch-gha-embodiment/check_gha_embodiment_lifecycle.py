#!/usr/bin/env python3
"""Source-safe composition check for E3 embodiment control + E4 GHA adapter."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
PUBLIC_CONTROL = HERE.parent / "embodiment-control"
if PUBLIC_CONTROL.is_dir():
    sys.path.insert(0, str(PUBLIC_CONTROL))

from agent_dispatch_gha_actuator import (
    SidecarAssignmentBinding,
    normalize_observation,
)
from embodiment_control import (
    ControlGrant,
    DurableAuthorityGrant,
    EmbodimentControl,
)
from embodiment_semantics import BodyState

NOW = datetime(2026, 10, 2, 22, 0, tzinfo=timezone.utc)


def caller():
    return ControlGrant(
        principal_id="surface:synthetic",
        scopes=frozenset(
            {
                "embodiments:read",
                "embodiments:materialize",
                "embodiment-effects:write",
            }
        ),
        resources=frozenset({"workcell:*"}),
        expires_at=NOW + timedelta(hours=1),
    )


def authority():
    return DurableAuthorityGrant(
        authority_ref="github:public-safe-authority",
        actor_id="actor-a",
        actions=frozenset({"materialize"}),
        resources=frozenset({"workcell:*"}),
        expires_at=NOW + timedelta(hours=1),
    )


def binding():
    return SidecarAssignmentBinding(
        workset_ref="github-file:private/repo@branch:worksets/example.json",
        delegation_id="delegation-private",
        assignment_id="assignment-001",
    )


def observation(status, conclusion):
    return {
        "assignment": {"assignment_id": "assignment-001"},
        "binding": {"target_kind": "github-actions"},
        "runs": [{"status": status, "conclusion": conclusion}],
    }


def create_dispatched(control, *, intent_id, body_id, effect_id):
    control.request_materialize(
        caller(),
        authority(),
        intent_id=intent_id,
        actor_id="actor-a",
        body_instance_id=body_id,
        resource="workcell:alpha",
        capability_class="gha-public-workcell",
        capabilities={"build"},
        now=NOW,
    )
    control.request_effect(
        caller(),
        effect_id=effect_id,
        intent_id=intent_id,
        kind="materialize",
        actuator_id="agent-dispatch:public-gha",
        now=NOW,
    )
    control.fabric.admit(body_id)
    control.fabric.dispatch(body_id)


def apply(control, effect_id, normalized):
    return control.reconcile_provider_observation(
        caller(),
        effect_id=effect_id,
        provider_runtime_observed=normalized["provider_runtime_observed"],
        provider_present_now=normalized["provider_present_now"],
        provider_exit_observed=normalized["provider_exit_observed"],
        now=NOW,
    )


def main():
    # Normal observed-running -> terminal lifecycle.
    control = EmbodimentControl()
    create_dispatched(
        control,
        intent_id="intent-running",
        body_id="body-running",
        effect_id="effect-running",
    )
    running = normalize_observation(
        observation("in_progress", None),
        binding(),
    )
    r1 = apply(control, "effect-running", running)
    assert r1["transitions"] == ["provider_start_ack"]
    assert r1["instance"]["state"] == BodyState.MATERIALIZED.value
    assert r1["instance"]["provider_present"] is True

    terminal = normalize_observation(
        observation("completed", "success"),
        binding(),
    )
    r2 = apply(control, "effect-running", terminal)
    assert r2["transitions"] == ["provider_exit"]
    assert r2["instance"]["state"] == BodyState.DEMATERIALIZING.value
    assert r2["instance"]["provider_present"] is False
    assert terminal["execution_success_is_durable_work_acceptance"] is False

    # Terminal-first polling must not leave a phantom provider-present body.
    terminal_first = EmbodimentControl()
    create_dispatched(
        terminal_first,
        intent_id="intent-terminal",
        body_id="body-terminal",
        effect_id="effect-terminal",
    )
    collapsed = apply(
        terminal_first,
        "effect-terminal",
        normalize_observation(observation("completed", "success"), binding()),
    )
    assert collapsed["transitions"] == ["provider_start_ack", "provider_exit"]
    assert collapsed["instance"]["state"] == BodyState.DEMATERIALIZING.value
    assert collapsed["instance"]["provider_present"] is False

    # Provider exit fences the old incarnation, allowing fresh embodiment even
    # while old registration/credential cleanup remains.
    fresh = terminal_first.request_materialize(
        caller(),
        authority(),
        intent_id="intent-fresh",
        actor_id="actor-a",
        body_instance_id="body-fresh",
        resource="workcell:alpha",
        capability_class="gha-public-workcell",
        capabilities={"build"},
        now=NOW,
    )
    assert fresh["body_state"] == BodyState.REQUESTED.value
    assert (
        terminal_first.fabric.body("body-terminal").generation
        < terminal_first.fabric.body("body-fresh").generation
    )

    print("GHA embodiment lifecycle composition: PASS")


if __name__ == "__main__":
    main()
