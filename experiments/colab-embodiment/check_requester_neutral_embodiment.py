#!/usr/bin/env python3
"""Requester-neutral cross-surface embodiment composition checks.

This is source-safe semantic qualification only. It does not claim live ChatGPT
tunnel, Colab provider, or GitHub Actions dispatch authority.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
PUBLIC_ROOT = HERE.parent
for sibling in (
    "agent-dispatch-gha-embodiment",
    "embodiment-control",
    "colab-embodiment",
):
    candidate = PUBLIC_ROOT / sibling
    if candidate.is_dir():
        sys.path.insert(0, str(candidate))

from agent_dispatch_gha_actuator import (
    SidecarAssignmentBinding,
    materialization_call_plan,
)
from colab_embodiment_actuator import (
    CONSUMER_COLAB,
    plan_colab_materialization,
)
from embodiment_control import (
    ControlGrant,
    DurableAuthorityGrant,
    EmbodimentControl,
)
from embodiment_semantics import BodyState

NOW = datetime(2026, 10, 2, 23, 0, tzinfo=timezone.utc)


def caller(principal):
    return ControlGrant(
        principal_id=principal,
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


def authority(actor):
    return DurableAuthorityGrant(
        authority_ref=f"github:synthetic/{actor}",
        actor_id=actor,
        actions=frozenset({"materialize"}),
        resources=frozenset({"workcell:*"}),
        expires_at=NOW + timedelta(hours=1),
    )


def gha_binding(assignment_id):
    return SidecarAssignmentBinding(
        workset_ref="github-file:private/repo@branch:worksets/example.json",
        delegation_id="delegation-private",
        assignment_id=assignment_id,
    )


def request_gha(control, principal, actor, suffix):
    intent_id=f"intent-{suffix}"
    body_id=f"body-{suffix}"
    receipt=control.request_materialize(
        caller(principal),
        authority(actor),
        intent_id=intent_id,
        actor_id=actor,
        body_instance_id=body_id,
        resource="workcell:alpha",
        capability_class="gha-public-workcell",
        capabilities={"build"},
        now=NOW,
    )
    effect=control.request_effect(
        caller(principal),
        effect_id=f"effect-{suffix}",
        intent_id=intent_id,
        kind="materialize",
        actuator_id="agent-dispatch:public-gha",
        now=NOW,
    )
    plan=materialization_call_plan(effect, gha_binding(f"assignment-{suffix}"))
    return receipt, effect, plan


def main():
    # ChatGPT and Colab are merely different principals at this layer.
    for principal, actor, suffix in (
        ("surface:chatgpt-private-mcp", "actor-chatgpt", "chatgpt-gha"),
        ("surface:colab", "actor-colab", "colab-gha"),
    ):
        control=EmbodimentControl()
        receipt, effect, plan=request_gha(control, principal, actor, suffix)
        assert receipt["operation"] == "materialize"
        assert receipt["body_state"] == BodyState.REQUESTED.value
        assert effect["kind"] == "materialize"
        assert plan["body_instance_id"] == receipt["body_instance_id"]
        assert plan["body_generation"] == receipt["body_generation"]
        assert plan["selected_executor_owns_queue"] is True
        assert plan["generic_remote_command_admitted"] is False

    # A GHA-originating principal can request consumer Colab through the same
    # E3 semantic primitive, but the current physical actuator boundary is BLOCKED.
    control=EmbodimentControl()
    receipt=control.request_materialize(
        caller("surface:gha"),
        authority("actor-gha"),
        intent_id="intent-gha-colab",
        actor_id="actor-gha",
        body_instance_id="body-gha-colab",
        resource="workcell:alpha",
        capability_class=CONSUMER_COLAB,
        capabilities={"notebook"},
        now=NOW,
    )
    assert receipt["body_state"] == BodyState.REQUESTED.value
    control.fabric.admit("body-gha-colab")
    plan=plan_colab_materialization(CONSUMER_COLAB)
    assert plan["classification"] == "BLOCKED"
    assert plan["reason"] == "human_provider_activation_required"
    blocked=control.fabric.block_materialization("body-gha-colab")
    assert blocked.state is BodyState.BLOCKED
    assert not blocked.provider_present
    assert not blocked.interaction_open

    # Requester substrate never becomes durable authority.
    assert control.get_intent(
        caller("surface:gha"),
        intent_id="intent-gha-colab",
        now=NOW,
    )["authority_ref"] == "github:synthetic/actor-gha"

    print("requester-neutral cross-surface embodiment: PASS")


if __name__ == "__main__":
    main()
