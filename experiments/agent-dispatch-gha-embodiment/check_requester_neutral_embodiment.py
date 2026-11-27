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
from embodiment_semantics import BodyState, FabricError

NOW = datetime(2026, 10, 2, 23, 0, tzinfo=timezone.utc)


def caller(principal):
    return ControlGrant(
        principal_id=principal,
        scopes=frozenset(
            {
                "embodiments:read",
                "embodiments:materialize",
                "embodiments:dematerialize",
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
        actions=frozenset({"materialize", "dematerialize"}),
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


    # Re-embodiment is actor-stable and substrate-neutral. A GHA body may
    # disappear while GitHub remains the durable authority, after which the
    # same actor can request a fresh Colab body with a new immutable instance
    # and generation. No runtime affordance transfers across the boundary.
    rebody=EmbodimentControl()
    gha_receipt, _, _=request_gha(
        rebody,
        "surface:chatgpt-private-mcp",
        "actor-rebody",
        "rebody-gha",
    )
    old_body=gha_receipt["body_instance_id"]
    rebody.fabric.admit(old_body)
    rebody.fabric.dispatch(old_body)
    rebody.fabric.provider_start_ack(old_body)
    rebody.fabric.register(old_body)
    rebody.fabric.record_interaction_binding(old_body, "github-dle")
    rebody.fabric.attest_readiness(old_body)
    old_view=rebody.get_instance(
        caller("surface:chatgpt-private-mcp"),
        body_instance_id=old_body,
        now=NOW,
    )
    assert old_view["state"] == BodyState.READY.value
    assert old_view["interaction_binding"] == "github-dle"
    assert old_view["authority_ref"] == "github:synthetic/actor-rebody"
    old_generation=old_view["body_generation"]

    rebody.fabric.provider_exit(old_body)
    lost_view=rebody.get_instance(
        caller("surface:chatgpt-private-mcp"),
        body_instance_id=old_body,
        now=NOW,
    )
    assert lost_view["state"] == BodyState.DEMATERIALIZING.value
    assert lost_view["interaction_open"] is False
    assert lost_view["effective_affordances"] == []

    colab_receipt=rebody.request_materialize(
        caller("surface:gha"),
        authority("actor-rebody"),
        intent_id="intent-rebody-colab",
        actor_id="actor-rebody",
        body_instance_id="body-rebody-colab",
        resource="workcell:alpha",
        capability_class=CONSUMER_COLAB,
        capabilities={"notebook"},
        now=NOW,
    )
    assert colab_receipt["authority_ref"] == "github:synthetic/actor-rebody"
    assert colab_receipt["body_generation"] > old_generation
    rebody.fabric.admit("body-rebody-colab")
    rebody_colab_plan=plan_colab_materialization(CONSUMER_COLAB)
    assert rebody_colab_plan["classification"] == "BLOCKED"
    blocked_rebody=rebody.fabric.block_materialization("body-rebody-colab")
    assert blocked_rebody.state is BodyState.BLOCKED
    assert blocked_rebody.interaction_open is False

    # A local authority revocation fences current embodiment and prevents a
    # still-valid external authority reference from silently rematerializing.
    revoked=EmbodimentControl()
    revoked_receipt, _, _=request_gha(
        revoked,
        "surface:colab",
        "actor-revoked",
        "revoked-gha",
    )
    revoked_body=revoked_receipt["body_instance_id"]
    revoked.fabric.admit(revoked_body)
    revoked.fabric.dispatch(revoked_body)
    revoked.fabric.provider_start_ack(revoked_body)
    revoked.fabric.register(revoked_body)
    revoked.fabric.record_interaction_binding(revoked_body, "github-dle")
    revoked.fabric.attest_readiness(revoked_body)
    revoked.fabric.revoke_authority("actor-revoked")
    revoked_view=revoked.get_instance(
        caller("surface:colab"),
        body_instance_id=revoked_body,
        now=NOW,
    )
    assert revoked_view["state"] == BodyState.DRAINING.value
    assert revoked_view["interaction_open"] is False
    assert revoked_view["effective_affordances"] == []
    try:
        revoked.request_materialize(
            caller("surface:colab"),
            authority("actor-revoked"),
            intent_id="intent-revoked-new",
            actor_id="actor-revoked",
            body_instance_id="body-revoked-new",
            resource="workcell:alpha",
            capability_class="gha-public-workcell",
            capabilities={"build"},
            now=NOW,
        )
    except FabricError as exc:
        assert "revoked" in str(exc)
    else:
        raise AssertionError("revoked actor rematerialized")


    # Controller failure is a control-plane failure, not provider truth. A
    # provider start can be observed while the controller is down; admission
    # decisions resume only after recovery, then teardown must converge with
    # zero required residue.
    recovering=EmbodimentControl()
    recovery_receipt, _, _=request_gha(
        recovering,
        "surface:chatgpt-private-mcp",
        "actor-recovery",
        "recovery-gha",
    )
    recovery_body=recovery_receipt["body_instance_id"]
    recovering.fabric.admit(recovery_body)
    recovering.fabric.dispatch(recovery_body)
    recovering.fabric.crash_controller()
    recovering.fabric.provider_start_ack(recovery_body)
    try:
        recovering.fabric.register(recovery_body)
    except FabricError as exc:
        assert "controller" in str(exc)
    else:
        raise AssertionError("controller-down registration was admitted")
    recovering.fabric.recover_controller()
    recovering.fabric.register(recovery_body)
    recovering.fabric.record_interaction_binding(recovery_body, "github-dle")
    recovering.fabric.attest_readiness(recovery_body)
    ready_after_recovery=recovering.get_instance(
        caller("surface:chatgpt-private-mcp"),
        body_instance_id=recovery_body,
        now=NOW,
    )
    assert ready_after_recovery["state"] == BodyState.READY.value
    assert ready_after_recovery["interaction_binding"] == "github-dle"

    stop_receipt=recovering.request_dematerialize(
        caller("surface:chatgpt-private-mcp"),
        authority("actor-recovery"),
        intent_id="intent-recovery-stop",
        body_instance_id=recovery_body,
        reason="bounded work complete",
        now=NOW,
    )
    assert stop_receipt["desired_presence"] == "absent"
    recovering.fabric.provider_exit(recovery_body)
    recovery_state=recovering.fabric.body(recovery_body)
    assert recovery_state.state is BodyState.DEMATERIALIZING
    assert recovery_state.provider_present is False
    assert recovery_state.interaction_open is False
    if "registration" in recovery_state.finalizers:
        recovering.fabric.finalizer_step(recovery_body, "registration")
    if "credential" in recovery_state.finalizers:
        recovering.fabric.finalizer_step(recovery_body, "credential")
    recovering.fabric.confirm_dematerialized(recovery_body)
    recovery_done=recovering.fabric.body(recovery_body)
    assert recovery_done.state is BodyState.DEMATERIALIZED
    assert recovery_done.actor_id is None
    assert recovery_done.finalizers == set()

    print("requester-neutral cross-surface embodiment: PASS")


if __name__ == "__main__":
    main()
