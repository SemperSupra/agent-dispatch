#!/usr/bin/env python3
"""Dependency-free public-safe checks for embodiment_control.py."""

from datetime import datetime, timedelta, timezone

from embodiment_control import (
    ControlGrant,
    DurableAuthorityGrant,
    EmbodimentControl,
)
from embodiment_semantics import BodyState, FabricError

NOW = datetime(2026, 10, 2, 20, 0, tzinfo=timezone.utc)


def caller(*resources, scopes=None):
    return ControlGrant(
        principal_id="surface:test",
        scopes=scopes
        or frozenset(
            {
                "embodiments:read",
                "embodiments:materialize",
                "embodiments:dematerialize",
                "embodiment-effects:write",
            }
        ),
        resources=frozenset(resources or {"workcell:*"}),
        expires_at=NOW + timedelta(hours=1),
    )


def authority(
    actor_id="actor-a",
    *,
    resources=frozenset({"workcell:*"}),
    actions=frozenset({"materialize", "dematerialize"}),
):
    return DurableAuthorityGrant(
        authority_ref="github:public-safe-authority",
        actor_id=actor_id,
        actions=actions,
        resources=resources,
        expires_at=NOW + timedelta(hours=1),
    )


def materialize(control, *, now=NOW):
    return control.request_materialize(
        caller(),
        authority(),
        intent_id="intent-a1",
        actor_id="actor-a",
        body_instance_id="body-a1",
        resource="workcell:alpha",
        capability_class="gha-public-workcell",
        capabilities={"mcp", "build"},
        now=now,
    )


def expect(exc_type, fragment, fn):
    try:
        fn()
    except exc_type as exc:
        assert fragment in str(exc), (fragment, str(exc))
    else:
        raise AssertionError(f"expected {exc_type.__name__}: {fragment}")


def main():
    control = EmbodimentControl()

    expect(
        PermissionError,
        "embodiments:materialize",
        lambda: control.request_materialize(
            caller(scopes=frozenset({"embodiments:read"})),
            authority(),
            intent_id="deny-control",
            actor_id="actor-a",
            body_instance_id="body-deny-control",
            resource="workcell:alpha",
            capability_class="gha-public-workcell",
            now=NOW,
        ),
    )

    expect(
        PermissionError,
        "durable authority lacks",
        lambda: control.request_materialize(
            caller(),
            authority(actions=frozenset({"dematerialize"})),
            intent_id="deny-authority",
            actor_id="actor-a",
            body_instance_id="body-deny-authority",
            resource="workcell:alpha",
            capability_class="gha-public-workcell",
            now=NOW,
        ),
    )

    first = materialize(control)
    second = materialize(control, now=NOW + timedelta(seconds=30))
    assert first == second
    assert first["body_state"] == "REQUESTED"
    assert first["generic_remote_command_admitted"] is False
    assert first["provider_effect_is_implicit"] is False

    expect(
        FabricError,
        "idempotency collision",
        lambda: control.request_materialize(
            caller(),
            authority(),
            intent_id="intent-a1",
            actor_id="actor-a",
            body_instance_id="different-body",
            resource="workcell:alpha",
            capability_class="gha-public-workcell",
            now=NOW + timedelta(seconds=31),
        ),
    )

    expect(
        PermissionError,
        "embodiments:read",
        lambda: control.get_instance(
            caller("workcell:beta"),
            body_instance_id="body-a1",
            now=NOW,
        ),
    )

    effect = control.request_effect(
        caller(),
        effect_id="effect-a1",
        intent_id="intent-a1",
        kind="materialize",
        actuator_id="agent-dispatch:public-gha",
        now=NOW,
    )
    assert effect["body_generation"] == first["body_generation"]
    assert effect["generic_remote_command_admitted"] is False

    expect(
        FabricError,
        "does not match",
        lambda: control.request_effect(
            caller(),
            effect_id="effect-wrong-kind",
            intent_id="intent-a1",
            kind="dematerialize",
            actuator_id="agent-dispatch:public-gha",
            now=NOW,
        ),
    )

    expect(
        ValueError,
        "unsupported effect kind",
        lambda: control.request_effect(
            caller(),
            effect_id="effect-command",
            intent_id="intent-a1",
            kind="command",
            actuator_id="agent-dispatch:public-gha",
            now=NOW,
        ),
    )

    ack = control.acknowledge_effect(
        caller(),
        effect_id="effect-a1",
        outcome="succeeded",
        provider_ref="github-actions:run:123",
        now=NOW + timedelta(seconds=1),
    )
    assert ack["state"] == "ACK_SUCCEEDED"
    assert ack["provider_ack_is_semantic_truth"] is False

    duplicate_ack = control.acknowledge_effect(
        caller(),
        effect_id="effect-a1",
        outcome="succeeded",
        provider_ref="github-actions:run:123",
        now=NOW + timedelta(seconds=2),
    )
    assert duplicate_ack["ack_outcome"] == "succeeded"

    reconciled = control.reconcile_effect(
        caller(),
        effect_id="effect-a1",
        result="converged",
        now=NOW + timedelta(seconds=3),
    )
    assert reconciled["state"] == "RECONCILED"

    duplicate_reconcile = control.reconcile_effect(
        caller(),
        effect_id="effect-a1",
        result="converged",
        now=NOW + timedelta(seconds=4),
    )
    assert duplicate_reconcile["state"] == "RECONCILED"

    fabric = control.fabric
    fabric.admit("body-a1")
    fabric.dispatch("body-a1")
    fabric.provider_start_ack("body-a1")
    fabric.register("body-a1")
    fabric.record_direct_path("body-a1")
    fabric.record_interaction_binding("body-a1", "direct-p2p")
    fabric.attest_readiness("body-a1")
    ready_view = control.get_instance(
        caller("workcell:alpha"),
        body_instance_id="body-a1",
        now=NOW,
    )
    assert ready_view["interaction_binding"] == "direct-p2p"
    assert ready_view["interaction_open"] is True

    stop1 = control.request_dematerialize(
        caller(),
        authority(),
        intent_id="stop-a1",
        body_instance_id="body-a1",
        reason="work complete",
        now=NOW + timedelta(minutes=1),
    )
    stop2 = control.request_dematerialize(
        caller(),
        authority(),
        intent_id="stop-a1",
        body_instance_id="body-a1",
        reason="work complete",
        now=NOW + timedelta(minutes=2),
    )
    assert stop1 == stop2
    assert fabric.body("body-a1").state is BodyState.DRAINING
    assert stop1["desired_presence"] == "absent"

    expired = ControlGrant(
        principal_id="surface:test",
        scopes=frozenset({"embodiments:read"}),
        resources=frozenset({"*"}),
        expires_at=NOW,
    )
    expect(
        PermissionError,
        "expired",
        lambda: control.get_instance(
            expired,
            body_instance_id="body-a1",
            now=NOW,
        ),
    )

    print("embodiment control contract: PASS")


if __name__ == "__main__":
    main()
