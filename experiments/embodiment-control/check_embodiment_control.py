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



    # Provider lifecycle reconciliation is separate from provider effect ACK.
    lifecycle = EmbodimentControl()
    materialize(lifecycle)
    lifecycle_effect = lifecycle.request_effect(
        caller(),
        effect_id="effect-lifecycle",
        intent_id="intent-a1",
        kind="materialize",
        actuator_id="agent-dispatch:public-gha",
        now=NOW,
    )
    assert lifecycle_effect["state"] == "REQUESTED"
    lifecycle.fabric.admit("body-a1")
    lifecycle.fabric.dispatch("body-a1")

    running_reconcile = lifecycle.reconcile_provider_observation(
        caller(),
        effect_id="effect-lifecycle",
        provider_runtime_observed=True,
        provider_present_now=True,
        provider_exit_observed=False,
        now=NOW + timedelta(seconds=5),
    )
    assert running_reconcile["transitions"] == ["provider_start_ack"]
    assert running_reconcile["instance"]["state"] == "MATERIALIZED"
    assert running_reconcile["instance"]["provider_present"] is True

    terminal_reconcile = lifecycle.reconcile_provider_observation(
        caller(),
        effect_id="effect-lifecycle",
        provider_runtime_observed=False,
        provider_present_now=False,
        provider_exit_observed=True,
        now=NOW + timedelta(seconds=6),
    )
    assert terminal_reconcile["transitions"] == ["provider_exit"]
    assert terminal_reconcile["instance"]["state"] == "DEMATERIALIZING"
    assert terminal_reconcile["instance"]["provider_present"] is False
    assert terminal_reconcile["provider_observation_is_work_acceptance"] is False

    # Terminal-first without strong runtime proof fails closed as BLOCKED.
    terminal_first = EmbodimentControl()
    terminal_first.request_materialize(
        caller(),
        authority(),
        intent_id="intent-terminal-first",
        actor_id="actor-a",
        body_instance_id="body-terminal-first",
        resource="workcell:alpha",
        capability_class="gha-public-workcell",
        capabilities={"build"},
        now=NOW,
    )
    terminal_first.request_effect(
        caller(),
        effect_id="effect-terminal-first",
        intent_id="intent-terminal-first",
        kind="materialize",
        actuator_id="agent-dispatch:public-gha",
        now=NOW,
    )
    terminal_first.fabric.admit("body-terminal-first")
    terminal_first.fabric.dispatch("body-terminal-first")
    blocked_terminal = terminal_first.reconcile_provider_observation(
        caller(),
        effect_id="effect-terminal-first",
        provider_runtime_observed=False,
        provider_present_now=False,
        provider_exit_observed=True,
        now=NOW + timedelta(seconds=7),
    )
    assert blocked_terminal["transitions"] == ["block_unconfirmed_materialization"]
    assert blocked_terminal["instance"]["state"] == "BLOCKED"
    assert blocked_terminal["instance"]["provider_present"] is False

    # Strong independent runtime-start evidence still permits terminal-first start+exit.
    strong = EmbodimentControl()
    strong.request_materialize(
        caller(),
        authority(),
        intent_id="intent-terminal-strong",
        actor_id="actor-a",
        body_instance_id="body-terminal-strong",
        resource="workcell:alpha",
        capability_class="gha-public-workcell",
        capabilities={"build"},
        now=NOW,
    )
    strong.request_effect(
        caller(),
        effect_id="effect-terminal-strong",
        intent_id="intent-terminal-strong",
        kind="materialize",
        actuator_id="agent-dispatch:public-gha",
        now=NOW,
    )
    strong.fabric.admit("body-terminal-strong")
    strong.fabric.dispatch("body-terminal-strong")
    collapsed = strong.reconcile_provider_observation(
        caller(),
        effect_id="effect-terminal-strong",
        provider_runtime_observed=True,
        provider_present_now=False,
        provider_exit_observed=True,
        now=NOW + timedelta(seconds=7),
    )
    assert collapsed["transitions"] == ["provider_start_ack", "provider_exit"]
    assert collapsed["instance"]["state"] == "DEMATERIALIZING"



    # Stop-during-start + terminal-first observation must clear late provider residue.
    stopped = EmbodimentControl()
    stopped.request_materialize(
        caller(),
        authority(),
        intent_id="intent-stopped",
        actor_id="actor-a",
        body_instance_id="body-stopped",
        resource="workcell:alpha",
        capability_class="gha-public-workcell",
        capabilities={"build"},
        now=NOW,
    )
    stopped.request_effect(
        caller(),
        effect_id="effect-stopped",
        intent_id="intent-stopped",
        kind="materialize",
        actuator_id="agent-dispatch:public-gha",
        now=NOW,
    )
    stopped.fabric.admit("body-stopped")
    stopped.fabric.dispatch("body-stopped")
    stopped.fabric.request_stop("body-stopped")
    stopped_result = stopped.reconcile_provider_observation(
        caller(),
        effect_id="effect-stopped",
        provider_runtime_observed=False,
        provider_present_now=False,
        provider_exit_observed=True,
        now=NOW + timedelta(seconds=8),
    )
    assert stopped_result["transitions"] == ["settle_provider_absent"]
    assert stopped_result["instance"]["state"] == "DEMATERIALIZING"
    assert stopped_result["instance"]["provider_present"] is False

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
