#!/usr/bin/env python3
"""Dependency-free executable checks for embodiment_semantics.py.

This is the public-safe canonical smoke/conformance checker.  It deliberately
uses only Python assertions and the provider-independent semantic model so the
same bytes can execute in public Agent Dispatch without exposing private data.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from embodiment_semantics import BodyState, EmbodimentFabric, FabricError  # noqa: E402


AUTHORITY = "github:synthetic-authority"


def expect_error(fn, contains: str) -> None:
    try:
        fn()
    except FabricError as exc:
        assert contains in str(exc), (contains, str(exc))
    else:
        raise AssertionError(f"expected FabricError containing {contains!r}")


def ready(
    fabric: EmbodimentFabric,
    *,
    actor_id: str,
    body_id: str,
    intent_id: str,
    parent_body_id: str | None = None,
    capabilities=frozenset({"mcp", "build", "materialize"}),
) -> None:
    fabric.request_start(
        actor_id=actor_id,
        body_id=body_id,
        intent_id=intent_id,
        authority_ref=AUTHORITY,
        capabilities=capabilities,
        parent_body_id=parent_body_id,
    )
    fabric.admit(body_id)
    fabric.dispatch(body_id)
    fabric.provider_start_ack(body_id)
    fabric.register(body_id)
    fabric.record_direct_path(body_id)
    fabric.attest_readiness(body_id)


def check_idempotency() -> None:
    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    first = f.request_start(
        actor_id="actor-a",
        body_id="body-a1",
        intent_id="intent-a1",
        authority_ref=AUTHORITY,
        capabilities={"mcp"},
    )
    generation = f.actors["actor-a"].generation
    again = f.request_start(
        actor_id="actor-a",
        body_id="body-a1",
        intent_id="intent-a1",
        authority_ref=AUTHORITY,
        capabilities={"mcp"},
    )
    assert first is again
    assert f.actors["actor-a"].generation == generation
    expect_error(
        lambda: f.request_start(
            actor_id="actor-a",
            body_id="other",
            intent_id="intent-a1",
            authority_ref=AUTHORITY,
        ),
        "idempotency",
    )
    expect_error(
        lambda: f.request_start(
            actor_id="actor-a",
            body_id="body-a1",
            intent_id="intent-a1",
            authority_ref=AUTHORITY,
            capabilities={"mcp", "materialize"},
        ),
        "idempotency",
    )


def check_affordance_and_replacement_fencing() -> None:
    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    ready(f, actor_id="actor-a", body_id="body-a1", intent_id="intent-a1")
    assert f.effective_affordances("body-a1") == {"mcp", "build", "materialize"}
    assert not f.body("body-a1").actuation_granted
    f.admit_actuation("body-a1", "mcp")
    expect_error(lambda: f.admit_actuation("body-a1", "gpu"), "effective affordance")

    old_generation = f.body("body-a1").generation
    new = f.request_replace(
        actor_id="actor-a",
        old_body_id="body-a1",
        new_body_id="body-a2",
        intent_id="replace-a2",
        authority_ref=AUTHORITY,
        capabilities={"mcp"},
    )
    old = f.body("body-a1")
    assert new.generation > old_generation
    assert old.state is BodyState.DRAINING
    assert not old.interaction_open
    assert not old.actuation_granted
    assert not f.effective_affordances("body-a1")

    old = f.attempt_stale_path_replay("body-a1")
    assert old.stale_evidence_seen
    assert not old.path_ok
    assert not old.interaction_open
    assert not old.actuation_granted


def check_late_provider_callback() -> None:
    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    f.request_start(
        actor_id="actor-a",
        body_id="body-a1",
        intent_id="intent-a1",
        authority_ref=AUTHORITY,
        capabilities={"mcp"},
    )
    f.admit("body-a1")
    f.dispatch("body-a1")
    f.request_stop("body-a1")
    body = f.provider_start_ack("body-a1")
    assert body.state is BodyState.DRAINING
    assert body.provider_present
    assert "provider" in body.finalizers
    assert not body.interaction_open


def check_path_loss_and_expiry() -> None:
    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    ready(f, actor_id="actor-a", body_id="body-a1", intent_id="intent-a1")
    f.admit_actuation("body-a1", "mcp")
    body = f.lose_path("body-a1")
    assert body.state is BodyState.DEGRADED
    assert not body.interaction_open
    assert not body.actuation_granted

    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    ready(f, actor_id="actor-a", body_id="body-a1", intent_id="intent-a1")
    f.admit_actuation("body-a1", "mcp")
    prior = f.actors["actor-a"].generation
    body = f.expire("body-a1")
    assert body.state is BodyState.EXPIRED
    assert f.actors["actor-a"].generation > prior
    assert not body.interaction_open
    assert not body.actuation_granted


def check_teardown_and_immutable_identity() -> None:
    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    ready(f, actor_id="actor-a", body_id="body-a1", intent_id="intent-a1")
    f.request_stop("body-a1")
    f.provider_stop_ack("body-a1")
    body = f.finalizer_fail("body-a1")
    assert body.cleanup_failures == 1
    f.finalizer_exhausted("body-a1")
    assert body.state is BodyState.BLOCKED
    assert body.finalizers
    assert not body.interaction_open

    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    ready(f, actor_id="actor-a", body_id="body-a1", intent_id="intent-a1")
    f.request_stop("body-a1")
    f.provider_stop_ack("body-a1")
    f.finalizer_step("body-a1", "registration")
    f.finalizer_step("body-a1", "credential")
    f.confirm_dematerialized("body-a1")
    body = f.body("body-a1")
    assert body.state is BodyState.DEMATERIALIZED
    assert body.actor_id is None
    expect_error(
        lambda: f.request_start(
            actor_id="actor-a",
            body_id="body-a1",
            intent_id="reuse",
            authority_ref=AUTHORITY,
        ),
        "immutable",
    )


def check_controller_recovery() -> None:
    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    f.request_start(
        actor_id="actor-a",
        body_id="body-a1",
        intent_id="intent-a1",
        authority_ref=AUTHORITY,
        capabilities={"mcp"},
    )
    f.admit("body-a1")
    f.dispatch("body-a1")
    f.crash_controller()
    body = f.provider_start_ack("body-a1")
    assert body.state is BodyState.MATERIALIZED
    expect_error(lambda: f.register("body-a1"), "controller")
    f.recover_controller()
    f.register("body-a1")
    assert body.state is BodyState.REGISTERED


def check_child_graph() -> None:
    f = EmbodimentFabric(max_generation=20, max_restarts=1, max_fanout=1)
    for actor in ("parent", "child", "other"):
        f.add_actor(actor)

    ready(f, actor_id="parent", body_id="parent-body", intent_id="parent-intent")
    expect_error(
        lambda: f.request_start(
            actor_id="child",
            body_id="child-body",
            intent_id="child-before-parent-actuation",
            authority_ref=AUTHORITY,
            parent_body_id="parent-body",
        ),
        "parent body cannot",
    )

    f.admit_actuation("parent-body", "mcp")
    expect_error(
        lambda: f.request_start(
            actor_id="child",
            body_id="child-body",
            intent_id="child-wrong-action",
            authority_ref=AUTHORITY,
            parent_body_id="parent-body",
        ),
        "parent body cannot",
    )

    f.admit_actuation("parent-body", "materialize")
    ready(
        f,
        actor_id="child",
        body_id="child-body",
        intent_id="child-intent",
        parent_body_id="parent-body",
    )
    f.admit_actuation("child-body", "materialize")

    expect_error(
        lambda: f.request_start(
            actor_id="other",
            body_id="other-child",
            intent_id="fanout-overflow",
            authority_ref=AUTHORITY,
            parent_body_id="parent-body",
        ),
        "parent body cannot",
    )
    expect_error(
        lambda: f.request_start(
            actor_id="other",
            body_id="grandchild",
            intent_id="depth-two",
            authority_ref=AUTHORITY,
            parent_body_id="child-body",
        ),
        "parent body cannot",
    )
    expect_error(
        lambda: f.request_replace(
            actor_id="parent",
            old_body_id="parent-body",
            new_body_id="parent-body-2",
            intent_id="replace-parent",
            authority_ref=AUTHORITY,
        ),
        "live children",
    )

    parent_gen = f.actors["parent"].generation
    child_gen = f.actors["child"].generation
    f.request_stop("parent-body")
    parent = f.body("parent-body")
    child = f.body("child-body")
    assert parent.state is BodyState.DRAINING
    assert child.state is BodyState.DRAINING
    assert f.actors["parent"].generation > parent_gen
    assert f.actors["child"].generation > child_gen
    assert not parent.interaction_open
    assert not child.interaction_open
    assert not child.actuation_granted


def main() -> None:
    check_idempotency()
    check_affordance_and_replacement_fencing()
    check_late_provider_callback()
    check_path_loss_and_expiry()
    check_teardown_and_immutable_identity()
    check_controller_recovery()
    check_child_graph()
    print("embodiment executable semantics: PASS")


if __name__ == "__main__":
    main()
