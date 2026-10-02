#!/usr/bin/env python3
"""Dependency-free public-safe checks for embodiment_semantics.py."""

from embodiment_semantics import BodyState, EmbodimentFabric, FabricError


def ready(fabric, body="body-a1", intent="intent-a1"):
    fabric.request_start(
        actor_id="actor-a",
        body_id=body,
        intent_id=intent,
        authority_ref="github:public-safe-authority",
        capabilities={"mcp", "build"},
    )
    fabric.admit(body)
    fabric.dispatch(body)
    fabric.provider_start_ack(body)
    fabric.register(body)
    fabric.record_direct_path(body)
    fabric.attest_readiness(body)


def expect_error(fn, contains):
    try:
        fn()
    except FabricError as exc:
        assert contains in str(exc)
    else:
        raise AssertionError(f"expected FabricError containing {contains!r}")


def main():
    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    first = f.request_start(
        actor_id="actor-a",
        body_id="body-a1",
        intent_id="intent-a1",
        authority_ref="github:public-safe-authority",
        capabilities={"mcp"},
    )
    generation = f.actors["actor-a"].generation
    again = f.request_start(
        actor_id="actor-a",
        body_id="body-a1",
        intent_id="intent-a1",
        authority_ref="github:public-safe-authority",
        capabilities={"mcp"},
    )
    assert again is first
    assert f.actors["actor-a"].generation == generation
    expect_error(
        lambda: f.request_start(
            actor_id="actor-a",
            body_id="body-other",
            intent_id="intent-a1",
            authority_ref="github:public-safe-authority",
        ),
        "idempotency",
    )

    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    ready(f)
    assert f.effective_affordances("body-a1") == {"mcp", "build"}
    assert not f.body("body-a1").actuation_granted
    f.admit_actuation("body-a1", "mcp")
    expect_error(lambda: f.admit_actuation("body-a1", "gpu"), "effective affordance")

    old_generation = f.body("body-a1").generation
    new = f.request_replace(
        actor_id="actor-a",
        old_body_id="body-a1",
        new_body_id="body-a2",
        intent_id="replace-a2",
        authority_ref="github:public-safe-authority",
        capabilities={"mcp"},
    )
    old = f.body("body-a1")
    assert new.generation > old_generation
    assert old.state is BodyState.DRAINING
    assert not old.interaction_open
    assert not old.actuation_granted
    assert not f.effective_affordances("body-a1")

    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    f.request_start(
        actor_id="actor-a",
        body_id="body-a1",
        intent_id="intent-a1",
        authority_ref="github:public-safe-authority",
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

    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    ready(f)
    f.admit_actuation("body-a1", "mcp")
    body = f.lose_path("body-a1")
    assert body.state is BodyState.DEGRADED
    assert not body.interaction_open
    assert not body.actuation_granted
    assert not f.effective_affordances("body-a1")

    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    ready(f)
    f.admit_actuation("body-a1", "mcp")
    prior_generation = f.actors["actor-a"].generation
    body = f.expire("body-a1")
    assert body.state is BodyState.EXPIRED
    assert f.actors["actor-a"].generation > prior_generation
    assert not body.interaction_open
    assert not body.actuation_granted

    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    ready(f)
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
    ready(f)
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
            intent_id="intent-reuse",
            authority_ref="github:public-safe-authority",
            capabilities={"mcp"},
        ),
        "immutable",
    )

    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    f.request_start(
        actor_id="actor-a",
        body_id="body-a1",
        intent_id="intent-a1",
        authority_ref="github:public-safe-authority",
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

    print("embodiment executable semantics: PASS")


if __name__ == "__main__":
    main()
