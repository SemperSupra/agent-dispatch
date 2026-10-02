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

    try:
        f.request_start(
            actor_id="actor-a",
            body_id="body-other",
            intent_id="intent-a1",
            authority_ref="github:public-safe-authority",
        )
    except FabricError:
        pass
    else:
        raise AssertionError("idempotency collision was admitted")

    f = EmbodimentFabric(max_generation=20, max_restarts=1)
    f.add_actor("actor-a")
    ready(f)
    assert f.effective_affordances("body-a1") == {"mcp", "build"}
    f.admit_actuation("body-a1", "mcp")
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
    f.request_stop("body-a1")
    body = f.body("body-a1")
    assert body.finalizers == {"provider", "registration", "credential"}
    f.provider_stop_ack("body-a1")
    f.finalizer_step("body-a1", "registration")
    f.finalizer_step("body-a1", "credential")
    f.confirm_dematerialized("body-a1")
    assert body.state is BodyState.DEMATERIALIZED
    assert body.actor_id is None

    print("embodiment executable semantics: PASS")


if __name__ == "__main__":
    main()
