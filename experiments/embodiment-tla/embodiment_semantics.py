#!/usr/bin/env python3
"""Executable reference semantics for actor embodiment/materialization.

This module is deliberately provider-independent.  It models the operational
state transitions defined by personal-ops#97 and the TLA+ verification artifact.
It is not a scheduler, task database, network controller, or work-authority
source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterable


class FabricError(RuntimeError):
    """A requested semantic transition is not currently admissible."""


class BodyState(StrEnum):
    ABSENT = "ABSENT"
    REQUESTED = "REQUESTED"
    ADMITTED = "ADMITTED"
    MATERIALIZING = "MATERIALIZING"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    MATERIALIZED = "MATERIALIZED"
    REGISTERED = "REGISTERED"
    READY = "READY"
    DEGRADED = "DEGRADED"
    DRAINING = "DRAINING"
    DEMATERIALIZING = "DEMATERIALIZING"
    DEMATERIALIZED = "DEMATERIALIZED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    FAILED_TERMINAL = "FAILED_TERMINAL"
    EXPIRED = "EXPIRED"


ACTIVE_STATES = frozenset(
    {
        BodyState.REQUESTED,
        BodyState.ADMITTED,
        BodyState.MATERIALIZING,
        BodyState.FAILED_RETRYABLE,
        BodyState.MATERIALIZED,
        BodyState.REGISTERED,
        BodyState.READY,
        BodyState.DEGRADED,
    }
)

CLEANUP_STATES = frozenset(
    {
        BodyState.DRAINING,
        BodyState.DEMATERIALIZING,
        BodyState.EXPIRED,
        BodyState.REJECTED,
        BodyState.FAILED_TERMINAL,
        BodyState.BLOCKED,
    }
)

LIVE_STATES = ACTIVE_STATES | frozenset(
    {BodyState.DRAINING, BodyState.DEMATERIALIZING, BodyState.EXPIRED}
)


@dataclass
class ActorRecord:
    actor_id: str
    generation: int = 0
    authority_valid: bool = True


@dataclass
class BodyRecord:
    body_id: str
    actor_id: str | None = None
    generation: int = 0
    state: BodyState = BodyState.ABSENT
    desired_present: bool = False
    provider_present: bool = False
    callback_pending: bool = False
    registered: bool = False
    ready: bool = False
    path_ok: bool = False
    interaction_open: bool = False
    actuation_granted: bool = False
    stop_requested: bool = False
    authority_ref: str | None = None
    parent_body_id: str | None = None
    capabilities: frozenset[str] = frozenset()
    finalizers: set[str] = field(default_factory=set)
    restart_count: int = 0
    cleanup_failures: int = 0


@dataclass(frozen=True)
class IntentRecord:
    intent_id: str
    actor_id: str
    body_id: str
    authority_ref: str
    operation: str


class EmbodimentFabric:
    """Pure desired-state embodiment transition system."""

    def __init__(
        self,
        *,
        max_generation: int = 2**31 - 1,
        max_restarts: int = 1,
    ) -> None:
        if max_generation < 1:
            raise ValueError("max_generation must be positive")
        if max_restarts < 0:
            raise ValueError("max_restarts must be non-negative")
        self.max_generation = max_generation
        self.max_restarts = max_restarts
        self.actors: dict[str, ActorRecord] = {}
        self.bodies: dict[str, BodyRecord] = {}
        self.intents: dict[str, IntentRecord] = {}
        self.controller_up = True

    def add_actor(self, actor_id: str) -> ActorRecord:
        if not actor_id:
            raise ValueError("actor_id must be non-empty")
        return self.actors.setdefault(actor_id, ActorRecord(actor_id=actor_id))

    def body(self, body_id: str) -> BodyRecord:
        try:
            return self.bodies[body_id]
        except KeyError as exc:
            raise FabricError(f"unknown body: {body_id}") from exc

    def request_start(
        self,
        *,
        actor_id: str,
        body_id: str,
        intent_id: str,
        authority_ref: str,
        capabilities: Iterable[str] = (),
        parent_body_id: str | None = None,
    ) -> BodyRecord:
        self._require_controller()
        actor = self._actor(actor_id)
        existing = self._idempotent_intent(
            intent_id=intent_id,
            actor_id=actor_id,
            body_id=body_id,
            authority_ref=authority_ref,
            operation="start",
        )
        if existing is not None:
            return existing
        if not actor.authority_valid:
            raise FabricError("actor authority is revoked")
        if actor.generation >= self.max_generation:
            raise FabricError("actor generation exhausted")
        if any(
            b.actor_id == actor_id
            and b.generation == actor.generation
            and b.state in LIVE_STATES
            for b in self.bodies.values()
        ):
            raise FabricError("actor already has a current live body; use replace")

        body = self.bodies.setdefault(body_id, BodyRecord(body_id=body_id))
        if body.state is not BodyState.ABSENT:
            raise FabricError("body instance identity is immutable and cannot be reused")

        actor.generation += 1
        self._initialize_body(
            body,
            actor=actor,
            authority_ref=authority_ref,
            capabilities=capabilities,
            parent_body_id=parent_body_id,
        )
        self.intents[intent_id] = IntentRecord(
            intent_id, actor_id, body_id, authority_ref, "start"
        )
        self.assert_invariants()
        return body

    def request_replace(
        self,
        *,
        actor_id: str,
        old_body_id: str,
        new_body_id: str,
        intent_id: str,
        authority_ref: str,
        capabilities: Iterable[str] = (),
    ) -> BodyRecord:
        self._require_controller()
        actor = self._actor(actor_id)
        existing = self._idempotent_intent(
            intent_id=intent_id,
            actor_id=actor_id,
            body_id=new_body_id,
            authority_ref=authority_ref,
            operation="replace",
        )
        if existing is not None:
            return existing

        old = self.body(old_body_id)
        if old.actor_id != actor_id or not self._current_generation(old):
            raise FabricError("old body is not the actor's current embodiment")
        if old.state not in {
            BodyState.MATERIALIZED,
            BodyState.REGISTERED,
            BodyState.READY,
            BodyState.DEGRADED,
        }:
            raise FabricError("old body is not replaceable from its current state")
        if not actor.authority_valid:
            raise FabricError("actor authority is revoked")
        if actor.generation >= self.max_generation:
            raise FabricError("actor generation exhausted")

        new = self.bodies.setdefault(new_body_id, BodyRecord(body_id=new_body_id))
        if new.state is not BodyState.ABSENT:
            raise FabricError("body instance identity is immutable and cannot be reused")

        actor.generation += 1
        self._begin_drain(old)
        self._initialize_body(
            new,
            actor=actor,
            authority_ref=authority_ref,
            capabilities=capabilities,
            parent_body_id=old.parent_body_id,
        )
        self.intents[intent_id] = IntentRecord(
            intent_id, actor_id, new_body_id, authority_ref, "replace"
        )
        self.assert_invariants()
        return new

    def admit(self, body_id: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        if body.state is not BodyState.REQUESTED:
            raise FabricError("body is not awaiting admission")
        if not self._authorized_current(body):
            body.state = BodyState.REJECTED
            body.desired_present = False
            body.stop_requested = True
            self._close_interaction(body)
        else:
            body.state = BodyState.ADMITTED
        self.assert_invariants()
        return body

    def dispatch(self, body_id: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        self._require(
            body.state is BodyState.ADMITTED
            and body.desired_present
            and self._authorized_current(body),
            "body is not dispatchable",
        )
        body.state = BodyState.MATERIALIZING
        body.callback_pending = True
        self.assert_invariants()
        return body

    def fail_start(self, body_id: str) -> BodyRecord:
        body = self.body(body_id)
        self._require(
            body.state is BodyState.MATERIALIZING and body.callback_pending,
            "body has no pending materialization",
        )
        if body.restart_count < self.max_restarts:
            body.state = BodyState.FAILED_RETRYABLE
        else:
            body.state = BodyState.FAILED_TERMINAL
            body.desired_present = False
            body.stop_requested = True
            self._close_interaction(body)
        self.assert_invariants()
        return body

    def retry_dispatch(self, body_id: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        self._require(
            body.state is BodyState.FAILED_RETRYABLE
            and body.desired_present
            and body.restart_count < self.max_restarts
            and self._authorized_current(body),
            "body is not retryable",
        )
        body.restart_count += 1
        body.state = BodyState.MATERIALIZING
        body.callback_pending = True
        self.assert_invariants()
        return body

    def provider_start_ack(self, body_id: str) -> BodyRecord:
        body = self.body(body_id)
        self._require(body.callback_pending, "no provider start callback is pending")

        if (
            body.state in {BodyState.MATERIALIZING, BodyState.FAILED_RETRYABLE}
            and body.desired_present
            and self._authorized_current(body)
        ):
            body.provider_present = True
            body.callback_pending = False
            body.state = BodyState.MATERIALIZED
        else:
            # A late provider callback may create residue, but it cannot restore
            # interaction or authority after fencing/stop/revocation.
            body.provider_present = True
            body.callback_pending = False
            body.finalizers.add("provider")
            self._close_interaction(body)
        self.assert_invariants()
        return body

    def register(self, body_id: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        self._require(
            body.state is BodyState.MATERIALIZED
            and body.provider_present
            and body.desired_present
            and self._authorized_current(body),
            "body is not registerable",
        )
        body.registered = True
        body.state = BodyState.REGISTERED
        self.assert_invariants()
        return body

    def record_direct_path(self, body_id: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        self._require(
            body.state in {BodyState.REGISTERED, BodyState.DEGRADED}
            and body.registered
            and body.desired_present
            and self._authorized_current(body),
            "direct-path evidence is not admissible",
        )
        body.path_ok = True
        self.assert_invariants()
        return body

    def attest_readiness(self, body_id: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        self._require(
            body.state in {BodyState.REGISTERED, BodyState.DEGRADED}
            and body.provider_present
            and body.registered
            and body.path_ok
            and body.desired_present
            and self._authorized_current(body),
            "body lacks current independent readiness evidence",
        )
        body.state = BodyState.READY
        body.ready = True
        body.interaction_open = True
        self.assert_invariants()
        return body

    def admit_actuation(self, body_id: str, action: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        self._require(
            action in self.effective_affordances(body_id),
            "requested action is not an effective affordance",
        )
        body.actuation_granted = True
        self.assert_invariants()
        return body

    def lose_path(self, body_id: str) -> BodyRecord:
        body = self.body(body_id)
        self._require(body.state is BodyState.READY, "body is not ready")
        body.state = BodyState.DEGRADED
        body.ready = False
        body.path_ok = False
        self._close_interaction(body)
        self.assert_invariants()
        return body

    def request_stop(self, body_id: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        self._require(body.state in ACTIVE_STATES, "body is not in an active state")
        actor = self._actor_for(body)
        if self._current_generation(body) and actor.generation < self.max_generation:
            actor.generation += 1
        self._begin_drain(body)
        self.assert_invariants()
        return body

    def expire(self, body_id: str) -> BodyRecord:
        """Expire an active embodiment and fence it before cleanup converges."""
        body = self.body(body_id)
        self._require(body.state in ACTIVE_STATES, "body is not in an active state")
        actor = self._actor_for(body)
        if self._current_generation(body) and actor.generation < self.max_generation:
            actor.generation += 1
        body.state = BodyState.EXPIRED
        body.desired_present = False
        body.stop_requested = True
        body.ready = False
        body.path_ok = False
        self._close_interaction(body)
        body.finalizers = self._required_finalizers(body)
        self.assert_invariants()
        return body

    def revoke_authority(self, actor_id: str) -> ActorRecord:
        self._require_controller()
        actor = self._actor(actor_id)
        actor.authority_valid = False
        if actor.generation < self.max_generation:
            actor.generation += 1
        for body in self.bodies.values():
            if body.actor_id == actor_id and body.state in ACTIVE_STATES:
                self._begin_drain(body)
        self.assert_invariants()
        return actor

    def begin_cleanup(self, body_id: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        self._require(
            body.state in {BodyState.DRAINING, BodyState.EXPIRED}
            and not body.provider_present,
            "cleanup cannot begin while provider runtime remains",
        )
        body.state = BodyState.DEMATERIALIZING
        body.finalizers.discard("provider")
        self.assert_invariants()
        return body

    def provider_stop_ack(self, body_id: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        self._require(
            body.state
            in {BodyState.DRAINING, BodyState.EXPIRED, BodyState.DEMATERIALIZING}
            and body.provider_present,
            "provider stop acknowledgement is not applicable",
        )
        body.provider_present = False
        body.state = BodyState.DEMATERIALIZING
        body.finalizers.discard("provider")
        self.assert_invariants()
        return body

    def finalizer_step(self, body_id: str, kind: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        self._require(
            body.state is BodyState.DEMATERIALIZING
            and kind in body.finalizers
            and kind != "provider",
            "finalizer is not pending",
        )
        body.finalizers.remove(kind)
        if kind == "registration":
            body.registered = False
        self.assert_invariants()
        return body

    def finalizer_fail(self, body_id: str) -> BodyRecord:
        """Record one bounded cleanup failure without reopening interaction."""
        self._require_controller()
        body = self.body(body_id)
        self._require(
            body.state is BodyState.DEMATERIALIZING
            and bool(body.finalizers)
            and body.cleanup_failures < self.max_restarts,
            "cleanup failure is not retryable",
        )
        body.cleanup_failures += 1
        self._close_interaction(body)
        self.assert_invariants()
        return body

    def finalizer_exhausted(self, body_id: str) -> BodyRecord:
        """Converge exhausted cleanup to a durable actionable BLOCKED state."""
        self._require_controller()
        body = self.body(body_id)
        self._require(
            body.state is BodyState.DEMATERIALIZING
            and bool(body.finalizers)
            and body.cleanup_failures == self.max_restarts,
            "cleanup retry budget is not exhausted",
        )
        body.state = BodyState.BLOCKED
        self._close_interaction(body)
        self.assert_invariants()
        return body

    def confirm_dematerialized(self, body_id: str) -> BodyRecord:
        self._require_controller()
        body = self.body(body_id)
        self._require(
            body.state is BodyState.DEMATERIALIZING
            and not body.provider_present
            and not body.registered
            and not body.finalizers,
            "required residue remains",
        )
        body.state = BodyState.DEMATERIALIZED
        body.actor_id = None
        body.generation = 0
        body.desired_present = False
        body.callback_pending = False
        body.ready = False
        body.path_ok = False
        body.interaction_open = False
        body.actuation_granted = False
        body.authority_ref = None
        body.parent_body_id = None
        body.capabilities = frozenset()
        self.assert_invariants()
        return body

    def crash_controller(self) -> None:
        self._require(self.controller_up, "controller is already down")
        self.controller_up = False

    def recover_controller(self) -> None:
        self._require(not self.controller_up, "controller is already up")
        self.controller_up = True
        self.assert_invariants()

    def effective_affordances(self, body_id: str) -> frozenset[str]:
        body = self.body(body_id)
        if not (
            body.state is BodyState.READY
            and body.ready
            and body.provider_present
            and body.registered
            and body.path_ok
            and body.interaction_open
            and not body.stop_requested
            and self._authorized_current(body)
        ):
            return frozenset()
        return body.capabilities

    def assert_invariants(self) -> None:
        for body in self.bodies.values():
            if body.actuation_granted and not self.effective_affordances(body.body_id):
                raise AssertionError("actuation granted without effective affordance")
            if (
                body.actor_id is not None
                and not self._current_generation(body)
                and (body.interaction_open or body.actuation_granted)
            ):
                raise AssertionError("stale embodiment generation can interact")
            if body.ready:
                if not (
                    body.state is BodyState.READY
                    and body.provider_present
                    and body.registered
                    and body.path_ok
                    and self._authorized_current(body)
                ):
                    raise AssertionError("READY lacks independent evidence")
            if body.stop_requested and body.actuation_granted:
                raise AssertionError("stopped body can actuate")
            if body.state is BodyState.DEMATERIALIZED:
                if any(
                    (
                        body.actor_id is not None,
                        body.provider_present,
                        body.registered,
                        body.ready,
                        body.interaction_open,
                        body.actuation_granted,
                        bool(body.finalizers),
                    )
                ):
                    raise AssertionError("dematerialized body retains residue")

        for actor in self.actors.values():
            current = [
                body
                for body in self.bodies.values()
                if body.actor_id == actor.actor_id
                and body.generation == actor.generation
                and body.state in LIVE_STATES
            ]
            if len(current) > 1:
                raise AssertionError("multiple current bodies for one actor")

    def _initialize_body(
        self,
        body: BodyRecord,
        *,
        actor: ActorRecord,
        authority_ref: str,
        capabilities: Iterable[str],
        parent_body_id: str | None,
    ) -> None:
        body.actor_id = actor.actor_id
        body.generation = actor.generation
        body.state = BodyState.REQUESTED
        body.desired_present = True
        body.provider_present = False
        body.callback_pending = False
        body.registered = False
        body.ready = False
        body.path_ok = False
        body.interaction_open = False
        body.actuation_granted = False
        body.stop_requested = False
        body.authority_ref = authority_ref
        body.parent_body_id = parent_body_id
        body.capabilities = frozenset(capabilities)
        body.finalizers.clear()
        body.restart_count = 0
        body.cleanup_failures = 0

    def _begin_drain(self, body: BodyRecord) -> None:
        body.state = BodyState.DRAINING
        body.desired_present = False
        body.stop_requested = True
        body.ready = False
        body.path_ok = False
        self._close_interaction(body)
        body.finalizers = self._required_finalizers(body)

    def _required_finalizers(self, body: BodyRecord) -> set[str]:
        result = {"credential"}
        if body.provider_present:
            result.add("provider")
        if body.registered:
            result.add("registration")
        return result

    def _close_interaction(self, body: BodyRecord) -> None:
        body.interaction_open = False
        body.actuation_granted = False

    def _authorized_current(self, body: BodyRecord) -> bool:
        if body.actor_id is None:
            return False
        actor = self._actor(body.actor_id)
        return actor.authority_valid and self._current_generation(body)

    def _current_generation(self, body: BodyRecord) -> bool:
        return (
            body.actor_id is not None
            and body.generation == self._actor(body.actor_id).generation
        )

    def _actor_for(self, body: BodyRecord) -> ActorRecord:
        if body.actor_id is None:
            raise FabricError("body is not assigned to an actor")
        return self._actor(body.actor_id)

    def _actor(self, actor_id: str) -> ActorRecord:
        try:
            return self.actors[actor_id]
        except KeyError as exc:
            raise FabricError(f"unknown actor: {actor_id}") from exc

    def _idempotent_intent(
        self,
        *,
        intent_id: str,
        actor_id: str,
        body_id: str,
        authority_ref: str,
        operation: str,
    ) -> BodyRecord | None:
        existing = self.intents.get(intent_id)
        if existing is None:
            return None
        if existing != IntentRecord(
            intent_id, actor_id, body_id, authority_ref, operation
        ):
            raise FabricError("idempotency key collision")
        return self.body(existing.body_id)

    def _require_controller(self) -> None:
        self._require(self.controller_up, "controller is unavailable")

    @staticmethod
    def _require(condition: bool, message: str) -> None:
        if not condition:
            raise FabricError(message)
