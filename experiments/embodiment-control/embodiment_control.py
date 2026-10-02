#!/usr/bin/env python3
"""Provider-neutral embodiment control contract.

This module projects bounded desired-state embodiment operations onto the
verified executable semantics in embodiment_semantics.py.

It intentionally does not implement durable work/task authority, provider
scheduling, arbitrary remote command execution, or application-data transport.
Durable authority is supplied as a verified external projection and GitHub /
Agent Dispatch remain the owning DLE.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from fnmatch import fnmatchcase
from typing import Any, Iterable, Literal

from embodiment_semantics import (
    ACTIVE_STATES,
    BodyRecord,
    BodyState,
    EmbodimentFabric,
    FabricError,
)

EffectKind = Literal["materialize", "dematerialize"]
EffectAck = Literal["succeeded", "failed", "timeout"]
ReconcileResult = Literal["converged", "retryable", "blocked"]

READ_SCOPE = "embodiments:read"
MATERIALIZE_SCOPE = "embodiments:materialize"
DEMATERIALIZE_SCOPE = "embodiments:dematerialize"
EFFECTS_SCOPE = "embodiment-effects:write"


@dataclass(frozen=True)
class ControlGrant:
    """Short-lived authority for one control surface/principal."""

    principal_id: str
    scopes: frozenset[str]
    resources: frozenset[str]
    expires_at: datetime

    def validate(self, *, now: datetime) -> None:
        _aware(now, "now")
        _aware(self.expires_at, "expires_at")
        if not self.principal_id:
            raise ValueError("principal_id must be non-empty")
        if not self.scopes:
            raise ValueError("control grant requires at least one scope")
        if not self.resources:
            raise ValueError("control grant requires at least one resource")
        if now >= self.expires_at:
            raise PermissionError("control grant expired")

    def allows(self, scope: str, resource: str, *, now: datetime) -> bool:
        self.validate(now=now)
        return scope in self.scopes and _resource_allowed(self.resources, resource)


@dataclass(frozen=True)
class DurableAuthorityGrant:
    """Verified projection of durable DLE authority, not another work database."""

    authority_ref: str
    actor_id: str
    actions: frozenset[str]
    resources: frozenset[str]
    expires_at: datetime
    source: str = "github"

    def validate(self, *, now: datetime) -> None:
        _aware(now, "now")
        _aware(self.expires_at, "expires_at")
        if self.source != "github":
            raise PermissionError("durable authority source must be github")
        if not self.authority_ref.startswith("github:"):
            raise ValueError("authority_ref must be a github durable locator")
        if not self.actor_id:
            raise ValueError("durable authority actor_id must be non-empty")
        if not self.actions:
            raise ValueError("durable authority requires at least one action")
        if not self.resources:
            raise ValueError("durable authority requires at least one resource")
        if now >= self.expires_at:
            raise PermissionError("durable authority expired")

    def allows(self, action: str, resource: str, *, now: datetime) -> bool:
        self.validate(now=now)
        return action in self.actions and _resource_allowed(self.resources, resource)


@dataclass(frozen=True)
class IntentMeta:
    intent_id: str
    operation: Literal["materialize", "dematerialize"]
    actor_id: str
    body_instance_id: str
    resource: str
    capability_class: str | None
    authority_ref: str
    requested_by: str
    requested_at: datetime
    reason: str | None = None


@dataclass
class EffectRecord:
    effect_id: str
    intent_id: str
    body_instance_id: str
    resource: str
    kind: EffectKind
    actuator_id: str
    body_generation: int
    actor_generation_at_request: int
    requested_at: datetime
    state: str = "REQUESTED"
    ack_outcome: EffectAck | None = None
    provider_ref: str | None = None
    ack_at: datetime | None = None
    reconciliation: ReconcileResult | None = None
    reconciled_at: datetime | None = None


class EmbodimentControl:
    """Pure provider-neutral control projection over EmbodimentFabric."""

    def __init__(self, fabric: EmbodimentFabric | None = None) -> None:
        self.fabric = fabric or EmbodimentFabric()
        self.intent_meta: dict[str, IntentMeta] = {}
        self.body_resources: dict[str, str] = {}
        self.capability_classes: dict[str, str] = {}
        self.effects: dict[str, EffectRecord] = {}

    def request_materialize(
        self,
        caller: ControlGrant,
        authority: DurableAuthorityGrant,
        *,
        intent_id: str,
        actor_id: str,
        body_instance_id: str,
        resource: str,
        capability_class: str,
        capabilities: Iterable[str] = (),
        parent_body_id: str | None = None,
        lifecycle_coupling: str = "independent",
        now: datetime,
    ) -> dict[str, Any]:
        _aware(now, "now")
        _nonempty(
            intent_id=intent_id,
            actor_id=actor_id,
            body_instance_id=body_instance_id,
            resource=resource,
            capability_class=capability_class,
        )
        self._authorize(
            caller,
            authority,
            scope=MATERIALIZE_SCOPE,
            action="materialize",
            actor_id=actor_id,
            resource=resource,
            now=now,
        )

        requested = IntentMeta(
            intent_id=intent_id,
            operation="materialize",
            actor_id=actor_id,
            body_instance_id=body_instance_id,
            resource=resource,
            capability_class=capability_class,
            authority_ref=authority.authority_ref,
            requested_by=caller.principal_id,
            requested_at=now,
        )
        existing = self.intent_meta.get(intent_id)
        if existing is not None:
            if not _same_intent_payload(existing, requested):
                raise FabricError("control intent idempotency collision")
            return self._intent_receipt(existing)

        if actor_id not in self.fabric.actors:
            self.fabric.add_actor(actor_id)

        body = self.fabric.request_start(
            actor_id=actor_id,
            body_id=body_instance_id,
            intent_id=intent_id,
            authority_ref=authority.authority_ref,
            capabilities=capabilities,
            parent_body_id=parent_body_id,
            lifecycle_coupling=lifecycle_coupling,
        )
        self.intent_meta[intent_id] = requested
        self.body_resources[body_instance_id] = resource
        self.capability_classes[body_instance_id] = capability_class
        return self._intent_receipt(requested, body=body)

    def request_dematerialize(
        self,
        caller: ControlGrant,
        authority: DurableAuthorityGrant,
        *,
        intent_id: str,
        body_instance_id: str,
        reason: str,
        now: datetime,
    ) -> dict[str, Any]:
        _aware(now, "now")
        _nonempty(intent_id=intent_id, body_instance_id=body_instance_id, reason=reason)
        body = self.fabric.body(body_instance_id)
        if body.actor_id is None:
            raise FabricError("body is not assigned to an actor")
        resource = self._resource_for(body_instance_id)
        self._authorize(
            caller,
            authority,
            scope=DEMATERIALIZE_SCOPE,
            action="dematerialize",
            actor_id=body.actor_id,
            resource=resource,
            now=now,
        )

        requested = IntentMeta(
            intent_id=intent_id,
            operation="dematerialize",
            actor_id=body.actor_id,
            body_instance_id=body_instance_id,
            resource=resource,
            capability_class=self.capability_classes.get(body_instance_id),
            authority_ref=authority.authority_ref,
            requested_by=caller.principal_id,
            requested_at=now,
            reason=reason,
        )
        existing = self.intent_meta.get(intent_id)
        if existing is not None:
            if not _same_intent_payload(existing, requested):
                raise FabricError("control intent idempotency collision")
            return self._intent_receipt(existing)

        if body.state in ACTIVE_STATES:
            self.fabric.request_stop(body_instance_id)
        elif body.state not in {
            BodyState.DRAINING,
            BodyState.DEMATERIALIZING,
            BodyState.DEMATERIALIZED,
            BodyState.EXPIRED,
            BodyState.BLOCKED,
            BodyState.REJECTED,
            BodyState.FAILED_TERMINAL,
        }:
            raise FabricError("body cannot converge to absent from current state")

        self.intent_meta[intent_id] = requested
        return self._intent_receipt(requested, body=body)

    def get_intent(
        self,
        caller: ControlGrant,
        *,
        intent_id: str,
        now: datetime,
    ) -> dict[str, Any]:
        meta = self._intent(intent_id)
        self._authorize_read(caller, meta.resource, now=now)
        return self._intent_receipt(meta)

    def get_instance(
        self,
        caller: ControlGrant,
        *,
        body_instance_id: str,
        now: datetime,
    ) -> dict[str, Any]:
        resource = self._resource_for(body_instance_id)
        self._authorize_read(caller, resource, now=now)
        return self._instance_view(self.fabric.body(body_instance_id), resource)

    def list_instances(
        self,
        caller: ControlGrant,
        *,
        now: datetime,
    ) -> dict[str, Any]:
        caller.validate(now=now)
        if READ_SCOPE not in caller.scopes:
            raise PermissionError(f"caller lacks {READ_SCOPE}")
        visible = []
        for body_id, resource in self.body_resources.items():
            if _resource_allowed(caller.resources, resource):
                visible.append(self._instance_view(self.fabric.body(body_id), resource))
        visible.sort(key=lambda item: (item["resource"], item["body_instance_id"]))
        return {
            "schema": "embodiment-control-instances/v1",
            "classification": "FILTERED_INSTANCE_VIEW",
            "instances": visible,
            "durable_work_authority": "github",
            "generic_remote_command_admitted": False,
        }

    def request_effect(
        self,
        caller: ControlGrant,
        *,
        effect_id: str,
        intent_id: str,
        kind: EffectKind,
        actuator_id: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Record a typed provider effect request; no command payload is accepted."""

        _aware(now, "now")
        _nonempty(effect_id=effect_id, intent_id=intent_id, actuator_id=actuator_id)
        if kind not in {"materialize", "dematerialize"}:
            raise ValueError("unsupported effect kind")
        meta = self._intent(intent_id)
        if meta.operation != kind:
            raise FabricError("effect kind does not match control intent")
        self._authorize_control_scope(caller, EFFECTS_SCOPE, meta.resource, now=now)

        body = self.fabric.body(meta.body_instance_id)
        actor = self.fabric.actors[meta.actor_id]
        candidate = EffectRecord(
            effect_id=effect_id,
            intent_id=intent_id,
            body_instance_id=meta.body_instance_id,
            resource=meta.resource,
            kind=kind,
            actuator_id=actuator_id,
            body_generation=body.generation,
            actor_generation_at_request=actor.generation,
            requested_at=now,
        )
        existing = self.effects.get(effect_id)
        if existing is not None:
            if not _same_effect_payload(existing, candidate):
                raise FabricError("effect idempotency collision")
            return self._effect_receipt(existing)

        self.effects[effect_id] = candidate
        return self._effect_receipt(candidate)

    def acknowledge_effect(
        self,
        caller: ControlGrant,
        *,
        effect_id: str,
        outcome: EffectAck,
        provider_ref: str | None,
        now: datetime,
    ) -> dict[str, Any]:
        _aware(now, "now")
        effect = self._effect(effect_id)
        self._authorize_control_scope(caller, EFFECTS_SCOPE, effect.resource, now=now)
        if outcome not in {"succeeded", "failed", "timeout"}:
            raise ValueError("unsupported effect acknowledgement")
        if outcome == "succeeded" and not provider_ref:
            raise ValueError("successful provider acknowledgement requires provider_ref")
        if effect.ack_outcome is not None:
            if effect.ack_outcome != outcome or effect.provider_ref != provider_ref:
                raise FabricError("effect acknowledgement collision")
            return self._effect_receipt(effect)
        if effect.state != "REQUESTED":
            raise FabricError("effect acknowledgement is not pending")
        effect.ack_outcome = outcome
        effect.state = {
            "succeeded": "ACK_SUCCEEDED",
            "failed": "ACK_FAILED",
            "timeout": "TIMED_OUT",
        }[outcome]
        effect.provider_ref = provider_ref
        effect.ack_at = now
        return self._effect_receipt(effect)

    def reconcile_effect(
        self,
        caller: ControlGrant,
        *,
        effect_id: str,
        result: ReconcileResult,
        now: datetime,
    ) -> dict[str, Any]:
        _aware(now, "now")
        effect = self._effect(effect_id)
        self._authorize_control_scope(caller, EFFECTS_SCOPE, effect.resource, now=now)
        if result not in {"converged", "retryable", "blocked"}:
            raise ValueError("unsupported reconciliation result")
        if effect.reconciliation is not None:
            if effect.reconciliation != result:
                raise FabricError("effect reconciliation collision")
            return self._effect_receipt(effect)
        if effect.state not in {"ACK_SUCCEEDED", "ACK_FAILED", "TIMED_OUT"}:
            raise FabricError("effect must be acknowledged before reconciliation")
        effect.reconciliation = result
        effect.reconciled_at = now
        effect.state = {
            "converged": "RECONCILED",
            "retryable": "RETRYABLE",
            "blocked": "BLOCKED",
        }[result]
        return self._effect_receipt(effect)

    def _authorize(
        self,
        caller: ControlGrant,
        authority: DurableAuthorityGrant,
        *,
        scope: str,
        action: str,
        actor_id: str,
        resource: str,
        now: datetime,
    ) -> None:
        self._authorize_control_scope(caller, scope, resource, now=now)
        authority.validate(now=now)
        if authority.actor_id != actor_id:
            raise PermissionError("durable authority actor mismatch")
        if not authority.allows(action, resource, now=now):
            raise PermissionError(f"durable authority lacks {action} for resource")

    def _authorize_read(
        self,
        caller: ControlGrant,
        resource: str,
        *,
        now: datetime,
    ) -> None:
        self._authorize_control_scope(caller, READ_SCOPE, resource, now=now)

    @staticmethod
    def _authorize_control_scope(
        caller: ControlGrant,
        scope: str,
        resource: str,
        *,
        now: datetime,
    ) -> None:
        if not caller.allows(scope, resource, now=now):
            raise PermissionError(f"caller lacks {scope} for resource")

    def _intent(self, intent_id: str) -> IntentMeta:
        try:
            return self.intent_meta[intent_id]
        except KeyError as exc:
            raise KeyError("unknown control intent") from exc

    def _effect(self, effect_id: str) -> EffectRecord:
        try:
            return self.effects[effect_id]
        except KeyError as exc:
            raise KeyError("unknown provider effect") from exc

    def _resource_for(self, body_instance_id: str) -> str:
        try:
            return self.body_resources[body_instance_id]
        except KeyError as exc:
            raise KeyError("body has no control resource projection") from exc

    def _intent_receipt(
        self,
        meta: IntentMeta,
        *,
        body: BodyRecord | None = None,
    ) -> dict[str, Any]:
        current = body or self.fabric.body(meta.body_instance_id)
        actor = self.fabric.actors[meta.actor_id]
        return {
            "schema": "embodiment-control-intent/v1",
            "classification": (
                "MATERIALIZATION_REQUESTED"
                if meta.operation == "materialize"
                else "DEMATERIALIZATION_REQUESTED"
            ),
            "intent_id": meta.intent_id,
            "operation": meta.operation,
            "actor_id": meta.actor_id,
            "body_instance_id": meta.body_instance_id,
            "resource": meta.resource,
            "capability_class": meta.capability_class,
            "authority_ref": meta.authority_ref,
            "requested_by": meta.requested_by,
            "requested_at": meta.requested_at.isoformat(),
            "reason": meta.reason,
            "body_state": current.state.value,
            "body_generation": current.generation,
            "actor_generation": actor.generation,
            "desired_presence": "present" if current.desired_present else "absent",
            "durable_work_authority": "github",
            "control_state_is_work_authority": False,
            "provider_effect_is_implicit": False,
            "generic_remote_command_admitted": False,
        }

    def _instance_view(self, body: BodyRecord, resource: str) -> dict[str, Any]:
        actor_generation = (
            self.fabric.actors[body.actor_id].generation
            if body.actor_id is not None
            else None
        )
        return {
            "body_instance_id": body.body_id,
            "actor_id": body.actor_id,
            "resource": resource,
            "capability_class": self.capability_classes.get(body.body_id),
            "state": body.state.value,
            "desired_presence": "present" if body.desired_present else "absent",
            "body_generation": body.generation,
            "actor_generation": actor_generation,
            "current_generation": (
                body.actor_id is not None and body.generation == actor_generation
            ),
            "ready": body.ready,
            "interaction_open": body.interaction_open,
            "effective_affordances": sorted(
                self.fabric.effective_affordances(body.body_id)
            ),
            "authority_ref": body.authority_ref,
        }

    @staticmethod
    def _effect_receipt(effect: EffectRecord) -> dict[str, Any]:
        return {
            "schema": "embodiment-control-effect/v1",
            "classification": "PROVIDER_EFFECT_RECEIPT",
            "effect_id": effect.effect_id,
            "intent_id": effect.intent_id,
            "body_instance_id": effect.body_instance_id,
            "resource": effect.resource,
            "kind": effect.kind,
            "actuator_id": effect.actuator_id,
            "body_generation": effect.body_generation,
            "actor_generation_at_request": effect.actor_generation_at_request,
            "requested_at": effect.requested_at.isoformat(),
            "state": effect.state,
            "ack_outcome": effect.ack_outcome,
            "provider_ref": effect.provider_ref,
            "ack_at": effect.ack_at.isoformat() if effect.ack_at else None,
            "reconciliation": effect.reconciliation,
            "reconciled_at": (
                effect.reconciled_at.isoformat() if effect.reconciled_at else None
            ),
            "provider_ack_is_semantic_truth": False,
            "semantic_reconciliation_required": True,
            "generic_remote_command_admitted": False,
        }


def _same_intent_payload(left: IntentMeta, right: IntentMeta) -> bool:
    return (
        left.intent_id,
        left.operation,
        left.actor_id,
        left.body_instance_id,
        left.resource,
        left.capability_class,
        left.authority_ref,
        left.reason,
    ) == (
        right.intent_id,
        right.operation,
        right.actor_id,
        right.body_instance_id,
        right.resource,
        right.capability_class,
        right.authority_ref,
        right.reason,
    )


def _same_effect_payload(left: EffectRecord, right: EffectRecord) -> bool:
    return (
        left.effect_id,
        left.intent_id,
        left.body_instance_id,
        left.resource,
        left.kind,
        left.actuator_id,
        left.body_generation,
        left.actor_generation_at_request,
    ) == (
        right.effect_id,
        right.intent_id,
        right.body_instance_id,
        right.resource,
        right.kind,
        right.actuator_id,
        right.body_generation,
        right.actor_generation_at_request,
    )


def _resource_allowed(patterns: frozenset[str], resource: str) -> bool:
    return any(
        pattern == "*" or fnmatchcase(resource, pattern)
        for pattern in patterns
    )


def _nonempty(**values: str) -> None:
    for field, value in values.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be non-empty")


def _aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
