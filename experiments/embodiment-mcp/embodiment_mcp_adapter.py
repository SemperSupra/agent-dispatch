#!/usr/bin/env python3
"""Private-MCP projection for the provider-neutral embodiment control API.

This module is transport-independent.  It defines the narrow semantic tool
surface that a private MCP server may expose behind an approved tunnel.  It is
not an MCP transport implementation, provider actuator, scheduler, task
database, or durable authority source.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Any, Callable, Iterable, Mapping

from embodiment_control import (
    ControlGrant,
    DurableAuthorityGrant,
    EmbodimentControl,
)

AuthorityResolver = Callable[
    [str, str, str, str, datetime],
    DurableAuthorityGrant,
]

READ_TOOLS = (
    "embodiment.list_instances",
    "embodiment.get_instance",
    "embodiment.get_intent",
)
WRITE_TOOLS = (
    "embodiment.request",
    "embodiment.release",
)


@dataclass(frozen=True)
class McpToolSpec:
    name: str
    mutating: bool
    purpose: str


class EmbodimentMcpAdapter:
    """Least-authority semantic projection intended for a private MCP boundary."""

    def __init__(
        self,
        *,
        control: EmbodimentControl,
        caller: ControlGrant,
        authority_resolver: AuthorityResolver,
        admitted_capability_classes: Iterable[str],
        writes_enabled: bool = False,
    ) -> None:
        classes = frozenset(
            item.strip()
            for item in admitted_capability_classes
            if isinstance(item, str) and item.strip()
        )
        if not classes:
            raise ValueError("at least one admitted capability class is required")
        self.control = control
        self.caller = caller
        self.authority_resolver = authority_resolver
        self.admitted_capability_classes = classes
        self.writes_enabled = bool(writes_enabled)

    def tool_catalog(self) -> tuple[McpToolSpec, ...]:
        tools = [
            McpToolSpec("embodiment.list_instances", False, "filtered instance discovery"),
            McpToolSpec("embodiment.get_instance", False, "read one visible embodiment"),
            McpToolSpec("embodiment.get_intent", False, "read one visible control intent"),
        ]
        if self.writes_enabled:
            tools.extend(
                [
                    McpToolSpec(
                        "embodiment.request",
                        True,
                        "request bounded embodiment desired-present state",
                    ),
                    McpToolSpec(
                        "embodiment.release",
                        True,
                        "request bounded embodiment desired-absent state",
                    ),
                ]
            )
        return tuple(tools)

    def security_posture(self) -> dict[str, Any]:
        return {
            "schema": "embodiment-mcp-security/v1",
            "private_tunnel_required": True,
            "public_mcp_fallback_admitted": False,
            "caller_identity_bound_server_side": True,
            "durable_authority_source": "github",
            "provider_effect_tools_exposed": False,
            "provider_credentials_exposed": False,
            "network_credentials_exposed": False,
            "generic_remote_command_exposed": False,
            "writes_enabled": self.writes_enabled,
        }

    def call(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | None,
        *,
        now: datetime,
    ) -> dict[str, Any]:
        if not isinstance(tool_name, str) or not tool_name:
            raise ValueError("tool_name must be non-empty")
        args = dict(arguments or {})

        if tool_name == "embodiment.list_instances":
            self._shape(args, required=(), optional=())
            return self.control.list_instances(self.caller, now=now)

        if tool_name == "embodiment.get_instance":
            self._shape(args, required=("body_instance_id",), optional=())
            return self.control.get_instance(
                self.caller,
                body_instance_id=self._text(args, "body_instance_id"),
                now=now,
            )

        if tool_name == "embodiment.get_intent":
            self._shape(args, required=("intent_id",), optional=())
            return self.control.get_intent(
                self.caller,
                intent_id=self._text(args, "intent_id"),
                now=now,
            )

        if tool_name == "embodiment.request":
            self._require_writes()
            self._shape(
                args,
                required=(
                    "intent_id",
                    "authority_ref",
                    "actor_id",
                    "resource",
                    "capability_class",
                ),
                optional=(
                    "capabilities",
                    "parent_body_instance_id",
                    "lifecycle_coupling",
                ),
            )
            capability_class = self._text(args, "capability_class")
            if capability_class not in self.admitted_capability_classes:
                raise PermissionError("capability class is not admitted by this MCP surface")
            intent_id = self._text(args, "intent_id")
            actor_id = self._text(args, "actor_id")
            resource = self._text(args, "resource")
            authority_ref = self._text(args, "authority_ref")
            authority = self._resolve_authority(
                authority_ref,
                actor_id,
                "materialize",
                resource,
                now,
            )
            body_instance_id = self._body_instance_id(
                intent_id=intent_id,
                actor_id=actor_id,
                resource=resource,
                capability_class=capability_class,
            )
            capabilities = self._capabilities(args.get("capabilities", ()))
            parent = args.get("parent_body_instance_id")
            if parent is not None and (not isinstance(parent, str) or not parent.strip()):
                raise ValueError("parent_body_instance_id must be a non-empty string")
            coupling = args.get("lifecycle_coupling", "independent")
            if not isinstance(coupling, str) or not coupling.strip():
                raise ValueError("lifecycle_coupling must be a non-empty string")
            receipt = self.control.request_materialize(
                self.caller,
                authority,
                intent_id=intent_id,
                actor_id=actor_id,
                body_instance_id=body_instance_id,
                resource=resource,
                capability_class=capability_class,
                capabilities=capabilities,
                parent_body_id=parent.strip() if isinstance(parent, str) else None,
                lifecycle_coupling=coupling.strip(),
                now=now,
            )
            return self._safe_receipt(receipt)

        if tool_name == "embodiment.release":
            self._require_writes()
            self._shape(
                args,
                required=(
                    "intent_id",
                    "authority_ref",
                    "body_instance_id",
                    "reason",
                ),
                optional=(),
            )
            body_instance_id = self._text(args, "body_instance_id")
            visible = self.control.get_instance(
                self.caller,
                body_instance_id=body_instance_id,
                now=now,
            )
            actor_id = visible.get("actor_id")
            resource = visible.get("resource")
            if not isinstance(actor_id, str) or not actor_id:
                raise PermissionError("body has no actor identity available to this surface")
            if not isinstance(resource, str) or not resource:
                raise PermissionError("body has no resource projection available to this surface")
            authority_ref = self._text(args, "authority_ref")
            authority = self._resolve_authority(
                authority_ref,
                actor_id,
                "dematerialize",
                resource,
                now,
            )
            receipt = self.control.request_dematerialize(
                self.caller,
                authority,
                intent_id=self._text(args, "intent_id"),
                body_instance_id=body_instance_id,
                reason=self._text(args, "reason"),
                now=now,
            )
            return self._safe_receipt(receipt)

        raise KeyError("tool is not exposed by the embodiment MCP surface")

    def _resolve_authority(
        self,
        authority_ref: str,
        actor_id: str,
        action: str,
        resource: str,
        now: datetime,
    ) -> DurableAuthorityGrant:
        grant = self.authority_resolver(
            authority_ref,
            actor_id,
            action,
            resource,
            now,
        )
        if not isinstance(grant, DurableAuthorityGrant):
            raise TypeError("authority resolver must return DurableAuthorityGrant")
        if grant.authority_ref != authority_ref:
            raise PermissionError("resolved durable authority reference mismatch")
        return grant

    def _require_writes(self) -> None:
        if not self.writes_enabled:
            raise PermissionError("MCP embodiment writes are not enabled")

    @staticmethod
    def _shape(
        args: Mapping[str, Any],
        *,
        required: tuple[str, ...],
        optional: tuple[str, ...],
    ) -> None:
        required_set = set(required)
        allowed = required_set | set(optional)
        missing = sorted(required_set - set(args))
        extra = sorted(set(args) - allowed)
        if missing:
            raise ValueError(f"missing MCP tool arguments: {', '.join(missing)}")
        if extra:
            raise ValueError(f"unexpected MCP tool arguments: {', '.join(extra)}")

    @staticmethod
    def _text(args: Mapping[str, Any], key: str) -> str:
        value = args.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _capabilities(value: Any) -> frozenset[str]:
        if value is None:
            return frozenset()
        if isinstance(value, str):
            raise ValueError("capabilities must be an iterable of strings")
        try:
            items = list(value)
        except TypeError as exc:
            raise ValueError("capabilities must be an iterable of strings") from exc
        normalized: set[str] = set()
        for item in items:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("capabilities must contain non-empty strings")
            normalized.add(item.strip())
        return frozenset(normalized)

    @staticmethod
    def _body_instance_id(
        *,
        intent_id: str,
        actor_id: str,
        resource: str,
        capability_class: str,
    ) -> str:
        material = "\x1f".join(
            (intent_id, actor_id, resource, capability_class)
        ).encode("utf-8")
        return "emb-" + sha256(material).hexdigest()[:24]

    @staticmethod
    def _safe_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
        safe = dict(receipt)
        forbidden = {
            "provider_ref",
            "provider_credentials",
            "network_credentials",
            "workset_ref",
            "delegation_id",
            "generic_command",
            "command",
        }
        leaked = forbidden & set(safe)
        if leaked:
            raise AssertionError(f"unsafe MCP receipt fields: {sorted(leaked)}")
        safe["mcp_projection"] = "private-semantic-control"
        safe["provider_effect_tools_exposed"] = False
        safe["generic_remote_command_admitted"] = False
        return safe
