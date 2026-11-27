#!/usr/bin/env python3
"""Dependency-free public-safe checks for the embodiment MCP projection."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
PUBLIC_CONTROL = HERE.parent / "embodiment-control"
if PUBLIC_CONTROL.is_dir():
    sys.path.insert(0, str(PUBLIC_CONTROL))
sys.path.insert(0, str(HERE))

from embodiment_control import ControlGrant, DurableAuthorityGrant, EmbodimentControl
from embodiment_mcp_adapter import EmbodimentMcpAdapter

NOW = datetime(2026, 10, 3, 0, 0, tzinfo=timezone.utc)


def control_grant():
    return ControlGrant(
        principal_id="surface:chatgpt-private-mcp",
        scopes=frozenset(
            {
                "embodiments:read",
                "embodiments:materialize",
                "embodiments:dematerialize",
            }
        ),
        resources=frozenset({"workcell:alpha"}),
        expires_at=NOW + timedelta(hours=1),
    )


def resolver(authority_ref, actor_id, action, resource, now):
    if authority_ref == "github:synthetic/mismatch":
        return DurableAuthorityGrant(
            authority_ref=authority_ref,
            actor_id="other-actor",
            actions=frozenset({"materialize", "dematerialize"}),
            resources=frozenset({"workcell:alpha"}),
            expires_at=NOW + timedelta(hours=1),
        )
    if authority_ref != "github:synthetic/work":
        raise PermissionError("unknown durable authority reference")
    return DurableAuthorityGrant(
        authority_ref=authority_ref,
        actor_id=actor_id,
        actions=frozenset({"materialize", "dematerialize"}),
        resources=frozenset({"workcell:alpha"}),
        expires_at=NOW + timedelta(hours=1),
    )


def expect(exc_type, fragment, fn):
    try:
        fn()
    except exc_type as exc:
        assert fragment in str(exc), (fragment, str(exc))
    else:
        raise AssertionError(f"expected {exc_type.__name__}: {fragment}")


def make_adapter(*, writes):
    return EmbodimentMcpAdapter(
        control=EmbodimentControl(),
        caller=control_grant(),
        authority_resolver=resolver,
        admitted_capability_classes={
            "gha-public-workcell",
            "colab-managed-workcell",
        },
        writes_enabled=writes,
    )


def request_args():
    return {
        "intent_id": "intent-mcp-a1",
        "authority_ref": "github:synthetic/work",
        "actor_id": "actor-a",
        "resource": "workcell:alpha",
        "capability_class": "gha-public-workcell",
        "capabilities": ["build", "github-dle"],
    }


def main():
    readonly = make_adapter(writes=False)
    assert [tool.name for tool in readonly.tool_catalog()] == [
        "embodiment.list_instances",
        "embodiment.get_instance",
        "embodiment.get_intent",
    ]
    posture = readonly.security_posture()
    assert posture["private_tunnel_required"] is True
    assert posture["public_mcp_fallback_admitted"] is False
    assert posture["provider_effect_tools_exposed"] is False
    assert posture["generic_remote_command_exposed"] is False

    expect(
        PermissionError,
        "writes are not enabled",
        lambda: readonly.call("embodiment.request", request_args(), now=NOW),
    )
    expect(
        KeyError,
        "not exposed",
        lambda: readonly.call(
            "embodiment.request_effect",
            {"effect_id": "effect-1", "command": "echo nope"},
            now=NOW,
        ),
    )

    writable = make_adapter(writes=True)
    names = [tool.name for tool in writable.tool_catalog()]
    assert names == [
        "embodiment.list_instances",
        "embodiment.get_instance",
        "embodiment.get_intent",
        "embodiment.request",
        "embodiment.release",
    ]
    assert not any("effect" in name or "command" in name for name in names)

    first = writable.call("embodiment.request", request_args(), now=NOW)
    second = writable.call(
        "embodiment.request",
        request_args(),
        now=NOW + timedelta(seconds=10),
    )
    assert first == second
    assert first["body_instance_id"].startswith("emb-")
    assert first["authority_ref"] == "github:synthetic/work"
    assert first["mcp_projection"] == "private-semantic-control"
    assert first["provider_effect_tools_exposed"] is False
    assert first["generic_remote_command_admitted"] is False
    for secretish in (
        "provider_ref",
        "provider_credentials",
        "network_credentials",
        "workset_ref",
        "delegation_id",
        "command",
    ):
        assert secretish not in first

    body_id = first["body_instance_id"]
    instance = writable.call(
        "embodiment.get_instance",
        {"body_instance_id": body_id},
        now=NOW,
    )
    assert instance["actor_id"] == "actor-a"
    assert instance["resource"] == "workcell:alpha"
    assert instance["capability_class"] == "gha-public-workcell"

    listing = writable.call("embodiment.list_instances", {}, now=NOW)
    assert [item["body_instance_id"] for item in listing["instances"]] == [body_id]

    expect(
        ValueError,
        "unexpected MCP tool arguments",
        lambda: writable.call(
            "embodiment.request",
            {**request_args(), "command": "uname -a"},
            now=NOW,
        ),
    )
    expect(
        PermissionError,
        "not admitted",
        lambda: writable.call(
            "embodiment.request",
            {
                **request_args(),
                "intent_id": "intent-unknown-class",
                "capability_class": "arbitrary-shell",
            },
            now=NOW,
        ),
    )
    expect(
        PermissionError,
        "lacks embodiments:materialize",
        lambda: writable.call(
            "embodiment.request",
            {
                **request_args(),
                "intent_id": "intent-other-resource",
                "resource": "workcell:beta",
            },
            now=NOW,
        ),
    )
    expect(
        PermissionError,
        "actor mismatch",
        lambda: writable.call(
            "embodiment.request",
            {
                **request_args(),
                "intent_id": "intent-mismatch",
                "authority_ref": "github:synthetic/mismatch",
            },
            now=NOW,
        ),
    )

    released = writable.call(
        "embodiment.release",
        {
            "intent_id": "intent-mcp-stop",
            "authority_ref": "github:synthetic/work",
            "body_instance_id": body_id,
            "reason": "bounded work complete",
        },
        now=NOW + timedelta(minutes=1),
    )
    assert released["desired_presence"] == "absent"
    assert released["mcp_projection"] == "private-semantic-control"
    assert released["provider_effect_tools_exposed"] is False

    print("private embodiment MCP projection: PASS")


if __name__ == "__main__":
    main()
