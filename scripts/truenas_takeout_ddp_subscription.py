#!/usr/bin/env python3
"""Passive, fail-closed TrueNAS DDP docker.events subscription protocol parser.

The socket is injected by an independently admitted caller. No connection,
authentication, secrets, host access, or TrueNAS Apps changes occur here.
Passing this parser does not qualify live DOCKER_READ RBAC or a T6 guest.
"""
from __future__ import annotations

import re


class WitnessBlocked(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise WitnessBlocked(reason)


CID_RE = re.compile(r"[0-9a-f]{64}\Z")


def recv(ws):
    try:
        message = ws.recv_json()
    except (OSError, EOFError, TimeoutError, ValueError):
        raise WitnessBlocked("STREAM_LOST") from None
    require(isinstance(message, dict), "INVALID_MESSAGE")
    if message.get("msg") == "ping":
        response = {"msg": "pong"}
        if "id" in message:
            response["id"] = message["id"]
        ws.send_json(response)
    return message


def arm(ws, subscription_id="takeout-events", max_messages=12):
    """Only request read-only docker.events; await exact DDP READY."""
    require(isinstance(subscription_id, str) and
            re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{3,70}", subscription_id),
            "INVALID_SUBSCRIPTION_ID")
    require(type(max_messages) is int and 1 <= max_messages <= 100,
            "INVALID_HANDSHAKE_BUDGET")
    ws.send_json({"msg": "sub", "id": subscription_id, "name": "docker.events"})
    for _ in range(max_messages):
        message = recv(ws)
        kind = message.get("msg")
        if kind == "ping":
            continue
        if kind in ("error", "nosub", "failed", "removed"):
            raise WitnessBlocked("SUBSCRIPTION_REJECTED")
        if kind == "ready":
            require(message.get("subs") == [subscription_id], "READY_IDENTITY_MISMATCH")
            return {"status": "READY", "stream": "docker.events",
                    "live_rbac_qualified": False, "truenas_guest": "NOT_RUN"}
        raise WitnessBlocked("MESSAGE_BEFORE_READY")
    raise WitnessBlocked("READY_MISSING")


def collect_worker_until_die(ws, *, project, service, container_id, max_messages=2000):
    """Return only exact project/worker envelopes; unrelated metadata is dropped.

    An upstream independently bound oracle must still validate the complete
    create/start/die order, exit code, event timestamps, app state, image config
    and materialization identity. This function alone does not attest success.
    """
    require(isinstance(project, str) and
            re.fullmatch(r"ix-[a-z0-9_-]{3,80}", project), "INVALID_PROJECT")
    require(isinstance(service, str) and
            re.fullmatch(r"[a-z0-9_-]{3,80}", service), "INVALID_SERVICE")
    require(isinstance(container_id, str) and CID_RE.fullmatch(container_id),
            "INVALID_CONTAINER_ID")
    require(type(max_messages) is int and 1 <= max_messages <= 10000,
            "INVALID_EVENT_BUDGET")
    events = []
    for _ in range(max_messages):
        message = recv(ws)
        kind = message.get("msg")
        if kind == "ping":
            continue
        if kind in ("error", "nosub", "failed", "removed", "ready"):
            raise WitnessBlocked("SUBSCRIPTION_INTERRUPTED")
        require(kind == "added" and message.get("collection") == "docker.events",
                "UNEXPECTED_ENVELOPE")
        if message.get("id") != project:
            continue
        raw = message.get("fields")
        require(isinstance(raw, dict) and raw.get("Type") == "container",
                "PROJECT_EVENT_MALFORMED")
        actor = raw.get("Actor")
        attrs = actor.get("Attributes") if isinstance(actor, dict) else None
        require(isinstance(attrs, dict) and
                attrs.get("com.docker.compose.project") == project,
                "PROJECT_LABEL_MISMATCH")
        if attrs.get("com.docker.compose.service") != service:
            continue
        require(attrs.get("com.docker.compose.container-number") == "1" and
                actor.get("ID") == container_id, "WORKER_IDENTITY_MISMATCH")
        action = raw.get("Action")
        require(isinstance(action, str) and action, "ACTION_UNKNOWN")
        # Drop unrelated app payloads before returning to owner-controlled caller.
        events.append({"id": project, "fields": raw})
        if action == "die":
            return events
    raise WitnessBlocked("DIE_EVENT_MISSING")
