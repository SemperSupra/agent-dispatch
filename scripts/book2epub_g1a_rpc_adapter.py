#!/usr/bin/env python3
"""G1a read-only middleware adapter for an *already authenticated* AD session.

The caller owns connection, authentication, exact guest identity, TLS and slot admission.
This adapter does not connect, authenticate, dispatch, or grant API permissions.
"""
from __future__ import annotations

import re

from book2epub_g1a_middleware_readonly import observe

SESSION_ID = re.compile(r"[a-z0-9][a-z0-9._-]{7,79}\Z")
READ_METHODS = ("system.version", "docker.status", "docker.config")
REQUIRED_ROLE = "DOCKER_READ"


def observe_ddp_session(ws, ddp_call, session_id: str) -> dict:
    """Consume only the three G1a reads from an already-authorized transport.

    Evidence about the authenticated principal and transport MUST come from
    the independent session owner, not this source-only code or its unit tests.
    The TrueNAS backend, not a caller-supplied claim, enforces DOCKER_READ.
    """
    if not isinstance(session_id, str) or not SESSION_ID.fullmatch(session_id):
        raise ValueError("invalid bounded session ID")
    index = 0

    def call(method):
        nonlocal index
        if index >= len(READ_METHODS) or method != READ_METHODS[index]:
            raise ValueError("read-only RPC order or method violation")
        index += 1
        # Existing DDP client wraps reply/errors and sends params=[], never updates.
        return ddp_call(ws, f"book2epub-g1a-{index}", method, [])

    receipt = observe(call)
    receipt["adapter_schema"] = "book2epub-g1a-ddp-adapter/v1"
    receipt["required_trueNAS_role"] = REQUIRED_ROLE
    receipt["session_id"] = session_id
    receipt["read_only_rpc_count"] = index
    receipt["runtime_transport_attestation"] = "NOT_PROVEN_BY_THIS_ADAPTER"
    receipt["role_assignment_proven"] = False
    return receipt
