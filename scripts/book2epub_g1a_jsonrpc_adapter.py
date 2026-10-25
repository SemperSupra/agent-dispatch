#!/usr/bin/env python3
"""B1: source-only TrueNAS 25.04.2.6 JSON-RPC client admission membrane.

An external Agent Dispatch session owner supplies a pre-authenticated, TLS
peer-verified version-matched client. This module never constructs credentials
or sockets and cannot attest ownership or permissions merely from declarations.
"""
from __future__ import annotations

import re

from book2epub_g1a_middleware_readonly import observe

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SID = re.compile(r"[a-z0-9][a-z0-9._-]{7,79}\Z")
REQUIRED_KEYS = frozenset({
    "target", "protocol", "endpoint", "transport", "role",
    "peer_cert_sha256", "session_id",
})
TARGET = "TrueNAS-25.04.2.6"
METHODS = ("system.version", "docker.status", "docker.config")


class AdmissionError(ValueError):
    pass


def validate_binding(binding):
    """Shape validation only. Never upgrades statements into real attestations."""
    if not isinstance(binding, dict) or set(binding) != REQUIRED_KEYS:
        raise AdmissionError("invalid_binding_fields")
    if binding["target"] != TARGET:
        raise AdmissionError("target_drift")
    if binding["protocol"] != "JSONRPC_2_0" or binding["endpoint"] != "/api/current":
        raise AdmissionError("protocol_or_endpoint_not_admitted")
    if binding["transport"] != "WSS_CERT_VERIFIED_BY_SESSION_OWNER":
        raise AdmissionError("remote_tls_not_independently_bound")
    if binding["role"] != "DOCKER_READ":
        raise AdmissionError("wrong_read_role")
    if not isinstance(binding["peer_cert_sha256"], str) or not SHA256.fullmatch(binding["peer_cert_sha256"]):
        raise AdmissionError("invalid_peer_cert_fingerprint")
    if not isinstance(binding["session_id"], str) or not SID.fullmatch(binding["session_id"]):
        raise AdmissionError("invalid_session_identity")
    return True


def observe_client(client, binding):
    """Consume only the supplied object's API-client .call(method).

    A positive result is candidate status only: independently verified peer,
    role, and job-bound guest evidence must come from the session owner.
    """
    validate_binding(binding)
    if not hasattr(client, "call") or not callable(client.call):
        raise AdmissionError("no_api_call_interface")
    count = 0
    def read(method):
        nonlocal count
        if count >= len(METHODS) or method != METHODS[count]:
            raise AdmissionError("non_read_method_or_order")
        count += 1
        return client.call(method)
    receipt = observe(read)
    receipt.update({
        "adapter_schema": "book2epub-g1a-jsonrpc-client-adapter/v1",
        "protocol_requested": "JSONRPC_2_0",
        "read_only_rpc_count": count,
        "application_observation_rpc_count": count,
        "total_transport_rpc_count": "UNKNOWN_UNTIL_SESSION_OWNER_ATTESTS",
        "expected_implicit_client_setup_rpc": "core.set_options",
        "connection_setup_independently_authorized": False,
        "required_role": "DOCKER_READ",
        "session_id": binding["session_id"],
        "binding_shape_valid": True,
        "independent_role_proof": False,
        "independent_tls_peer_proof": False,
        "independent_guest_ownership_proof": False,
        "credential_disclosure": False,
        "runtime_verdict": "UNVERIFIED_CANDIDATE_ONLY",
    })
    return receipt
