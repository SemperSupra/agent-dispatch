#!/usr/bin/env python3
"""Offline audit of exact pinned TrueNAS 25.04.2.6 API client source.

No guest, socket, authentication, API call, model or Docker daemon is accessed.
The source tree must be separately checked out from the immutable upstream commit.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import pathlib
import sys

UPSTREAM = "truenas/api_client"
TAG_COMMIT = "3576b3cf9a87ae92bbf1d873e23215b48ca90819"
CLIENT_BLOB = "ccd59b19381b0d494528c6854db228e1c2a6665c"
SCHEMA = "book2epub-g1a-exact-client-source-audit/v1"


class AuditError(ValueError):
    pass


def git_blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def method(cls, name):
    return next((node for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name), None)


def audit_bytes(raw):
    if not isinstance(raw, bytes) or len(raw) > 100000:
        raise AuditError("source_invalid_or_too_large")
    if git_blob_sha(raw) != CLIENT_BLOB:
        raise AuditError("exact_upstream_blob_mismatch")
    try:
        tree = ast.parse(raw, filename="pinned_trueNAS_client.py")
    except (SyntaxError, ValueError, UnicodeError) as exc:
        raise AuditError("upstream_source_unparseable") from exc
    classes = {c.name: c for c in tree.body if isinstance(c, ast.ClassDef)}
    if not {"Client", "JSONRPCClient", "WSClient"}.issubset(classes):
        raise AuditError("client_class_missing")
    factory = method(classes["Client"], "__init__")
    rpc = method(classes["JSONRPCClient"], "call")
    sock = method(classes["WSClient"], "connect")
    if factory is None or rpc is None or sock is None:
        raise AuditError("client_method_missing")
    factory_args = factory.args.args
    names = [arg.arg for arg in factory_args]
    if "verify_ssl" not in names or not factory.args.defaults:
        raise AuditError("ssl_parameter_missing")
    ssl_default = factory.args.defaults[-1]
    if names[-1] != "verify_ssl" or not isinstance(ssl_default, ast.Constant) or ssl_default.value is not True:
        raise AuditError("ssl_default_not_true")
    rpc_names = [a.arg for a in rpc.args.args]
    if rpc_names[:2] != ["self", "method"] or rpc.args.vararg is None or rpc.args.vararg.arg != "params":
        raise AuditError("rpc_call_not_method_plus_variadic_params")
    # Source-level check only, not TLS or certificate verification at runtime.
    verify_logic = any(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name) and node.value.id == "self"
        and node.attr == "verify_ssl"
        for node in ast.walk(sock)
    )
    if not verify_logic:
        raise AuditError("ssl_parameter_unused_in_connection")
    # Factory must retain URL selection between legacy and JSON-RPC.
    has_legacy = any(isinstance(n, ast.Name) and n.id == "LegacyClient" for n in ast.walk(factory))
    has_rpc = any(isinstance(n, ast.Name) and n.id == "JSONRPCClient" for n in ast.walk(factory))
    if not has_legacy or not has_rpc:
        raise AuditError("protocol_selection_unavailable")
    # The official client issues a session setup RPC automatically on socket
    # establishment. Three caller-triggered observations do not equal three
    # wire-level RPCs; make that behavior an explicit admission dependency.
    on_open = method(classes["JSONRPCClient"], "on_open")
    if on_open is None:
        raise AuditError("setup_rpc_method_missing")
    setup_calls = []
    for node in ast.walk(on_open):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "self"
                and node.func.attr == "call"):
            continue
        if (not node.args or not isinstance(node.args[0], ast.Constant)
                or not isinstance(node.args[0].value, str)):
            raise AuditError("dynamic_connection_setup_rpc")
        setup_calls.append(node.args[0].value)
    if setup_calls != ["core.set_options"]:
        raise AuditError("unreviewed_connection_setup_rpcs")
    return {
        "schema": SCHEMA, "repository": UPSTREAM,
        "upstream_commit": TAG_COMMIT, "client_source_blob": CLIENT_BLOB,
        "source_only": True, "classification": "PINNED_CLIENT_SOURCE_COMPATIBLE_RUNTIME_UNVERIFIED",
        "client_factory_ssl_default": True, "jsonrpc_call_variadic": True,
        "protocol_branch_identified": True, "connection_uses_ssl_flag": True,
        "implicit_connection_setup_rpcs": setup_calls,
        "observation_rpc_count_is_total_wire_count": False,
        "connection_setup_requires_independent_authorization": True,
        "server_protocol_tested": False, "ssl_peer_verified": False,
        "authenticated_role_tested": False, "trueNAS_guest_observed": False,
        "dispatch_authorized": False, "physical_apply": "HOLD",
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = audit_bytes(args.source.read_bytes())
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (OSError, AuditError):
        print("ERROR: exact upstream TrueNAS client source audit refused", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
