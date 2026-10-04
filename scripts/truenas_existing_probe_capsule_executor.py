#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
from typing import Any

from truenas_session_manifest import SessionError

SCHEMA = "truenas-capsule-context/v1"
DISPATCH_SCHEMA = "truenas-capsule-dispatch/v1"
RECEIPT_SCHEMA = "truenas-capsule-execution/v1"

PROVIDER_PORT_ARGS = {
    "litellm-t6": {"service": "--service-port"},
    "wow-sidecar-t6": {},
    "garm-t6": {"service": "--service-port"},
    "official-catalog-t6": {},
    "foliorelay-t6": {
        "control": "--control-port",
        "ipp": "--ipp-port",
        "observer": "--observer-port",
    },
}

STATE_TIMEOUT = {
    "litellm-t6": 240,
    "wow-sidecar-t6": 240,
    "garm-t6": 240,
    "official-catalog-t6": 240,
    "foliorelay-t6": 300,
}

KNOWN_FAILURES = {
    "ORACLE_FAILURE",
    "HARNESS_FAILURE",
    "ENVIRONMENT_FAILURE",
    "UNSUPPORTED",
}


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SessionError(f"{path}: top-level value must be an object")
    return value


def nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SessionError(f"{label} must be a non-empty string")
    return value


def positive_port(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise SessionError(f"{label} must be a TCP port")
    return value


def provider_context(context: dict[str, Any], provider_id: str) -> dict[str, Any]:
    rows = context.get("providers")
    if not isinstance(rows, dict):
        raise SessionError("context.providers must be an object")
    row = rows.get(provider_id)
    if not isinstance(row, dict):
        raise SessionError(f"context has no provider binding for {provider_id}")
    return row


def build_probe_command(
    descriptor: dict[str, Any],
    context: dict[str, Any],
    provider_receipt: pathlib.Path,
) -> list[str]:
    if descriptor.get("schema") != DISPATCH_SCHEMA:
        raise SessionError("unsupported capsule dispatch schema")
    capsule = descriptor.get("capsule")
    provider = descriptor.get("provider")
    if not isinstance(capsule, dict) or not isinstance(provider, dict):
        raise SessionError("dispatch requires capsule and provider objects")

    provider_id = nonempty(capsule.get("provider"), "capsule.provider")
    if provider_id != provider.get("id"):
        raise SessionError("capsule/provider identity mismatch")
    if provider_id not in PROVIDER_PORT_ARGS:
        raise SessionError(f"provider is not admitted by existing-probe executor: {provider_id}")

    probe = pathlib.Path(nonempty(provider.get("probe"), "provider.probe"))
    if not probe.is_file():
        raise SessionError(f"provider probe does not exist: {probe}")

    if context.get("schema") != SCHEMA:
        raise SessionError("unsupported capsule context schema")
    host = nonempty(context.get("host"), "context.host")
    middleware_port = positive_port(context.get("middleware_port"), "context.middleware_port")
    password_file = pathlib.Path(nonempty(context.get("password_file"), "context.password_file"))
    if not password_file.is_file():
        raise SessionError("context.password_file does not exist")
    tls = context.get("tls")
    if not isinstance(tls, bool):
        raise SessionError("context.tls must be boolean")

    binding = provider_context(context, provider_id)
    control_dir = pathlib.Path(nonempty(binding.get("control_dir"), f"{provider_id}.control_dir"))
    if not control_dir.is_dir():
        raise SessionError(f"{provider_id}.control_dir does not exist")
    foundry_commit = nonempty(binding.get("foundry_commit"), f"{provider_id}.foundry_commit")
    if len(foundry_commit) != 40 or any(ch not in "0123456789abcdef" for ch in foundry_commit):
        raise SessionError(f"{provider_id}.foundry_commit must be exact lowercase SHA")

    command = [
        sys.executable,
        str(probe),
        "--host", host,
        "--port", str(middleware_port),
    ]
    if tls:
        command.append("--tls")
    command += [
        "--password-file", str(password_file),
        "--control-dir", str(control_dir),
        "--foundry-commit", foundry_commit,
    ]

    ports = binding.get("ports", {})
    if not isinstance(ports, dict):
        raise SessionError(f"{provider_id}.ports must be an object")
    for name, flag in PROVIDER_PORT_ARGS[provider_id].items():
        command += [flag, str(positive_port(ports.get(name), f"{provider_id}.ports.{name}"))]

    command += [
        "--out", str(provider_receipt),
        "--timeout", "8",
        "--job-timeout", "300",
        "--state-timeout", str(STATE_TIMEOUT[provider_id]),
    ]
    return command


def wrap_receipt(
    descriptor: dict[str, Any],
    provider_receipt: dict[str, Any] | None,
    returncode: int,
    stderr: str,
) -> dict[str, Any]:
    capsule = descriptor["capsule"]
    provider = descriptor["provider"]
    supported = bool(
        provider_receipt
        and provider_receipt.get("classification") == "SUPPORTED"
        and provider_receipt.get("oracleSatisfied") is True
    )
    if supported:
        verdict = "SUPPORTED"
        cleanup_satisfied = True
        platform_healthy = True
        reason = "existing provider probe completed its accepted oracle and cleanup contract"
    else:
        observed = provider_receipt.get("classification") if provider_receipt else None
        verdict = observed if observed in KNOWN_FAILURES else "HARNESS_FAILURE"
        cleanup_satisfied = False
        platform_healthy = False
        reason = (
            (provider_receipt or {}).get("detail")
            or stderr.strip()
            or f"provider probe exited {returncode} without accepted receipt"
        )
    return {
        "schema": RECEIPT_SCHEMA,
        "capsule_id": capsule["id"],
        "provider": capsule["provider"],
        "provider_probe": provider["probe"],
        "manifest_sha256": descriptor["manifest_sha256"],
        "verdict": verdict,
        "mutating": capsule["mutating"],
        "cleanup_required": capsule["cleanup_required"],
        "cleanup_satisfied": cleanup_satisfied,
        "platform_healthy": platform_healthy,
        "authority_satisfied": True,
        "resource_guardrail_satisfied": True,
        "provider_returncode": returncode,
        "provider_receipt": provider_receipt,
        "reason": reason[:2000],
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--capsule", type=pathlib.Path, required=True)
    p.add_argument("--context", type=pathlib.Path, required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    try:
        descriptor = load_json(a.capsule)
        context = load_json(a.context)
        provider_receipt = a.out.with_suffix(".provider.json")
        command = build_probe_command(descriptor, context, provider_receipt)
        if a.dry_run:
            print(json.dumps({"schema":"truenas-capsule-command/v1","argv":command}, indent=2))
            return 0
        cp = subprocess.run(command, text=True, capture_output=True, check=False)
        source = load_json(provider_receipt) if provider_receipt.is_file() else None
        receipt = wrap_receipt(descriptor, source, cp.returncode, cp.stderr)
        a.out.write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n", encoding="utf-8")
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except (SessionError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
