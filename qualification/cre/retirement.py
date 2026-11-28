"""Retire only a bound CRE fixture container; observation failure is UNKNOWN.

This is a narrow Docker lifecycle helper for the existing public fixture, not
a provider registry, admission service or proof of all external-effect cleanup.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import subprocess

ID = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")
MAX_BYTES = 1024 * 1024
MAX_ROWS = 4096
INVENTORY = [
    "docker", "container", "ls", "--all", "--no-trunc",
    "--format", '{"ID":{{json .ID}},"Names":{{json .Names}}}',
]


def _run(argv, timeout):
    return subprocess.run(argv, capture_output=True, timeout=timeout, check=False)


def _command(run, argv, timeout):
    """Do not copy provider stderr or arbitrary command output into receipts."""
    try:
        result = run(argv, timeout)
    except subprocess.TimeoutExpired:
        return {"status": "TIMED_OUT"}, None
    except (OSError, subprocess.SubprocessError):
        return {"status": "UNAVAILABLE"}, None
    if (type(getattr(result, "returncode", None)) is not int
            or not isinstance(getattr(result, "stdout", None), bytes)):
        return {"status": "INVALID_RESPONSE"}, None
    if result.returncode != 0:
        return {"status": "FAILED", "exit_code": result.returncode}, None
    if len(result.stdout) > MAX_BYTES:
        return {"status": "OUTPUT_LIMIT"}, None
    return {"status": "SUCCEEDED", "exit_code": 0}, result.stdout


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _inventory(run, owned_id, owned_name, timeout):
    command, raw = _command(run, INVENTORY.copy(), timeout)
    observation = {
        "status": "UNKNOWN",
        "command": command,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
    if raw is None:
        return observation
    try:
        if raw and not raw.endswith(b"\n"):
            raise ValueError("incomplete inventory framing")
        lines = raw.decode("utf-8", errors="strict").splitlines()
        if len(lines) > MAX_ROWS:
            raise ValueError("inventory bound")
        rows, names = {}, set()
        for line in lines:
            row = json.loads(line, object_pairs_hook=_object)
            if not isinstance(row, dict) or set(row) != {"ID", "Names"}:
                raise ValueError("unexpected inventory fields")
            identifier, field = row["ID"], row["Names"]
            if (not isinstance(identifier, str) or not ID.fullmatch(identifier)
                    or not isinstance(field, str)):
                raise ValueError("invalid container identity")
            parts = field.split(",")
            if not parts or any(not NAME.fullmatch(n) or n in names for n in parts):
                raise ValueError("invalid or duplicate name")
            if len(set(parts)) != len(parts) or identifier in rows:
                raise ValueError("duplicate identity")
            rows[identifier] = frozenset(parts)
            names.update(parts)
        id_present = owned_id in rows if owned_id else False
        name_present = owned_name in names
        observation.update(
            status="COMPLETE",
            inventory_count=len(rows),
            owned_id_present=id_present,
            owned_name_present=name_present,
            identity_matches=id_present and owned_name in rows[owned_id],
            name_reused=name_present and (
                not owned_id or not id_present or owned_name not in rows[owned_id]
            ),
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        observation["command"]["status"] = "INVALID_INVENTORY"
    return observation


def retire_owned_container(owned_id, owned_name, *, run=_run, timeout=10):
    """Observe, remove the exact matched ID, then verify a complete inventory.

    Any command/permission/timeout/parse failure remains UNKNOWN, even if a later
    observation is empty. A missing launch ID cannot settle an uncertain create.
    Only a successful current complete inventory supports absence. The helper
    never removes by name, invokes inspect, retries a mutation, or publishes
    foreign IDs/names/command output.
    """
    receipt = {
        "schema": "cre-container-retirement/v1",
        "container_id": owned_id,
        "container_name": owned_name,
        "status": "UNKNOWN",
        "reason": "invalid_binding",
        "removal": {"status": "NOT_ATTEMPTED"},
        "observations": {},
        "claim_ceiling": "Container absence in the observed Docker daemon only; "
                         "external effects and other resources are not qualified.",
    }
    if (owned_id is not None and (
            not isinstance(owned_id, str) or not ID.fullmatch(owned_id))):
        return receipt
    if (not isinstance(owned_name, str) or not NAME.fullmatch(owned_name)
            or type(timeout) not in (int, float) or not 0 < timeout <= 20):
        return receipt

    before = _inventory(run, owned_id, owned_name, timeout)
    receipt["observations"]["before"] = before
    if before["status"] != "COMPLETE":
        receipt["reason"] = "initial_observation_unknown"
        return receipt
    if owned_id is None:
        receipt["reason"] = "launch_identity_unknown"
        return receipt
    if before["name_reused"]:
        receipt["reason"] = "name_reused"
        return receipt
    if not before["owned_id_present"] and not before["owned_name_present"]:
        receipt.update(status="CONFIRMED_ABSENT", reason="already_absent")
        return receipt
    if not before["identity_matches"]:
        receipt["reason"] = "identity_binding_changed"
        return receipt

    removal, raw = _command(
        run, ["docker", "container", "rm", "--force", owned_id], timeout
    )
    if raw is not None and raw.strip() != owned_id.encode("ascii"):
        removal["status"] = "IDENTITY_UNCONFIRMED"
    receipt["removal"] = removal
    after = _inventory(run, owned_id, owned_name, timeout)
    receipt["observations"]["after"] = after

    if removal["status"] != "SUCCEEDED":
        receipt["reason"] = "removal_outcome_unknown"
    elif after["status"] != "COMPLETE":
        receipt["reason"] = "final_observation_unknown"
    elif after["owned_id_present"]:
        receipt.update(status="PRESENT", reason="owned_container_remains")
    elif after["owned_name_present"]:
        receipt["reason"] = "name_reused"
    else:
        receipt.update(status="CONFIRMED_ABSENT", reason="removed_and_absent")
    return receipt
