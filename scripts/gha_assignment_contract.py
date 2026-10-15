#!/usr/bin/env python3
"""Fixed reviewed CPU profile + dynamic public-safe DLE assignment contract.

This is a deterministic contract library, NOT a scheduler, DLE authority
issuer, credential broker, or workflow dispatcher. Sidecar must independently
authenticate the caller, admit the exact DLE assignment, and suppress
ambiguous/replayed dispatch before invoking the static GitHub workflow.
A public runner cannot independently attest a private DLE's authorization.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re

import gha_workload_request as profile

SCHEMA = "gha-typed-assignment/v1"
FIELDS = {
    "schema", "assignment_id", "nonce", "profile_id", "profile_sha256",
    "source_sha", "authority_sha256", "issued_at", "expires_at",
    "data_class", "max_attempts", "max_cost_usd",
}
PROFILES = {
    "cpu-x64-arithmetic-v1": "requests/gha/cpu-x64-arithmetic-v1.json",
    "cpu-arm64-contract-v1": "requests/gha/cpu-arm64-contract-v1.json",
    "microsoft-devproxy-mock-v1": "requests/gha/microsoft-devproxy-mock-v1.json",
    "azurite-blob-transport-v1": "requests/gha/azurite-blob-transport-v1.json",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
NONCE = re.compile(r"^[0-9a-f]{32}$")
STAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
MAX_BYTES = 2048
MAX_TTL_SECONDS = 900
CLOCK_SKEW_SECONDS = 30


class Denied(ValueError):
    pass


def _strict_pairs(pairs):
    doc = {}
    for key, val in pairs:
        if key in doc:
            raise Denied("DUPLICATE_ASSIGNMENT_FIELD")
        doc[key] = val
    return doc


def _timestamp(value):
    if not isinstance(value, str) or not STAMP.fullmatch(value):
        raise Denied("ASSIGNMENT_TIMESTAMP_INVALID")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise Denied("ASSIGNMENT_TIMESTAMP_INVALID") from exc


def admit(raw: str | bytes, *, trusted_source_sha: str,
          now: datetime | None = None, prior_identities=()) -> dict:
    """Validate a public assignment, bind it to the checked-out reviewed profile.

    prior_identities is independently sourced DLE/native (assignment_id,nonce)
    evidence, not a self-assertion from the assignment. Its check is advisory;
    atomic anti-replay belongs in the existing Sidecar/Actions admission path.
    """
    if not isinstance(raw, (str, bytes)):
        raise Denied("ASSIGNMENT_TYPE_INVALID")
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    if not (10 <= len(data) <= MAX_BYTES):
        raise Denied("ASSIGNMENT_BYTES_INVALID")
    try:
        doc = json.loads(data, object_pairs_hook=_strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Denied("ASSIGNMENT_JSON_INVALID") from exc
    if not isinstance(doc, dict) or set(doc) != FIELDS or doc["schema"] != SCHEMA:
        raise Denied("ASSIGNMENT_FIELDS_DENIED")
    if not isinstance(doc["assignment_id"], str) or not profile.SAFE_ID.fullmatch(doc["assignment_id"]):
        raise Denied("ASSIGNMENT_ID_DENIED")
    if not isinstance(doc["nonce"], str) or not NONCE.fullmatch(doc["nonce"]):
        raise Denied("ASSIGNMENT_NONCE_DENIED")
    if not isinstance(doc["profile_id"], str) or doc["profile_id"] not in PROFILES:
        raise Denied("PROFILE_ID_DENIED")
    if not isinstance(doc["source_sha"], str) or not HEX40.fullmatch(doc["source_sha"]):
        raise Denied("SOURCE_SHA_INVALID")
    if not HEX40.fullmatch(trusted_source_sha) or doc["source_sha"] != trusted_source_sha:
        raise Denied("SOURCE_DRIFT")
    for field in ("profile_sha256", "authority_sha256"):
        if not isinstance(doc[field], str) or not HEX64.fullmatch(doc[field]):
            raise Denied("ASSIGNMENT_DIGEST_INVALID")
    if doc["data_class"] != "public-synthetic":
        raise Denied("PRIVATE_DATA_DENIED")
    if type(doc["max_attempts"]) is not int or doc["max_attempts"] != 1:
        raise Denied("ATTEMPT_LIMIT_DENIED")
    if type(doc["max_cost_usd"]) not in (int, float) or doc["max_cost_usd"] != 0:
        raise Denied("COST_LIMIT_DENIED")
    issued, expires = _timestamp(doc["issued_at"]), _timestamp(doc["expires_at"])
    if not (0 < (expires - issued).total_seconds() <= MAX_TTL_SECONDS):
        raise Denied("ASSIGNMENT_TTL_DENIED")
    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        raise Denied("TRUSTED_CLOCK_INVALID")
    if (issued - clock).total_seconds() > CLOCK_SKEW_SECONDS or expires <= clock:
        raise Denied("ASSIGNMENT_EXPIRED_OR_FUTURE")
    for old in prior_identities:
        if not isinstance(old, (list, tuple)) or len(old) != 2:
            raise Denied("REPLAY_EVIDENCE_INVALID")
        if doc["assignment_id"] == old[0] or doc["nonce"] == old[1]:
            raise Denied("REPLAY_OR_DUPLICATE")
    fixed_profile = profile.plan(PROFILES[doc["profile_id"]])
    if fixed_profile["request_sha256"] != doc["profile_sha256"]:
        raise Denied("PROFILE_DIGEST_DRIFT")
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        "schema": SCHEMA,
        "assignment_id": doc["assignment_id"],
        "nonce": doc["nonce"],
        "assignment_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "authority_sha256": doc["authority_sha256"],
        "source_sha": trusted_source_sha,
        "profile_id": doc["profile_id"],
        "profile_path": fixed_profile["request_path"],
        "profile_sha256": fixed_profile["request_sha256"],
        "runner": fixed_profile["runner"],
        "workload": fixed_profile["workload"],
        "timeout_seconds": fixed_profile["timeout_seconds"],
        "expires_at": doc["expires_at"],
        "max_attempts": 1,
        "max_cost_usd": 0,
        "data_class": "public-synthetic",
        "limitation": "Runner does not attest private DLE authorization; Sidecar/native reconciliation must",
    }
