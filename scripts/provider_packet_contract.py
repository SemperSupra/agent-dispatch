#!/usr/bin/env python3
"""Credential-free synthetic artifact-packet oracle; not an adapter, broker or DLE."""
from __future__ import annotations
import hashlib
import json
import re

MAX_MANIFEST_BYTES = 2048
MAX_PAYLOAD_BYTES = 65536
SCHEMA = "artifact-packet/v1"
FIELDS = {"schema", "artifact_id", "source_sha", "data_class", "locator",
          "revision", "sha256", "size_bytes"}
ID_PATTERN = re.compile(r"[a-z][a-z0-9-]{2,63}\Z")
SOURCE_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
LOCATOR_PATTERN = re.compile(r"fixture://[a-z][a-z0-9-]{2,47}/[a-z][a-z0-9-]{2,47}\Z")
REVISION_PATTERN = re.compile(r"rev-[a-z0-9]{1,32}\Z")


class Denied(ValueError):
    """Fail closed without echoing provider metadata or input."""


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Denied("DUPLICATE_FIELD")
        result[key] = value
    return result


def parse(raw: bytes, *, trusted_source_sha: str) -> dict:
    if not isinstance(raw, bytes) or not (10 <= len(raw) <= MAX_MANIFEST_BYTES):
        raise Denied("MANIFEST_BOUNDS")
    if not isinstance(trusted_source_sha, str) or not SOURCE_PATTERN.fullmatch(trusted_source_sha):
        raise Denied("TRUSTED_SOURCE_INVALID")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                         parse_constant=lambda _value: (_ for _ in ()).throw(Denied("INVALID_NUMBER")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Denied("MANIFEST_JSON_INVALID") from exc
    if not isinstance(doc, dict) or set(doc) != FIELDS or doc["schema"] != SCHEMA:
        raise Denied("MANIFEST_SCHEMA_DENIED")
    if not isinstance(doc["artifact_id"], str) or not ID_PATTERN.fullmatch(doc["artifact_id"]):
        raise Denied("ARTIFACT_ID_DENIED")
    if not isinstance(doc["source_sha"], str) or doc["source_sha"] != trusted_source_sha:
        raise Denied("SOURCE_BINDING_DENIED")
    if doc["data_class"] != "public-synthetic":
        raise Denied("DATA_CLASS_DENIED")
    if not isinstance(doc["locator"], str) or not LOCATOR_PATTERN.fullmatch(doc["locator"]):
        raise Denied("LOCATOR_DENIED")
    if not isinstance(doc["revision"], str) or not REVISION_PATTERN.fullmatch(doc["revision"]):
        raise Denied("REVISION_DENIED")
    if not isinstance(doc["sha256"], str) or not SHA256_PATTERN.fullmatch(doc["sha256"]):
        raise Denied("DIGEST_DENIED")
    if type(doc["size_bytes"]) is not int or not (0 <= doc["size_bytes"] <= MAX_PAYLOAD_BYTES):
        raise Denied("PAYLOAD_BOUNDS")
    return doc


def verify(raw: bytes, *, trusted_source_sha: str, observed_revision: str,
           payload: bytes) -> dict:
    doc = parse(raw, trusted_source_sha=trusted_source_sha)
    if not isinstance(observed_revision, str) or observed_revision != doc["revision"]:
        raise Denied("REVISION_CONFLICT")
    if not isinstance(payload, bytes) or len(payload) != doc["size_bytes"]:
        raise Denied("PAYLOAD_LENGTH_MISMATCH")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != doc["sha256"]:
        raise Denied("PAYLOAD_DIGEST_MISMATCH")
    return {
        "schema": "artifact-packet-receipt/v1",
        "source_sha": trusted_source_sha,
        "artifact_id": doc["artifact_id"],
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "payload_sha256": digest,
        "size_bytes": len(payload),
        "revision_match": True,
        "fixture_verified": True,
        "provider_access_verified": False,
        "max_cost_usd": 0,
        "data_class": "public-synthetic",
    }
