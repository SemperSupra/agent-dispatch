#!/usr/bin/env python3
"""Minimal execution-evidence helpers for demand-driven Firecracker placement.

This module describes an execution body and its receipt. It deliberately does
not schedule work, infer mission intent, maintain a provider/image registry, or
grant authority.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Iterable

SCHEMA = "firecracker-workload-evidence/v1"

FIRECRACKER_REASONS = frozenset({
    "stronger_isolation",
    "destructive_disposability",
    "machine_semantics",
    "body_variation",
    "warm_reset_economics",
})

RESULT_CLASSIFICATIONS = frozenset({
    "SUPPORTED",
    "HARNESS_FAILURE",
    "WORKLOAD_FAILURE",
    "ORACLE_FAILURE",
    "SETUP_REQUIRED",
    "VENUE_LIMITATION",
    "AUTHORITY_REQUIRED",
    "INCONCLUSIVE",
})


class ContractError(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_reasons(reasons: Iterable[str]) -> list[str]:
    out = sorted(set(str(x) for x in reasons))
    unknown = [x for x in out if x not in FIRECRACKER_REASONS]
    if unknown:
        raise ContractError(f"unknown Firecracker placement reason(s): {unknown}")
    if not out:
        raise ContractError("Firecracker placement requires at least one material reason")
    return out


def validate_visibility(*, venue: str, visibility: str) -> None:
    if visibility not in {"public_safe", "private"}:
        raise ContractError(f"unsupported visibility: {visibility}")
    if venue == "public-gha" and visibility != "public_safe":
        raise ContractError("public GHA Firecracker may receive only public-safe inputs")


def make_receipt(
    *,
    authority_ref: str,
    assignment_ref: str,
    assignment_revision: str,
    venue: str,
    visibility: str,
    placement_reasons: Iterable[str],
    inputs: dict,
    body: dict,
    execution: dict,
    outputs: dict,
    validation: dict | None,
    cleanup: dict,
) -> dict:
    if not authority_ref or not assignment_ref or not assignment_revision:
        raise ContractError("authority, assignment reference, and assignment revision are required")
    validate_visibility(venue=venue, visibility=visibility)
    reasons = normalize_reasons(placement_reasons)

    classification = execution.get("classification")
    if classification not in RESULT_CLASSIFICATIONS:
        raise ContractError(f"invalid execution classification: {classification}")

    receipt = {
        "schema": SCHEMA,
        "authority_ref": authority_ref,
        "assignment": {
            "ref": assignment_ref,
            "revision": assignment_revision,
        },
        "placement": {
            "body": "firecracker",
            "venue": venue,
            "visibility": visibility,
            "reasons": reasons,
        },
        "inputs": inputs,
        "body": body,
        "execution": execution,
        "outputs": outputs,
        "validation": validation,
        "cleanup": cleanup,
    }
    validate_receipt(receipt)
    return receipt


def validate_receipt(receipt: dict) -> None:
    if receipt.get("schema") != SCHEMA:
        raise ContractError("wrong receipt schema")

    assignment = receipt.get("assignment") or {}
    if not assignment.get("ref") or not assignment.get("revision"):
        raise ContractError("assignment identity is incomplete")

    placement = receipt.get("placement") or {}
    if placement.get("body") != "firecracker":
        raise ContractError("this receipt describes only Firecracker execution")
    validate_visibility(
        venue=str(placement.get("venue")),
        visibility=str(placement.get("visibility")),
    )
    normalize_reasons(placement.get("reasons") or [])

    execution = receipt.get("execution") or {}
    if execution.get("classification") not in RESULT_CLASSIFICATIONS:
        raise ContractError("invalid/missing execution classification")

    body = receipt.get("body") or {}
    for key in ("firecracker", "kernel", "rootfs", "resources"):
        if key not in body:
            raise ContractError(f"body evidence missing {key}")

    cleanup = receipt.get("cleanup") or {}
    if "ok" not in cleanup:
        raise ContractError("cleanup evidence must state ok true/false")

    outputs = receipt.get("outputs")
    if not isinstance(outputs, dict):
        raise ContractError("outputs must be a mapping")

    # Executor success is evidence, never implicit consequential acceptance.
    if receipt.get("validation") is not None:
        validation = receipt["validation"]
        if not isinstance(validation, dict):
            raise ContractError("validation must be null or a mapping")
        if validation.get("accepted") is True and not validation.get("validator_ref"):
            raise ContractError("accepted validation requires an independent validator reference")


def canonical_json(receipt: dict) -> str:
    validate_receipt(receipt)
    return json.dumps(receipt, sort_keys=True, separators=(",", ":"))


def receipt_digest(receipt: dict) -> str:
    return sha256_bytes(canonical_json(receipt).encode("utf-8"))
