#!/usr/bin/env python3
"""Independent native GHA source/runner/artifact/oracle check for v2 DLE receipts.

Native run/source/runner/receipt hash must be supplied by the observer, not
copied from the worker. DLE authority and duplicate-dispatch checks remain
separately mandatory for reconciliation; a green workflow is not authorization.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

import gha_assignment_contract as assignment
import gha_assignment_execute as executor
import gha_workload_request as profile
import verify_gha_typed_receipt as base

ADDITIONAL = {
    "assignment_sha256", "authority_sha256", "profile_id",
    "nonce_sha256", "expires_at",
}
FIELDS = base.RECEIPT_FIELDS | ADDITIONAL


def evaluate(*, assignment_json: str, receipt_bytes: bytes,
             trusted_source_sha: str, trusted_run_id: str,
             trusted_runner: str, trusted_receipt_sha256: str,
             now: datetime | None = None,
             trusted_native_created_at: str | None = None) -> dict:
    if not base.HEX64.fullmatch(trusted_receipt_sha256):
        raise base.VerdictError("TRUSTED_ARTIFACT_SHA_INVALID")
    if not (50 <= len(receipt_bytes) <= base.MAX_RECEIPT):
        raise base.VerdictError("RECEIPT_SIZE_OUT_OF_BOUNDS")
    if hashlib.sha256(receipt_bytes).hexdigest() != trusted_receipt_sha256:
        raise base.VerdictError("RECEIPT_ARTIFACT_HASH_MISMATCH")
    # Live runner verification uses the current clock. Durable independent
    # reconciliation may instead use the provider's *native* run creation
    # timestamp. Never derive this from a self-reported worker receipt.
    if trusted_native_created_at is not None:
        if now is not None:
            raise base.VerdictError("AMBIGUOUS_TRUSTED_TIME")
        try:
            witness = assignment._timestamp(trusted_native_created_at)
        except assignment.Denied as exc:
            raise base.VerdictError("NATIVE_CREATED_AT_INVALID") from exc
    else:
        witness = now
    p = assignment.admit(
        assignment_json, trusted_source_sha=trusted_source_sha, now=witness)
    doc = base.strict_json(receipt_bytes)
    if not isinstance(doc, dict) or set(doc) != FIELDS:
        raise base.VerdictError("V2_RECEIPT_FIELDS_DENIED")
    if doc["schema"] != executor.RECEIPT_V2:
        raise base.VerdictError("V2_RECEIPT_SCHEMA_DENIED")
    required = {
        "assignment_id": p["assignment_id"],
        "assignment_sha256": p["assignment_sha256"],
        "authority_sha256": p["authority_sha256"],
        "profile_id": p["profile_id"],
        "nonce_sha256": hashlib.sha256(p["nonce"].encode("ascii")).hexdigest(),
        "expires_at": p["expires_at"],
    }
    if any(doc.get(key) != value for key, value in required.items()):
        raise base.VerdictError("DLE_ASSIGNMENT_PROVENANCE_MISMATCH")
    fixed = profile.plan(p["profile_path"])
    older = {key: doc[key] for key in base.RECEIPT_FIELDS}
    older["schema"] = profile.RECEIPT
    older["assignment_id"] = fixed["assignment_id"]
    # Reuse the existing independent workload oracle on the exact reviewed
    # profile, while verifying the true outer artifact hash above.
    inner = (json.dumps(older, sort_keys=True, indent=2) + "\n").encode("utf-8")
    existing = base.evaluate(
        manifest_path=p["profile_path"], receipt_bytes=inner,
        trusted_source_sha=trusted_source_sha, trusted_run_id=trusted_run_id,
        trusted_runner=trusted_runner,
        trusted_receipt_sha256=hashlib.sha256(inner).hexdigest())
    return {
        "schema": "gha-dle-native-verdict/v1",
        "classification": "PASS",
        "assignment_id": p["assignment_id"],
        "assignment_sha256": p["assignment_sha256"],
        "authority_sha256": p["authority_sha256"],
        "profile_id": p["profile_id"],
        "profile_sha256": p["profile_sha256"],
        "native_run_id": trusted_run_id,
        "admission_time_basis": (
            "provider-native-run-created-at"
            if trusted_native_created_at is not None else "live-verification-clock"
        ),
        "trusted_native_created_at": trusted_native_created_at,
        "native_runner": trusted_runner,
        "source_sha": trusted_source_sha,
        "receipt_sha256": trusted_receipt_sha256,
        "oracle_classification": existing["classification"],
        "limitation": "Does not independently prove Sidecar caller admission or no-duplicate native dispatch; reconcile from DLE and GitHub API.",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--assignment-json", required=True)
    ap.add_argument("--receipt", type=Path, required=True)
    ap.add_argument("--source-sha", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--runner", required=True)
    ap.add_argument("--sha256", required=True)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--native-created-at",
                    help="UTC timestamp from independently authenticated GitHub Actions run metadata, not a worker field")
    args = ap.parse_args()
    try:
        result = evaluate(
            assignment_json=args.assignment_json, receipt_bytes=args.receipt.read_bytes(),
            trusted_source_sha=args.source_sha, trusted_run_id=args.run_id,
            trusted_runner=args.runner, trusted_receipt_sha256=args.sha256,
            trusted_native_created_at=args.native_created_at)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print("GHA_DLE_INDEPENDENT_VERDICT=PASS")
        return 0
    except (base.VerdictError, assignment.Denied, profile.Denied, OSError):
        print("GHA_DLE_INDEPENDENT_VERDICT=FAIL", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
