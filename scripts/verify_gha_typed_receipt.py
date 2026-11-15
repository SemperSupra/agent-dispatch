#!/usr/bin/env python3
"""Independently reduce an Agent Dispatch typed public CPU receipt.

Expects authoritative GitHub native run/source/runner metadata and an
artifact checksum *from outside the receipt*. The worker's self-reported
"qualified" boolean alone is never evidence of qualification. No API,
credentials, private data or scheduling; deterministic offline verification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gha_workload_request as request

SCHEMA = "gha-workload-verdict/v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
RECEIPT_FIELDS = {
    "schema", "assignment_id", "data_class", "observed_architecture",
    "qualified", "request_path", "request_sha256", "requested_runner",
    "result", "run_attempt", "run_id", "shape_verified", "source_sha",
    "workload",
}
RESULT_FIELDS = {
    "arithmetic-oracle": {
        "classification", "oracle_verified", "task_count", "fixture_sha256"},
    "sealed-contract-native": {"classification", "oracle_verified"},
    "microsoft-devproxy-mock": {"classification", "oracle_verified", "mock_only", "provider_access_verified", "verdict_sha256"},
    "azurite-blob-transport": {"classification", "oracle_verified", "emulator_only", "provider_access_verified", "verdict_sha256"},
    "mail-synthetic-baseline": {
        "classification", "oracle_verified", "retrieval_only",
        "model_inference", "query_count", "fixture_sha256"},
    "mail-openworker-policy": {
        "classification", "oracle_verified", "model_inference",
        "mail_credential_access", "source_blob_sha", "control_count",
        "upstream_commit", "verdict_sha256"},
    "mail-ragmail-loss-witness": {
        "classification", "oracle_verified", "upstream_commit", "source_blob_sha",
        "evidence_loss_confirmed", "dropped_messages", "dropped_attachments",
        "reader_qualified", "verdict_sha256"},
    "mail-evidence-go-challenge": {
        "classification", "oracle_verified", "typed_only", "model_inference",
        "question_count", "source_occurrences", "attachment_occurrences",
        "false_merge_count", "cross_tenant_leaks", "restart_verified",
        "native_pst_qualified", "corpus_sha256", "verdict_sha256"},
}
MAX_RECEIPT = 8192


class VerdictError(ValueError):
    pass


def strict_json(raw: bytes):
    def no_duplicate(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise VerdictError("DUPLICATE_RECEIPT_KEY")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=no_duplicate)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VerdictError("RECEIPT_JSON_INVALID") from exc


def evaluate(
    *, manifest_path: str, receipt_bytes: bytes, trusted_source_sha: str,
    trusted_run_id: str, trusted_runner: str, trusted_receipt_sha256: str,
) -> dict:
    if len(receipt_bytes) < 50 or len(receipt_bytes) > MAX_RECEIPT:
        raise VerdictError("RECEIPT_SIZE_OUT_OF_BOUNDS")
    if not HEX64.fullmatch(trusted_receipt_sha256):
        raise VerdictError("TRUSTED_ARTIFACT_SHA_INVALID")
    if hashlib.sha256(receipt_bytes).hexdigest() != trusted_receipt_sha256:
        raise VerdictError("RECEIPT_ARTIFACT_HASH_MISMATCH")
    if not HEX40.fullmatch(trusted_source_sha) or not RUN_ID.fullmatch(trusted_run_id):
        raise VerdictError("NATIVE_RUN_IDENTITY_INVALID")
    doc = strict_json(receipt_bytes)
    if not isinstance(doc, dict) or set(doc) != RECEIPT_FIELDS:
        raise VerdictError("RECEIPT_SCHEMA_FIELDS_UNTRUSTED")
    if doc["schema"] != request.RECEIPT:
        raise VerdictError("RECEIPT_SCHEMA_MISMATCH")
    p = request.plan(manifest_path)
    must_match = {
        "request_path": manifest_path,
        "request_sha256": p["request_sha256"],
        "assignment_id": p["assignment_id"],
        "requested_runner": p["runner"],
        "workload": p["workload"],
        "data_class": "public-synthetic",
        "source_sha": trusted_source_sha,
        "run_id": trusted_run_id,
        "run_attempt": "1",
    }
    if not all(doc.get(k) == v for k, v in must_match.items()):
        raise VerdictError("RECEIPT_PROVENANCE_MISMATCH")
    if trusted_runner != p["runner"]:
        raise VerdictError("NATIVE_RUNNER_LABEL_MISMATCH")
    if (doc.get("observed_architecture") != p["expected_machine"]
            or doc["shape_verified"] is not True):
        raise VerdictError("NATIVE_SHAPE_NOT_VERIFIED")
    if doc["qualified"] is not True:
        raise VerdictError("WORKLOAD_NOT_QUALIFIED")
    result = doc["result"]
    if not isinstance(result, dict) or set(result) != RESULT_FIELDS[p["workload"]]:
        raise VerdictError("WORKLOAD_RESULT_FIELDS_UNTRUSTED")
    if result["classification"] != "PASS" or result["oracle_verified"] is not True:
        raise VerdictError("WORKLOAD_ORACLE_NOT_VERIFIED")
    if p["workload"] == "microsoft-devproxy-mock":
        if (result.get("mock_only") is not True or
                result.get("provider_access_verified") is not False or
                not isinstance(result.get("verdict_sha256"), str) or
                not HEX64.fullmatch(result["verdict_sha256"])):
            raise VerdictError("MOCK_RECEIPT_AUTHORITY_DENIED")
    if p["workload"] == "azurite-blob-transport":
        if (result.get("emulator_only") is not True or
                result.get("provider_access_verified") is not False or
                not isinstance(result.get("verdict_sha256"), str) or
                not HEX64.fullmatch(result["verdict_sha256"])):
            raise VerdictError("EMULATOR_RECEIPT_AUTHORITY_DENIED")
    if p["workload"] == "mail-evidence-go-challenge":
        if (result.get("typed_only") is not True or
                result.get("model_inference") is not False or
                result.get("question_count") != 21 or
                result.get("source_occurrences") != 8 or
                result.get("attachment_occurrences") != 5 or
                result.get("false_merge_count") != 0 or
                result.get("cross_tenant_leaks") != 0 or
                result.get("restart_verified") is not True or
                result.get("native_pst_qualified") is not False or
                not isinstance(result.get("corpus_sha256"), str) or
                not HEX64.fullmatch(result["corpus_sha256"]) or
                not isinstance(result.get("verdict_sha256"), str) or
                not HEX64.fullmatch(result["verdict_sha256"])):
            raise VerdictError("GO_EVIDENCE_SCOPE_OR_GOLD_MISMATCH")
    if p["workload"] == "mail-ragmail-loss-witness":
        if (result.get("evidence_loss_confirmed") is not True or
                result.get("reader_qualified") is not False or
                result.get("dropped_messages") != 2 or
                result.get("dropped_attachments") != 1 or
                result.get("upstream_commit") !=
                "afab46bfdd83d11af8bacee8231871ff1292fced" or
                result.get("source_blob_sha") !=
                "5a9ee91a0f1b7d04439ab8808bf7b1c88df868d6" or
                not isinstance(result.get("verdict_sha256"), str) or
                not HEX64.fullmatch(result["verdict_sha256"])):
            raise VerdictError("RAGMAIL_NEGATIVE_ORACLE_NOT_VERIFIED")
    if p["workload"] == "mail-openworker-policy":
        if (result.get("model_inference") is not False or
                result.get("mail_credential_access") is not False or
                result.get("upstream_commit") !=
                "ecb445490fc054d52b8ea610d97ba947f57033d2" or
                result.get("source_blob_sha") !=
                "d621e606eea85be031c27237b0bc2ffcdfe590cb" or
                result.get("control_count") != 8 or
                not isinstance(result.get("verdict_sha256"), str) or
                not HEX64.fullmatch(result["verdict_sha256"])):
            raise VerdictError("UPSTREAM_POLICY_SCOPE_MISMATCH")
    if p["workload"] == "mail-synthetic-baseline":
        if (result.get("retrieval_only") is not True or
                result.get("model_inference") is not False or
                result.get("query_count") != 9 or
                not isinstance(result.get("fixture_sha256"), str) or
                not HEX64.fullmatch(result["fixture_sha256"])):
            raise VerdictError("SYNTHETIC_MAIL_SCOPE_OR_RECEIPT_MISMATCH")
    if p["workload"] == "arithmetic-oracle":
        nums = [i**2 for i in range(256)]
        independent_digest = hashlib.sha256(
            json.dumps(nums, separators=(",", ":")).encode()).hexdigest()
        if result.get("task_count") != 256 or result.get("fixture_sha256") != independent_digest:
            raise VerdictError("ARITHMETIC_ORACLE_MISMATCH")
    return {
        "schema": SCHEMA,
        "assignment_id": p["assignment_id"],
        "native_run_id": trusted_run_id,
        "native_runner": trusted_runner,
        "source_sha": trusted_source_sha,
        "request_sha256": p["request_sha256"],
        "receipt_sha256": trusted_receipt_sha256,
        "classification": "PASS",
        "meaning": "provider-linked public CPU workcell and fixed workload receipt validated",
        "limitation": "does not attest Sidecar admission, autonomous workflow dispatch, or private workloads",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--runner", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        data = args.receipt.read_bytes()
        result = evaluate(
            manifest_path=args.request,
            receipt_bytes=data,
            trusted_source_sha=args.source_sha,
            trusted_run_id=args.run_id,
            trusted_runner=args.runner,
            trusted_receipt_sha256=args.sha256,
        )
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print("GHA_RECEIPT_INDEPENDENT_VERDICT=PASS")
        return 0
    except (VerdictError, request.Denied, OSError) as exc:
        # Only internal uppercase error codes, never raw private provider data.
        reason = str(exc) if isinstance(exc, VerdictError) else "UNTRUSTED_EVIDENCE"
        print("GHA_RECEIPT_INDEPENDENT_VERDICT=FAIL_" + reason, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
