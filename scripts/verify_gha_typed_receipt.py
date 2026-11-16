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
    "mail-openworker-headless-mail": {
        "classification", "oracle_verified", "upstream_commit",
        "connector_blob_sha", "headless_blob_sha", "control_count",
        "fake_readonly", "duplicate_attachments_visible", "no_smtp_attempts",
        "isolated_defaults", "same_name_second_unaddressable",
        "attachment_download_occurrence_complete", "real_mail", "model_inference",
        "headless_engine_run", "verdict_sha256"},
    "mail-openworker-scripted": {
        "classification", "oracle_verified", "source_commit",
        "scripted_provider_only", "headless_engine_executed",
        "approval_denial_verified", "clean_restart_verified", "real_mail",
        "model_inference", "dependency_hash_locked", "atif_schema",
        "run_count", "denied_calls", "package_count", "dependency_sha256",
        "venv_size_bytes", "elapsed_seconds", "verdict_sha256"},
    "mail-qwen-real-cpu": {
        "classification", "oracle_verified", "real_model_inference",
        "automatic_promotion", "model_sha256", "engine_commit",
        "question_count", "model_calls", "selected_policy", "heldout_exact",
        "baseline_exact", "heldout_valid", "baseline_valid",
        "selected_cases", "baseline_cases", "dev_exact_scores",
        "unsupported_source_count", "semantic_quality_gate",
        "corpus_sha256", "verdict_sha256"},
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


# Independently authored replica of the frozen synthetic held-out answer oracle.
# These labels are never sent to the real model, only reviewed by verifier.
MODEL_HOLDOUT_GOLD = {
    "H1": ("en", "b1", "150"),
    "H2": ("en", "a1", "120"),
    "H3": ("de", "a3", "denied"),
    "H4": ("th", "a4", "approved"),
    "H5": ("en", "NONE", "UNKNOWN"),
    "H6": ("de", "a2", "Friday"),
    "H7": ("en", "NONE", "UNKNOWN"),
}
MODEL_ALLOWED_IDS = {"a1","a2","b1","a3","a4","a5","c1","NONE"}
MODEL_ALLOWED_VALUES = {"120","150","Friday","denied","approved","pending","UNKNOWN"}
MODEL_CASE_FIELDS = {"id","language","valid_json","exact","incorrect_source",
                     "abstained","duration_ms","output_sha256","source_id","value"}


def grade_public_model_cases(cases: list) -> dict:
    if not isinstance(cases,list) or len(cases)!=len(MODEL_HOLDOUT_GOLD):
        raise VerdictError("MODEL_CASE_COUNT_INVALID")
    observed={}
    for case in cases:
        if not isinstance(case,dict) or set(case)!=MODEL_CASE_FIELDS:
            raise VerdictError("MODEL_CASE_FIELDS_INVALID")
        identifier=case.get("id")
        if identifier not in MODEL_HOLDOUT_GOLD or identifier in observed:
            raise VerdictError("MODEL_CASE_IDS_INVALID")
        lang,truth_id,truth_value=MODEL_HOLDOUT_GOLD[identifier]
        if case.get("language")!=lang:
            raise VerdictError("MODEL_LANGUAGE_SCOPE_INVALID")
        source=case.get("source_id")
        value=case.get("value")
        allowed=(source in MODEL_ALLOWED_IDS and value in MODEL_ALLOWED_VALUES)
        exact=allowed and source==truth_id and value==truth_value
        wrong=(source not in ("NONE",truth_id)) if allowed else True
        abstained=source=="NONE"
        if (case.get("valid_json") is not allowed or
                case.get("exact") is not exact or
                case.get("incorrect_source") is not wrong or
                case.get("abstained") is not abstained or
                type(case.get("duration_ms")) is not int or
                not 0<=case["duration_ms"]<=30_000 or
                not isinstance(case.get("output_sha256"),str) or
                not HEX64.fullmatch(case["output_sha256"])):
            raise VerdictError("MODEL_CASE_ORACLE_MISMATCH")
        observed[identifier]=case
    return {
        "exact":sum(x["exact"] for x in observed.values()),
        "valid":sum(x["valid_json"] for x in observed.values()),
        "unsupported":sum(x["incorrect_source"] for x in observed.values()),
        "abstained":sum(x["abstained"] for x in observed.values()),
    }


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
    if p["workload"] == "mail-qwen-real-cpu":
        if (result.get("real_model_inference") is not True or
                result.get("automatic_promotion") is not False or
                result.get("model_sha256") != "9ee36184e616dfc76df4f5dd66f908dbde6979524ae36e6cefb67f532f798cb8" or
                result.get("engine_commit") != "b4c0e00a4fcc0287d0bb32fd7cb0d8b286af73ed" or
                result.get("question_count") != 7 or
                result.get("model_calls") != 20 or
                result.get("selected_policy") not in ("plain","evidence-first") or
                type(result.get("heldout_exact")) is not int or
                not 0 <= result["heldout_exact"] <= 7 or
                type(result.get("baseline_exact")) is not int or
                not 0 <= result["baseline_exact"] <= 7 or
                type(result.get("unsupported_source_count")) is not int or
                not 0 <= result["unsupported_source_count"] <= 7 or
                type(result.get("semantic_quality_gate")) is not bool or
                not isinstance(result.get("corpus_sha256"), str) or
                not HEX64.fullmatch(result["corpus_sha256"]) or
                not isinstance(result.get("verdict_sha256"), str) or
                not HEX64.fullmatch(result["verdict_sha256"])):
            raise VerdictError("REAL_MODEL_INFERENCE_OR_SCOPE_INVALID")
        if (type(result.get("heldout_valid")) is not int or
                not 0 <= result["heldout_valid"] <= 7 or
                type(result.get("baseline_valid")) is not int or
                not 0 <= result["baseline_valid"] <= 7):
            raise VerdictError("MODEL_CASE_QUALITY_COUNTS_INVALID")
        scores=result.get("dev_exact_scores")
        if (not isinstance(scores,dict) or set(scores)!={"plain","evidence-first"}
                or any(type(n) is not int or not 0<=n<=3 for n in scores.values())):
            raise VerdictError("MODEL_DEV_POLICY_SCORES_INVALID")
        chosen=sorted(("plain","evidence-first"),
            key=lambda k:(-scores[k],("plain","evidence-first").index(k)))[0]
        if chosen!=result["selected_policy"]:
            raise VerdictError("MODEL_POLICY_SELECTED_FROM_HOLDOUT")
        chosen_metrics=grade_public_model_cases(result.get("selected_cases"))
        baseline_metrics=grade_public_model_cases(result.get("baseline_cases"))
        if (chosen_metrics["exact"]!=result["heldout_exact"] or
                chosen_metrics["valid"]!=result["heldout_valid"] or
                chosen_metrics["unsupported"]!=result["unsupported_source_count"] or
                baseline_metrics["exact"]!=result["baseline_exact"] or
                baseline_metrics["valid"]!=result["baseline_valid"] or
                result["semantic_quality_gate"] is not
                    (chosen_metrics["exact"]>=6 and chosen_metrics["unsupported"]==0)):
            raise VerdictError("MODEL_INDEPENDENT_GOLD_METRIC_MISMATCH")
    if p["workload"] == "mail-openworker-scripted":
        if (result.get("source_commit") != "ecb445490fc054d52b8ea610d97ba947f57033d2" or
                result.get("scripted_provider_only") is not True or
                result.get("headless_engine_executed") is not True or
                result.get("approval_denial_verified") is not True or
                result.get("clean_restart_verified") is not True or
                result.get("real_mail") is not False or
                result.get("model_inference") is not False or
                result.get("dependency_hash_locked") is not False or
                result.get("atif_schema") != "ATIF-v1.7" or
                result.get("run_count") != 2 or
                type(result.get("denied_calls")) is not int or
                result["denied_calls"] < 2 or
                type(result.get("package_count")) is not int or
                result["package_count"] < 1 or
                type(result.get("venv_size_bytes")) is not int or
                result["venv_size_bytes"] < 1 or
                not isinstance(result.get("elapsed_seconds"), (float, int)) or
                not isinstance(result.get("dependency_sha256"), str) or
                not HEX64.fullmatch(result["dependency_sha256"]) or
                not isinstance(result.get("verdict_sha256"), str) or
                not HEX64.fullmatch(result["verdict_sha256"])):
            raise VerdictError("OPENWORKER_SCRIPTED_SCOPE_OR_PROVENANCE_INVALID")
    if p["workload"] == "mail-openworker-headless-mail":
        if (result.get("upstream_commit") != "ecb445490fc054d52b8ea610d97ba947f57033d2" or
                result.get("connector_blob_sha") != "7be4e1f9e78e8fd9d1ef81b58bbc86a916c48e76" or
                result.get("headless_blob_sha") != "3cadae25bd4a3c90d363ae296522058e578af917" or
                result.get("control_count") != 12 or
                result.get("fake_readonly") is not True or
                result.get("duplicate_attachments_visible") is not True or
                result.get("no_smtp_attempts") is not True or
                result.get("same_name_second_unaddressable") is not True or
                result.get("attachment_download_occurrence_complete") is not False or
                result.get("isolated_defaults") is not True or
                result.get("real_mail") is not False or
                result.get("model_inference") is not False or
                result.get("headless_engine_run") is not False or
                not isinstance(result.get("verdict_sha256"), str) or
                not HEX64.fullmatch(result["verdict_sha256"])):
            raise VerdictError("ORIGINAL_OPENWORKER_FAKE_MAIL_SCOPE_INVALID")
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
