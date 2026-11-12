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
    "python-oci-runtime": {"classification", "oracle_verified", "resolved_image_ref", "receipt_sha256", "production_promotable"},
    "python-ocr-toolchain": {"classification", "oracle_verified", "candidate_base_ref", "built_image_id", "toolchain_versions_sha256", "toolchain_versions", "receipt_sha256", "production_promotable"},
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
    expected_classification = ("PASS_CANDIDATE_ONLY" if p["workload"] in ("python-oci-runtime", "python-ocr-toolchain")
                               else "PASS")
    if result["classification"] != expected_classification or result["oracle_verified"] is not True:
        raise VerdictError("WORKLOAD_ORACLE_NOT_VERIFIED")
    if p["workload"] == "python-ocr-toolchain":
        base = result.get("candidate_base_ref")
        built = result.get("built_image_id")
        inventory = result.get("toolchain_versions_sha256")
        versions = result.get("toolchain_versions")
        digest_ok = (
            isinstance(versions, dict)
            and set(versions) == {"packages", "tools", "pip_inventory", "debian_inventory"}
            and versions.get("packages") == {"pypdf": "7.0.1", "jsonschema": "4.26.0"}
            and versions.get("tools") == {"ghostscript": "10.05.1",
                                           "tesseract": "tesseract 5.5.0",
                                           "poppler": "25.03.0-5+deb13u4"}
            and isinstance(versions.get("pip_inventory"), list)
            and 2 <= len(versions["pip_inventory"]) <= 64
            and all(isinstance(v, str) and
                    re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9._+!:-]+", v)
                    for v in versions["pip_inventory"])
            and isinstance(versions.get("debian_inventory"), dict)
            and set(versions["debian_inventory"]) == {
                "ghostscript", "poppler-utils", "tesseract-ocr", "tesseract-ocr-eng"}
            and all(isinstance(v, str) and
                    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}", v)
                    for v in versions["debian_inventory"].values())
            and hashlib.sha256(json.dumps(versions, sort_keys=True,
                                          separators=(",", ":")).encode()).hexdigest() == inventory
        )
        receipt_sha = result.get("receipt_sha256")
        if (not digest_ok
                or result.get("production_promotable") is not False
                or base != "python@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f"
                or not isinstance(built, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", built) is None
                or not isinstance(inventory, str) or not HEX64.fullmatch(inventory)
                or not isinstance(receipt_sha, str) or not HEX64.fullmatch(receipt_sha)):
            raise VerdictError("OCR_CANDIDATE_RECEIPT_DENIED")
    if p["workload"] == "python-oci-runtime":
        image = result.get("resolved_image_ref")
        if (result.get("production_promotable") is not False
                or not isinstance(image, str)
                or re.fullmatch(r"[a-zA-Z0-9./_-]+@sha256:[a-f0-9]{64}", image) is None
                or not isinstance(result.get("receipt_sha256"), str)
                or not HEX64.fullmatch(result["receipt_sha256"])):
            raise VerdictError("OCI_CANDIDATE_RECEIPT_DENIED")
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
