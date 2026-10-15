#!/usr/bin/env python3
"""Independent receipt validator: accepted fixture evidence != personal Graph access."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import microsoft_devproxy_contract as p


class Denied(ValueError):
    pass


def verify(raw: bytes, *, trusted_source: str, trusted_run: str) -> dict:
    if not isinstance(raw, bytes) or len(raw) > 8192 or len(raw) < 100:
        raise Denied("RECEIPT_BYTES_DENIED")
    try:
        r = json.loads(raw.decode("utf-8"), object_pairs_hook=p._object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Denied("RECEIPT_JSON_DENIED") from exc
    fields = {"schema", "data_class", "source_sha", "run_id", "fixture_sha256",
              "image", "image_version", "expected_cases", "passed_cases", "cases",
              "unmocked_status", "provider_access_verified", "identity_verified",
              "max_cost_usd", "classification"}
    if not isinstance(r, dict) or set(r) != fields:
        raise Denied("RECEIPT_FIELDS_DENIED")
    if (not re.fullmatch("[0-9a-f]{40}", trusted_source) or
            not re.fullmatch("[0-9]{1,20}", trusted_run) or
            r["source_sha"] != trusted_source or r["run_id"] != trusted_run):
        raise Denied("SOURCE_RUN_BINDING_DENIED")
    if r["schema"] != "microsoft-mock-contract-receipt/v1":
        raise Denied("RECEIPT_SCHEMA_DENIED")
    if r["data_class"] != "public-synthetic":
        raise Denied("DATA_CLASS_DENIED")
    if r["image"] != p.IMAGE or r["image_version"] != p.IMAGE_VERSION:
        raise Denied("TOOL_DIGEST_DRIFT")
    if r["fixture_sha256"] != p.validate_fixtures():
        raise Denied("FIXTURE_DIGEST_DRIFT")
    if (type(r["expected_cases"]) is not int or type(r["passed_cases"]) is not int or
            r["expected_cases"] != len(p.EXPECTED) or r["passed_cases"] != len(p.EXPECTED)):
        raise Denied("CASE_COUNT_DENIED")
    if (not isinstance(r["cases"], dict) or
            r["cases"] != {key: verdict for key, (_code, verdict) in p.EXPECTED.items()}):
        raise Denied("CASE_VERDICTS_DENIED")
    if type(r["unmocked_status"]) is not int or r["unmocked_status"] != 502:
        raise Denied("UNMOCKED_PROTECTION_DENIED")
    if (r["provider_access_verified"] is not False or
            r["identity_verified"] is not False or
            type(r["max_cost_usd"]) is not int or r["max_cost_usd"] != 0 or
            r["classification"] != "MOCK_ONLY_PASS"):
        raise Denied("MOCK_AUTHORITY_CONFUSION")
    return {
        "schema": "microsoft-mock-independent-verdict/v1",
        "source_sha": trusted_source,
        "run_id": trusted_run,
        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "tool_image": p.IMAGE,
        "expected_cases": len(p.EXPECTED),
        "verified": True,
        "provider_access_verified": False,
        "classification": "MOCK_ONLY_PASS",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--run-id", required=True)
    a = parser.parse_args()
    try:
        result = verify(Path(a.receipt).read_bytes(),
                        trusted_source=a.source, trusted_run=a.run_id)
        dest = Path(a.out)
        if dest.exists() or dest.is_symlink():
            raise Denied("VERDICT_ALREADY_EXISTS")
        dest.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print("MICROSOFT_MOCK_INDEPENDENT_PASS")
    except (OSError, ValueError, p.Denied):
        print("MICROSOFT_MOCK_INDEPENDENT_BLOCKED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
