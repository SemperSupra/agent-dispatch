#!/usr/bin/env python3
"""Use reviewed CPU profiles with one dynamic public-synthetic DLE envelope.

No scheduler, network call, credential, arbitrary code, dynamic workflow or
runner input. Caller/native replay admission remains a Sidecar responsibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

import gha_assignment_contract as contract
import gha_workload_request as profile

RECEIPT_V2 = "gha-workload-receipt/v2"


def plan(raw: str, source_sha: str) -> dict:
    return contract.admit(raw, trusted_source_sha=source_sha)


def run(raw: str, source_sha: str, digest: str) -> dict:
    p = plan(raw, source_sha)
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or p["assignment_sha256"] != digest:
        raise contract.Denied("ASSIGNMENT_DIGEST_DRIFT")
    native = profile.run(p["profile_path"], p["profile_sha256"])
    native.update({
        "schema": RECEIPT_V2,
        "assignment_id": p["assignment_id"],
        "assignment_sha256": p["assignment_sha256"],
        "authority_sha256": p["authority_sha256"],
        "profile_id": p["profile_id"],
        "nonce_sha256": hashlib.sha256(p["nonce"].encode("ascii")).hexdigest(),
        "expires_at": p["expires_at"],
    })
    return native


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--action", choices=["plan", "run"], required=True)
    ap.add_argument("--assignment", required=True)
    ap.add_argument("--source-sha", required=True)
    ap.add_argument("--digest", default="")
    ap.add_argument("--github-output", default="")
    ap.add_argument("--receipt", default="")
    args = ap.parse_args()
    try:
        p = plan(args.assignment, args.source_sha)
        if args.action == "plan":
            if not args.github_output:
                raise contract.Denied("OUTPUT_PATH_REQUIRED")
            with open(args.github_output, "a", encoding="utf-8") as fh:
                for key, value in (
                    ("runner", p["runner"]), ("request_path", p["profile_path"]),
                    ("request_sha256", p["profile_sha256"]),
                    ("assignment_sha256", p["assignment_sha256"]),
                    ("assignment_id", p["assignment_id"]),
                ):
                    fh.write(f"{key}={value}\n")
            print("GHA_DLE_PLAN_ADMITTED=true")
            return 0
        if not args.receipt:
            raise contract.Denied("RECEIPT_PATH_REQUIRED")
        result = run(args.assignment, args.source_sha, args.digest)
        dest = Path(args.receipt)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print("GHA_DLE_WORKLOAD_QUALIFIED=" + str(result["qualified"]).lower())
        return 0 if result["qualified"] is True else 2
    except (contract.Denied, profile.Denied, OSError):
        print("GHA_DLE_ASSIGNMENT_DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
