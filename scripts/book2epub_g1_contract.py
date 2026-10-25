#!/usr/bin/env python3
"""Book2EPUB pre-admission evidence reducer: one safe status for three audiences.

This is an OFFLINE verifier of *shape*, not a runtime verifier or authority grant.
Only a separately admitted independent actor may validate external receipts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

INPUT_SCHEMA = "book2epub-pre-admission-evidence/v1"
OUTPUT_SCHEMA = "book2epub-pre-admission-status/v1"
TARGET = "TrueNAS-25.04.2.6"
KIND = frozenset({
    "source_unit", "guest_middleware", "registry_network",
    "engine_digest_pull", "offline_image_load", "product_rights",
    "product_lifecycle", "epub_reader", "owned_cleanup",
})
RESULT = frozenset({"PASS", "FAIL", "NOT_RUN", "BLOCKED", "INCONCLUSIVE"})
ACTOR = frozenset({"producer", "executor", "independent-validator"})
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
IDENT = re.compile(r"[a-z0-9][a-z0-9._-]{2,79}\Z")
REF = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/"
    r"(?:actions/runs/[0-9]+|issues/[0-9]+(?:#issuecomment-[0-9]+)?|pull/[0-9]+)\Z"
)
ROOT_KEYS = frozenset({"schema", "session_id", "target", "source_sha", "evidence"})
EVIDENCE_KEYS = frozenset({"id", "kind", "actor", "result", "ref", "source_sha"})
HOLD = {
    "g1a": "INDEPENDENT_GUEST_ROLE_TRANSPORT_AND_SLOT_RECEIPT_REQUIRED",
    "g1b": "BENIGN_DIGEST_TRANSFER_AND_CLEANUP_NOT_VERIFIED",
    "g2": "PRODUCT_RIGHTS_OCI_MAF_SITE_APPROVAL_UNBOUND",
    "g3": "PRODUCT_F_AND_H_ORACLES_NOT_VERIFIED",
    "physical_apply": "SEPARATE_PHYSICAL_AUTHORIZATION_REQUIRED",
}
NEXT = "Qualify independent one-use TrueNAS 25.04.2.6 guest role and transport before G1a"
REASONS = {
    "source_unit": "Source-only unit test",
    "guest_middleware": "Guest middleware status",
    "registry_network": "Registry endpoint reachability",
    "engine_digest_pull": "Engine-level OCI digest pull",
    "offline_image_load": "Digest checked offline image load",
    "product_rights": "Product rights and source admission",
    "product_lifecycle": "Product lifecycle",
    "epub_reader": "Independent EPUB reader quality",
    "owned_cleanup": "Owned resource teardown",
}


class ContractError(ValueError):
    pass


def _string(value, pattern, name):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ContractError("invalid_" + name)
    return value


def _strict_keys(obj, allowed, name):
    if not isinstance(obj, dict) or set(obj) != allowed:
        raise ContractError("invalid_" + name + "_keys")


def assess(document):
    _strict_keys(document, ROOT_KEYS, "root")
    if document["schema"] != INPUT_SCHEMA or document["target"] != TARGET:
        raise ContractError("invalid_schema_or_target")
    sid = _string(document["session_id"], IDENT, "session_id")
    source = _string(document["source_sha"], SHA40, "source_sha")
    items = document["evidence"]
    if not isinstance(items, list) or len(items) > 24:
        raise ContractError("evidence_count_out_of_bounds")
    seen = set()
    safe = []
    for i, item in enumerate(items):
        _strict_keys(item, EVIDENCE_KEYS, "evidence")
        eid = _string(item["id"], IDENT, "evidence_id")
        if eid in seen:
            raise ContractError("duplicate_evidence_id")
        seen.add(eid)
        if item["kind"] not in KIND or item["actor"] not in ACTOR or item["result"] not in RESULT:
            raise ContractError("unrecognized_evidence_category")
        _string(item["ref"], REF, "evidence_ref")
        _string(item["source_sha"], SHA40, "evidence_source_sha")
        if item["source_sha"] != source:
            raise ContractError("mixed_source_revision")
        safe.append({
            "id": eid,
            "kind": item["kind"],
            "description": REASONS[item["kind"]],
            "reported_result": item["result"],
            "actor_role_claim": item["actor"],
            "ref": item["ref"],
            "verification": "EXTERNAL_VALIDATION_NOT_PERFORMED",
        })
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return {
        "schema": OUTPUT_SCHEMA,
        "session_id": sid,
        "target": TARGET,
        "source_sha": source,
        "input_sha256": hashlib.sha256(canonical).hexdigest(),
        "contract_validation": "VALID",
        "qualification": "EXTERNAL_EVIDENCE_NOT_INDEPENDENTLY_VERIFIED",
        "dispatch_authorized": False,
        "release_authorized": False,
        "all_gates": {k: {"state": "HOLD", "reason_code": v} for k, v in HOLD.items()},
        "evidence_count": len(safe),
        "reported_evidence": safe,
        "next_ready": NEXT,
    }


def human_text(status, markdown=False):
    """The same sanitized status for accessible human UI, automation and agents."""
    if status.get("schema") != OUTPUT_SCHEMA or status.get("qualification") != "EXTERNAL_EVIDENCE_NOT_INDEPENDENTLY_VERIFIED":
        raise ContractError("untrusted_status_not_renderable")
    if markdown:
        lines = ["# Book2EPUB qualification status", "",
                 "**State: HOLD — external evidence not independently verified**", "",
                 f"Session: \`{status['session_id']}\`", f"Target: \`{status['target']}\`",
                 f"Source commit: \`{status['source_sha']}\`", ""]
        lines.append("## Required gates")
        for stage, gate in status["all_gates"].items():
            lines.append(f"- **{stage.upper()}: HOLD** — {gate['reason_code'].replace('_', ' ').lower()}")
        lines.append("")
        lines.append("## Reported evidence (not verified)")
        for row in status["reported_evidence"]:
            lines.append(f"- {row['description']}: {row['reported_result']} (unverified; {row['ref']})")
        if not status["reported_evidence"]:
            lines.append("- No evidence supplied")
        lines.extend(["", "## Next admissible step", status["next_ready"]])
        return "\n".join(lines) + "\n"
    lines = [
        "Book2EPUB: HOLD — external evidence not independently verified",
        f"Session: {status['session_id']}  Target: {status['target']}",
        f"Reported items (unverified): {status['evidence_count']}",
    ]
    lines.extend(f"{k.upper()}: HOLD — {v['reason_code']}" for k, v in status["all_gates"].items())
    lines.append("Next: " + status["next_ready"])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=pathlib.Path, required=True)
    parser.add_argument("--format", choices=("json", "text", "markdown"), default="json")
    args = parser.parse_args(argv)
    try:
        source = args.file.read_text(encoding="utf-8")
        if len(source) > 131072:
            raise ContractError("input_too_large")
        result = assess(json.loads(source))
        if args.format == "json":
            print(json.dumps(result, sort_keys=True, indent=2))
        else:
            print(human_text(result, args.format == "markdown"), end="")
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, ContractError):
        # Do not echo untrusted paths, errors, responses or incidental secrets.
        print("ERROR: invalid pre-admission evidence; no authorization granted", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
