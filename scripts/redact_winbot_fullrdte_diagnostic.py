#!/usr/bin/env python3
"""Derive a bounded public diagnostic from a decrypted sealed FullRDTE result.

This helper never emits stdout/stderr payloads, credentials, API tokens, file
contents, or arbitrary result fields. It whitelists only orchestration and
qualification state needed to classify the next bounded rep.
"""
from __future__ import annotations

import argparse
import json
import re
import tarfile
from pathlib import Path

MAX_JSON_BYTES = 2 * 1024 * 1024

SAFE_BUILD = {
    "projection_authorized","free_bytes_before","switch_name","download_method",
    "download_seconds","media_size_bytes","image_apply_engine","build_seconds",
    "seed_test_vhd","seed_size_bytes","seed_integrity",
    "iso_reclaimed_before_materialization","seed_unchanged","seed_integrity_after",
}
SAFE_CELL = {
    "materialize_seconds","lineage","ip_observed","api_token_observed",
    "health_status","ready_seconds","runtime_taint_written",
    "prior_runtime_taint_absent","vm_absent_after_dispose",
    "runtime_disk_absent_after_dispose",
}
SAFE_PERSIST = {
    "explicit_attachment","exists_before_a","canary_written",
    "exists_after_a_dispose","canary_survived_rematerialization",
    "b_drive_letter","exists_after_b_dispose","oracle_satisfied",
}
SAFE_CONFORMANCE = {
    "contracts_revision","elapsed_seconds","pytest_exit_code",
    "results_present","summary","oracle_satisfied",
}
SAFE_EXEC = {
    "assignment_id","exit_code","task_exit_code","timed_out","capsule_sha256",
    "worker_revision","run_id","run_attempt","result_budget",
}
SAFE_CLEANUP = {
    "vm_a_absent","vm_b_absent","work_absent","oracle_satisfied",
    "error_type","error_message",
}

def _clean_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = re.sub(r"Wb![0-9A-Fa-f]{20,}", "<redacted-run-credential>", text)
    text = re.sub(r"\b[0-9A-Fa-f]{48,}\b", "<redacted-long-hex>", text)
    text = re.sub(r"(?i)(X-API-Key|WINBOT_API_TOKEN|api[_ -]?token)\s*[:=]\s*\S+",
                  r"\1=<redacted>", text)
    return text[:800]

def _load_member(tf: tarfile.TarFile, name: str) -> dict | None:
    members = [m for m in tf.getmembers() if m.isfile() and m.name == name]
    if not members:
        return None
    if len(members) != 1:
        raise SystemExit(f"unexpected duplicate result member: {name}")
    m = members[0]
    if m.size > MAX_JSON_BYTES:
        raise SystemExit(f"diagnostic JSON exceeds bound: {name}")
    fh = tf.extractfile(m)
    if fh is None:
        raise SystemExit(f"could not read result member: {name}")
    return json.loads(fh.read().decode("utf-8-sig"))

def _pick(source: dict | None, keys: set[str], *, clean_strings: bool = False) -> dict:
    source = source or {}
    out = {}
    for key in sorted(keys):
        if key not in source:
            continue
        value = source[key]
        out[key] = _clean_text(value) if clean_strings and isinstance(value, str) else value
    return out

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--result-tar", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    result_tar = Path(args.result_tar)
    output = Path(args.output)
    with tarfile.open(result_tar, "r:gz") as tf:
        execution = _load_member(tf, "execution.json")
        full = _load_member(tf, "files/full-rdte.json")

    diag: dict[str, object] = {
        "schema_version": 1,
        "scope": "redacted_fullrdte_diagnostic",
        "execution": _pick(execution, SAFE_EXEC),
        "full_rdte": None,
    }
    if full:
        cells = full.get("work_cells") or {}
        cleanup = _pick(full.get("cleanup"), SAFE_CLEANUP, clean_strings=True)
        diag["full_rdte"] = {
            "schema_version": full.get("schema_version"),
            "profile": full.get("profile"),
            "assignment_id": full.get("assignment_id"),
            "source_revision": full.get("source_revision"),
            "projection_identity_sha256": full.get("projection_identity_sha256"),
            "classification": full.get("classification"),
            "failure_domain": full.get("failure_domain"),
            "error_type": full.get("error_type"),
            "error_message": _clean_text(full.get("error_message")),
            "elapsed_seconds": full.get("elapsed_seconds"),
            "build": _pick(full.get("build"), SAFE_BUILD, clean_strings=True),
            "work_cells": {
                "a": _pick(cells.get("a"), SAFE_CELL),
                "b": _pick(cells.get("b"), SAFE_CELL),
            },
            "persistence": _pick(full.get("persistence"), SAFE_PERSIST),
            "conformance": _pick(full.get("conformance"), SAFE_CONFORMANCE),
            "cleanup": cleanup,
        }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(diag, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
