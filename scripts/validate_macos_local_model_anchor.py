#!/usr/bin/env python3
"""Independent validator for the generation-neutral macOS local-model anchor."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from typing import Any

RAW_SCHEMA = "macos-local-model-anchor/raw-v2"
VALIDATION_SCHEMA = "macos-local-model-anchor/validation-v2"
EXPECTED_MODEL_SHA256 = "8030f04528538d47bda434f6f0bdf3952c40a58123e4d5e755332f23731a8684"
EXPECTED_MODEL_SIZE = 105454144
EXPECTED_LLAMA_COMMIT = "b29c606e28a01b1bc8c1351026a0fa6e616bf6c4"
EXPECTED_REPETITIONS = 2
EXPECTED_TASK_CLASS = "runtime.local-model-deterministic-inference"

def check(raw: dict[str, Any]) -> tuple[bool, list[str], list[str]]:
    errors: list[str] = []
    notes: list[str] = []

    if raw.get("schema") != RAW_SCHEMA:
        errors.append("raw-schema-mismatch")

    model = raw.get("model") or {}
    download = raw.get("download") or {}
    runtime = raw.get("runtime") or {}
    task = raw.get("task") or {}
    host = raw.get("host_profile") or {}
    preflight = raw.get("metal_preflight") or {}
    reps = raw.get("repetitions") or []

    if model.get("expected_sha256") != EXPECTED_MODEL_SHA256:
        errors.append("model-contract-sha-mismatch")
    if download.get("sha256") != EXPECTED_MODEL_SHA256:
        errors.append("downloaded-model-sha-mismatch")
    if download.get("size") != EXPECTED_MODEL_SIZE:
        errors.append("downloaded-model-size-mismatch")
    if download.get("ok") is not True:
        errors.append("download-integrity-not-proven")

    if runtime.get("resolved_commit") != EXPECTED_LLAMA_COMMIT:
        errors.append("llama-runtime-commit-mismatch")
    if task.get("task_class") != EXPECTED_TASK_CLASS:
        errors.append("task-class-mismatch")
    if task.get("evidence_mode") != "anchor":
        errors.append("evidence-mode-mismatch")
    if "--single-turn" not in (task.get("generation_args") or []):
        errors.append("single-turn-lifecycle-missing")

    if host.get("machine") != "arm64":
        errors.append("not-arm64")
    # Deliberately do not require an M-generation string. Future hardware is admitted by capability.
    if preflight.get("classification") != "SUPPORTED":
        errors.append("metal-preflight-not-supported")
    families = ((preflight.get("evidence") or {}).get("families") or {})
    if not isinstance(families, dict) or not any(bool(v) for v in families.values()):
        errors.append("metal-family-vector-missing")

    if raw.get("producer_status") != "PRODUCED":
        errors.append("producer-did-not-complete")

    if len(reps) != EXPECTED_REPETITIONS:
        errors.append("wrong-repetition-count")
    else:
        candidates = []
        for i, rep in enumerate(reps):
            if rep.get("exit_code") != 0:
                errors.append(f"rep-{i}-nonzero-exit")
            candidate = rep.get("candidate")
            if not isinstance(candidate, str) or not candidate.strip():
                errors.append(f"rep-{i}-empty-candidate")
            else:
                candidates.append(candidate)
                expected_digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
                if rep.get("candidate_sha256") != expected_digest:
                    errors.append(f"rep-{i}-candidate-digest-mismatch")
            gpu = rep.get("gpu") or {}
            if gpu.get("metal_initialized") is not True:
                errors.append(f"rep-{i}-metal-not-initialized")
            if gpu.get("cpu_fallback_warning") is True:
                errors.append(f"rep-{i}-cpu-fallback-warning")
            if int(gpu.get("offloaded_layers") or 0) <= 0:
                errors.append(f"rep-{i}-no-gpu-layer-offload")
        if len(candidates) == EXPECTED_REPETITIONS and len(set(candidates)) != 1:
            errors.append("deterministic-repeat-mismatch")

    notes.append("PASS here means runtime/procedure anchor only; it is not broad actor competence.")
    notes.append("No silicon-generation allowlist is part of acceptance.")
    return (not errors), errors, notes

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--raw", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    raw_path = pathlib.Path(args.raw)
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    passed, errors, notes = check(raw)

    validation = {
        "schema": VALIDATION_SCHEMA,
        "raw_receipt_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        "outcome": "PASS_RUNTIME_PROCEDURE" if passed else "FAIL_RUNTIME_PROCEDURE",
        "passed": passed,
        "errors": errors,
        "notes": notes,
        "task_class": EXPECTED_TASK_CLASS,
        "claim_boundary": "runtime/procedure realization only",
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"MAC_LOCAL_MODEL_VALIDATION={out}")
    print(json.dumps(validation, indent=2, sort_keys=True))
    return 0 if passed else 1

if __name__ == "__main__":
    raise SystemExit(main())
