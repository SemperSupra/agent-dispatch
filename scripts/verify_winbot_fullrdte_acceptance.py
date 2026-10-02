#!/usr/bin/env python3
"""Strictly verify a redacted WinBot FullRDTE receipt against exact authority bindings."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _get(obj: dict, *parts):
    cur = obj
    for part in parts:
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--diagnostic", required=True)
    ap.add_argument("--reconstruction", required=True)
    ap.add_argument("--expected-source", required=True)
    ap.add_argument("--expected-projection", required=True)
    ap.add_argument("--expected-control", required=True)
    args = ap.parse_args()

    diagnostic = _load(args.diagnostic)
    reconstruction = _load(args.reconstruction)
    failures: list[str] = []

    def require(label: str, actual, expected) -> None:
        if actual != expected:
            failures.append(f"{label}: expected {expected!r}, observed {actual!r}")

    require("reconstruction.source_revision", reconstruction.get("source_revision"), args.expected_source)
    require("reconstruction.projection_identity_sha256", reconstruction.get("projection_identity_sha256"), args.expected_projection)
    require("reconstruction.control_blob_sha", reconstruction.get("control_blob_sha"), args.expected_control)
    require("reconstruction.private_repo_checkout", reconstruction.get("private_repo_checkout"), False)
    require("reconstruction.staged_public_git_objects_only", reconstruction.get("staged_public_git_objects_only"), True)

    require("diagnostic.scope", diagnostic.get("scope"), "redacted_fullrdte_diagnostic")
    execution = diagnostic.get("execution") or {}
    require("execution.capsule_sha256", execution.get("capsule_sha256"), reconstruction.get("capsule_sha256"))
    require("execution.task_exit_code", execution.get("task_exit_code"), 0)
    require("execution.exit_code", execution.get("exit_code"), 0)
    require("execution.timed_out", execution.get("timed_out"), False)
    require("execution.result_budget.exceeded", _get(execution, "result_budget", "exceeded"), False)

    full = diagnostic.get("full_rdte") or {}
    require("full_rdte.profile", full.get("profile"), "FullRDTE")
    require("full_rdte.source_revision", full.get("source_revision"), args.expected_source)
    require("full_rdte.projection_identity_sha256", full.get("projection_identity_sha256"), args.expected_projection)
    require("full_rdte.classification", full.get("classification"), "SUPPORTED")
    require("full_rdte.failure_domain", full.get("failure_domain"), None)
    require("full_rdte.error_type", full.get("error_type"), None)
    require("full_rdte.error_message", full.get("error_message"), None)

    build = full.get("build") or {}
    for key in (
        "projection_authorized",
        "master_build_started",
        "master_build_completed",
        "seed_test_vhd",
        "seed_integrity",
        "iso_reclaimed_before_materialization",
        "seed_unchanged",
        "seed_integrity_after",
    ):
        require(f"build.{key}", build.get(key), True)

    cells = full.get("work_cells") or {}
    a = cells.get("a") or {}
    b = cells.get("b") or {}
    require("work_cells.a.lineage", a.get("lineage"), "True")
    require("work_cells.a.ip_observed", a.get("ip_observed"), True)
    require("work_cells.a.api_token_observed", a.get("api_token_observed"), True)
    require("work_cells.a.runtime_taint_written", a.get("runtime_taint_written"), True)
    require("work_cells.a.vm_absent_after_dispose", a.get("vm_absent_after_dispose"), True)
    require("work_cells.a.runtime_disk_absent_after_dispose", a.get("runtime_disk_absent_after_dispose"), True)
    require("work_cells.b.lineage", b.get("lineage"), "True")
    require("work_cells.b.prior_runtime_taint_absent", b.get("prior_runtime_taint_absent"), True)
    require("work_cells.b.vm_absent_after_dispose", b.get("vm_absent_after_dispose"), True)
    require("work_cells.b.runtime_disk_absent_after_dispose", b.get("runtime_disk_absent_after_dispose"), True)

    persistence = full.get("persistence") or {}
    for key in (
        "explicit_attachment",
        "exists_before_a",
        "canary_written",
        "exists_after_a_dispose",
        "canary_survived_rematerialization",
        "exists_after_b_dispose",
        "oracle_satisfied",
    ):
        require(f"persistence.{key}", persistence.get(key), True)

    conformance = full.get("conformance") or {}
    require("conformance.pytest_exit_code", conformance.get("pytest_exit_code"), 0)
    require("conformance.results_present", conformance.get("results_present"), True)
    require("conformance.oracle_satisfied", conformance.get("oracle_satisfied"), True)

    cleanup = full.get("cleanup") or {}
    for key in ("vm_a_absent", "vm_b_absent", "work_absent", "oracle_satisfied"):
        require(f"cleanup.{key}", cleanup.get(key), True)

    result = {
        "schema_version": 1,
        "accepted": not failures,
        "source_revision": args.expected_source,
        "projection_identity_sha256": args.expected_projection,
        "control_blob_sha": args.expected_control,
        "evidence_basis": (
            "exact reconstruction/control binding + zero task exit under the bound FullRDTE "
            "control + independently redacted acceptance boundary fields"
        ),
        "failures": failures,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
