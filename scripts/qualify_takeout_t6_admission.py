#!/usr/bin/env python3
"""Fail-closed Takeout-only T6 *admission inventory*, never an executor.

Reads public source and static candidate metadata. It cannot grant #480 lane
authority, schedule KVM, authorize a product selector, or infer native guest
success from a hosted Docker run. Report all blockers without private data.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
TARGET = "25.04.2.6"
PROVIDER = "takeout-synthetic-t6"
SELECTOR = "takeout-synthetic"
ROUTE = "scripts/truenas_middleware_takeout_t6_probe.py"


class AdmissionError(ValueError):
    pass


def require(ok: bool, code: str) -> None:
    if not ok:
        raise AdmissionError(code)


def check(candidate: dict, providers: dict, run_request: dict,
          workflow_source: str, *, probe_path_present: bool = False,
          control_artifact_present: bool = False) -> dict:
    """Structured gap inventory; no positive claim of authorization."""
    require(isinstance(candidate, dict) and
            candidate.get("schema") == "takeout-t6-admission-candidate/v1",
            "INVALID_CANDIDATE_SCHEMA")
    require(candidate.get("scope") == "SYNTHETIC_ONLY" and
            candidate.get("decision") == "HOLD", "CANDIDATE_MUTATED_PAST_HOLD")
    auth = candidate.get("authority")
    require(isinstance(auth, dict) and
            auth.get("repository") == "SemperSupra/agent-dispatch-private" and
            auth.get("issue") == 642 and
            auth.get("foundry_issue") == 327 and
            auth.get("lane_issue") == 480, "AUTHORITY_DRIFT")
    target = candidate.get("target")
    require(isinstance(target, dict) and
            target.get("version") == TARGET and
            target.get("rung") == "t6" and
            target.get("guest_only") is True and
            target.get("middleware_commit") == "244b717370fe35fb9eefc3096acfbc25f12b57b6",
            "TARGET_DRIFT")
    product = candidate.get("producer")
    consumer = candidate.get("consumer")
    require(isinstance(product, dict) and isinstance(consumer, dict),
            "PROVENANCE_MISSING")
    # Pinned independent public cross-run receipt. These static identifiers
    # qualify only the public transport, never a native Apps import or slot.
    require(product.get("repository") == "SemperSupra/agent-dispatch" and
            product.get("pr") == 480 and
            product.get("source_commit") ==
            "7fb683572a4ce4d51b3c2a89bf5ba1b102c200b0" and
            product.get("cross_run_public_source_sha") == product.get("source_commit") and
            product.get("hosted_receipt_workflow") == 41905075905 and
            type(product.get("oci_artifact_id")) is int and
            product["oci_artifact_id"] == 13358599085 and
            product.get("oci_artifact_zip_sha256") ==
            "sha256:dcc0b35035163f0b5a1cbd73603070c40017d86c13817ca6cd7a3441c898506e" and
            product.get("oci_manifest_sha256") ==
            "sha256:dc4bd461467e15d5cd50152d17cc673383c86998ca61700ed7d57881dcea868e" and
            product.get("loaded_image_config_sha256") ==
            "sha256:2a42d2262e4f8d86bf9f07de64145b5bcf68cb1b491cf34b3f39126b1c054eed" and
            product.get("portable_oci_cross_format_workflow") == 41955695340 and
            product.get("artifact_independent_byte_audit") ==
            "PASS_PUBLIC_CROSS_RUN_2026-11-05" and
            product.get("native_guest_import_qualified") is False,
            "SOURCE_PROVENANCE_DRIFT")
    require(consumer.get("repository") == "SemperSupra/truenas-app-foundry" and
            consumer.get("pr") == 144 and isinstance(consumer.get("source_commit"), str) and
            SHA.fullmatch(consumer["source_commit"]), "FOUNDRY_PROVENANCE_DRIFT")
    receipt = candidate.get("completion")
    require(isinstance(receipt, dict) and
            receipt.get("kind") == "INDEPENDENT_OUTPUT_VERIFIED_WITH_APPLICATION_REPORT" and
            receipt.get("process_exit_required") is False and
            receipt.get("docker_read_required") is False and
            receipt.get("application_self_report_is_sufficient") is False and
            receipt.get("verified_hosted_workflow") == 41905075905,
            "COMPLETION_CONTRACT_DRIFT")
    execution = candidate.get("execution")
    require(isinstance(execution, dict) and
            execution.get("provider_id") == PROVIDER and
            execution.get("selector") == SELECTOR and
            execution.get("probe") == ROUTE and
            execution.get("control_artifact") == "takeout-synthetic-t6-control" and
            execution.get("run_dispatched") is False, "EXECUTION_PROPOSAL_DRIFT")
    policy = candidate.get("constraints")
    require(isinstance(policy, dict) and
            all(policy.get(name) is False for name in (
                "allow_real_google_data", "allow_physical_truenas",
                "allow_private_gha_minutes", "allow_global_docker_socket",
                "allow_new_site_docker_read")) and policy.get("retry") == "none",
            "PRIVILEGE_OR_BUDGET_DRIFT")
    require(isinstance(providers, dict) and
            providers.get("schema") == "truenas-capsule-providers/v1" and
            isinstance(providers.get("providers"), list), "REGISTRY_INVALID")
    require(isinstance(workflow_source, str) and
            "gha-kvm-truenas-run-request/v1" in workflow_source and
            "truenas_t6_product" in workflow_source, "RUNNER_SOURCE_INVALID")
    require(isinstance(run_request, dict) and
            run_request.get("schema") == "gha-kvm-truenas-run-request/v1",
            "RUN_REQUEST_INVALID")
    blockers = []
    registered = [p for p in providers["providers"] if isinstance(p, dict) and
                  p.get("id") == PROVIDER]
    if len(registered) != 1 or (
        registered[0].get("existing_selector") != SELECTOR or
        registered[0].get("probe") != ROUTE or
        registered[0].get("control_artifact") != "takeout-synthetic-t6-control"
    ):
        blockers.append("PRODUCT_PROVIDER_NOT_BOUND")
    # Literal selector in the workflow is a *necessary but insufficient* check.
    if (f'"{SELECTOR}"' not in workflow_source and
        f"'{SELECTOR}'" not in workflow_source):
        blockers.append("WORKFLOW_SELECTOR_NOT_BOUND")
    if not probe_path_present:
        blockers.append("NATIVE_TAKEOUT_PROBE_NOT_QUALIFIED")
    if not control_artifact_present:
        blockers.append("GUEST_CONTROL_ARTIFACT_NOT_QUALIFIED")
    if run_request.get("product") != SELECTOR:
        blockers.append("FRESH_TAKEOUT_RUN_REQUEST_MISSING")
    if not isinstance(execution.get("exclusive_lane_release"), str) or not execution["exclusive_lane_release"]:
        blockers.append("LANE_480_RELEASE_MISSING")
    if not isinstance(execution.get("fresh_takeout_run_request"), str) or not execution["fresh_takeout_run_request"]:
        blockers.append("UNIQUE_REQUEST_EDGE_NOT_RECORDED")
    # Public transport receipt is independent of native import. Even an
    # exact, unexpired ZIP must never suppress the guest import gate.
    if product.get("native_guest_import_qualified") is not True:
        blockers.append("NATIVE_OCI_IMPORT_NOT_QUALIFIED")
    if consumer.get("data_outcome_observer") != "CI_QUALIFIED":
        blockers.append("FOUNDRY_DATA_OUTCOME_OBSERVER_NOT_QUALIFIED")
    if consumer.get("native_app_observation") != "ACCEPTED":
        blockers.append("NATIVE_APP_OBSERVER_NOT_QUALIFIED")
    if consumer.get("zfs_retention") != "ACCEPTED":
        blockers.append("NATIVE_ZFS_RETENTION_NOT_QUALIFIED")
    # Never trust an unparsed timestamp to stand for a fresh OCI artifact.
    # The historical producer receipt expires on a fixed date, independently
    # of source/guest admission. This preflight cannot renew it or fetch bytes.
    expiry = product.get("oci_artifact_expires")
    if expiry == "EXPIRED":
        blockers.append("OCI_ARTIFACT_EXPIRED")
    elif not isinstance(expiry, str):
        blockers.append("OCI_ARTIFACT_EXPIRY_INVALID")
    else:
        try:
            parsed = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("timezone required")
        except ValueError:
            blockers.append("OCI_ARTIFACT_EXPIRY_INVALID")
        else:
            if parsed <= datetime.now(timezone.utc):
                blockers.append("OCI_ARTIFACT_EXPIRED")
    # Never emit READY from static claims; readiness requires a separate
    # admission issuer and one-use native executor, not untrusted JSON flags.
    return {"schema": "takeout-t6-static-preflight/v1",
            "classification": "STATIC_READ_ONLY_NOT_ADMISSION",
            "status": "BLOCKED" if blockers else "EXTERNAL_ADMISSION_STILL_REQUIRED",
            "blockers": sorted(set(blockers)),
            "target": TARGET, "product": SELECTOR,
            "already_dispatched": False, "guest_started": False,
            "docker_read_required": False, "physical_apply": "HOLD"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--providers", type=Path, required=True)
    parser.add_argument("--run-request", type=Path, required=True)
    parser.add_argument("--workflow", type=Path, required=True)
    parser.add_argument("--probe-present", action="store_true")
    parser.add_argument("--control-artifact-present", action="store_true")
    a = parser.parse_args()
    try:
        result = check(json.loads(a.candidate.read_text()),
                       json.loads(a.providers.read_text()),
                       json.loads(a.run_request.read_text()),
                       a.workflow.read_text(),
                       probe_path_present=a.probe_present,
                       control_artifact_present=a.control_artifact_present)
    except (OSError, ValueError, TypeError):
        print(json.dumps({"status": "BLOCKED", "reason": "MALFORMED_PREFLIGHT_INPUT"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "EXTERNAL_ADMISSION_STILL_REQUIRED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
