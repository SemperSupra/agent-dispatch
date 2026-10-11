#!/usr/bin/env python3
"""Reduce only the already bounded WinBot 9.5 receipt into a safe decision record.

Input must be the exact authority-repair-diagnostic-v2.json from the bounded
GitHub artifact. This never ingests sealed raw results, logs, or guest disks.
An A-only failure is not a license to launch seed / terminal FullRDTE.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

SOURCE = "90d5d8a7244b781c28d438d9ba01155735c765b7"
PROJECTION = "d4120a901d7855a9e0d7bc5f805d5e4b0dad8380abf52322c90f9981094d8b45"
CRITICAL = (
    "api_present","python_present","token_present","task_present",
    "authenticated_health","gsudo_present","sshd_capability_installed",
    "sshd_running","sshd_startup_automatic","ssh_firewall_enabled",
)
DEPENDENCY = (
    "winget_version_seen","winget_not_found_seen","winget_config_apply_seen",
    "winget_individual_fallback_seen","winget_config_warning_seen",
    "choco_fallback_seen","choco_python_attempt_seen",
    "choco_gsudo_attempt_seen","ssh_capability_install_attempt_seen",
    "remote_config_failure_seen","api_task_install_attempt_seen",
    "python_command_visible_at_probe","gsudo_command_visible_at_probe",
    "winget_command_visible_at_probe","choco_command_visible_at_probe",
    "python_binary_known_location_at_probe","sshd_service_exists_at_probe",
    "psdirect_elevated_at_probe",
)
CLEANUP = (
    "vm_a_absent","vm_b_absent","work_absent",
    "deterministic_nat_absent","oracle_satisfied",
)

def exact_bools(raw: object, keys: tuple[str,...]) -> dict[str,bool] | None:
    if not isinstance(raw, dict) or set(raw) != set(keys):
        return None
    if any(type(raw[k]) is not bool for k in keys):
        return None
    return {k: raw[k] for k in keys}

def reduce_bounded(r: dict) -> dict:
    """No raw values from untrusted input are forwarded, only fixed labels."""
    if not isinstance(r, dict):
        raise ValueError("root must be an object")
    if r.get("source_revision") != SOURCE or r.get("projection_identity_sha256") != PROJECTION:
        raise ValueError("exact source/projection identity mismatch")
    a = r.get("a")
    cleanup = r.get("cleanup")
    if not isinstance(a, dict) or not isinstance(cleanup, dict):
        raise ValueError("bounded A-only/cleanup record missing")
    if not all(type(cleanup.get(k)) is bool for k in CLEANUP):
        raise ValueError("cleanup booleans missing or wrong type")
    if not isinstance(cleanup.get("netnat_count_after_cleanup"), int) or type(cleanup.get("netnat_count_after_cleanup")) is bool:
        raise ValueError("cleanup NetNat count unavailable")
    cleaned = all(cleanup[k] for k in CLEANUP) and cleanup["netnat_count_after_cleanup"] == 0
    critical = exact_bools(a.get("critical_failure_flags"), CRITICAL)
    dependency = exact_bools(a.get("dependency_probe"), DEPENDENCY)
    critical_valid = a.get("critical_failure_marker_state") == "valid" and critical is not None
    dependency_valid = a.get("dependency_probe_state") == "valid" and dependency is not None
    diagnostic = (
        "cleanup_not_proved" if not cleaned else
        "critical_evidence_unavailable" if not critical_valid else
        "dependency_evidence_unavailable" if not dependency_valid else
        "product_ready_conflicting_terminal" if all(critical.values()) and a.get("provision_status") == "failed" else
        "runtime_dependency_absence" if not critical["python_present"] else
        "ssh_setup_incomplete" if not critical["sshd_capability_installed"] else
        "api_or_service_readiness_incomplete" if not all(critical.values()) else
        "none"
    )
    observations: list[str] = []
    if critical_valid:
        if critical["api_present"] and not critical["python_present"]:
            observations.append("api_source_present_python_absent")
        if not critical["gsudo_present"]:
            observations.append("gsudo_not_ready")
        if not critical["sshd_capability_installed"]:
            observations.append("openssh_capability_not_ready")
        if not critical["token_present"] or not critical["task_present"]:
            observations.append("api_registration_not_ready")
    if dependency_valid:
        for key in DEPENDENCY:
            if dependency[key]:
                observations.append("observed_" + key)
        if not dependency["python_binary_known_location_at_probe"] and not dependency["python_command_visible_at_probe"]:
            observations.append("python_not_found_in_probe")
        if dependency["remote_config_failure_seen"] and not dependency["ssh_capability_install_attempt_seen"]:
            observations.append("remote_setup_aborted_before_ssh_install_attempt")
        if dependency["winget_not_found_seen"] and dependency["choco_fallback_seen"]:
            observations.append("win_get_missing_choco_fallback_executed")
        if dependency["winget_config_apply_seen"] and not dependency["python_command_visible_at_probe"]:
            observations.append("winget_config_attempt_not_proof_of_python_install")
    product_pass = (
        cleaned and r.get("classification") == "PASS" and
        a.get("provision_status") == "complete" and
        critical_valid and all(critical.values())
    )
    # This reducer does not independently establish authenticated API,
    # gsudo, OpenSSH network policy and native A->B persistence gates.
    return {
        "schema_version": 1,
        "classification": "BOUNDED_DEPENDENCY_REDUCTION",
        "evidence_acceptance": "valid" if critical_valid and dependency_valid and cleaned else "incomplete",
        "failure_class": diagnostic,
        "critical_flags_valid": critical_valid,
        "dependency_flags_valid": dependency_valid,
        "cleanup_complete": cleaned,
        "critical_false_keys": [k for k in CRITICAL if critical_valid and not critical[k]],
        "positive_signals": observations,
        "a_only_product_pass_candidate": product_pass,
        "seed_admission": "BLOCKED",
        "terminal_admission": "BLOCKED",
        "requires_causal_review": True,
    }

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = reduce_bounded(json.loads(args.receipt.read_text(encoding="utf-8-sig")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
if __name__ == "__main__":
    main()
