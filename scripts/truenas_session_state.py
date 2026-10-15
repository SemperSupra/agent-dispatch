#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

TERMINAL_SESSION = {
    "SESSION_CONTAMINATED",
    "PLATFORM_UNHEALTHY",
    "RESOURCE_GUARDRAIL",
    "AUTHORITY_MISMATCH",
}
CAPSULE_VERDICTS = {
    "SUPPORTED",
    "ORACLE_FAILURE",
    "HARNESS_FAILURE",
    "ENVIRONMENT_FAILURE",
    "UNSUPPORTED",
    "DOCUMENTED_NEGATIVE",
    "NOT_EXECUTED",
}

@dataclass(frozen=True)
class CapsuleOutcome:
    capsule_id: str
    verdict: str
    mutating: bool
    cleanup_required: bool
    cleanup_satisfied: bool
    platform_healthy: bool
    authority_satisfied: bool = True
    resource_guardrail_satisfied: bool = True

@dataclass(frozen=True)
class SessionDecision:
    continue_mutation: bool
    session_classification: str
    next_state: str
    reason: str

def decide_after_capsule(outcome: CapsuleOutcome) -> SessionDecision:
    if outcome.verdict not in CAPSULE_VERDICTS:
        return SessionDecision(False, "HARNESS_FAILURE", "STOPPED", "unknown capsule verdict")
    if not outcome.authority_satisfied:
        return SessionDecision(False, "AUTHORITY_MISMATCH", "STOPPED", "capsule authority identity changed")
    if not outcome.resource_guardrail_satisfied:
        return SessionDecision(False, "RESOURCE_GUARDRAIL", "STOPPED", "resource floor/ceiling violated")
    if outcome.mutating and outcome.cleanup_required and not outcome.cleanup_satisfied:
        return SessionDecision(False, "SESSION_CONTAMINATED", "STOPPED", "mutating capsule cleanup was not proven")
    if not outcome.platform_healthy:
        return SessionDecision(False, "PLATFORM_UNHEALTHY", "STOPPED", "post-capsule platform health was not proven")
    return SessionDecision(True, "IN_PROGRESS", "READY", "capsule failure domain reconciled; next independent capsule may run")

def fold_session(outcomes: Iterable[CapsuleOutcome]) -> SessionDecision:
    last=SessionDecision(True,"IN_PROGRESS","READY","no capsules executed")
    for outcome in outcomes:
        last=decide_after_capsule(outcome)
        if not last.continue_mutation:
            return last
    return last

def finalize_session(outcomes: Iterable[CapsuleOutcome]) -> str:
    rows=list(outcomes)
    decision=fold_session(rows)
    if not decision.continue_mutation:
        return decision.session_classification
    if not rows:
        return "NO_CAPSULES"
    # A session can be structurally clean even when an individual product oracle failed.
    # Per-capsule verdicts remain authoritative and must not be collapsed into product PASS.
    return "SESSION_CLEAN"
