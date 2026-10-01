#!/usr/bin/env python3
"""Shared exact TrueNAS version observation helpers for product probes."""
from __future__ import annotations


def normalize_system_version(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeError("system.version did not return a non-empty string")
    token = value.removeprefix("TrueNAS-")
    if not token:
        raise RuntimeError("system.version normalized to an empty target token")
    return token


def require_target_version(observed: object, expected: str) -> str:
    if not isinstance(expected, str) or not expected or expected.startswith("TrueNAS-"):
        raise RuntimeError("expected target version must be a non-empty registry token without TrueNAS- prefix")
    token = normalize_system_version(observed)
    if token != expected:
        raise RuntimeError(f"target version drifted: expected {expected}, observed {token}")
    return token
