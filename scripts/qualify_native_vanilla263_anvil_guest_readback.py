#!/usr/bin/env python3
"""Bounded G4 quiesced native world Anvil file readback seam (source-only).

This is a fixed-path read-only adapter for the existing disposable native T6
DDP session and its already admitted owned App/world. It has no network client,
credential issuance, provider mutation or disk export. Neither a synthetic
test nor a caller-provided bytes callback is an independent live guest receipt.
"""
from __future__ import annotations

try:
    from .qualify_native_vanilla263_anvil_blocks import (
        MAX_REGION, SCHEMA, inspect, require)
    from .qualify_vanilla263_native_world_rollback import (
        APP, WORLD, app_state)
except ImportError:
    from qualify_native_vanilla263_anvil_blocks import (
        MAX_REGION, SCHEMA, inspect, require)
    from qualify_vanilla263_native_world_rollback import (
        APP, WORLD, app_state)

PATH = WORLD + "/region/r.0.0.mca"
REGION_DIRECTORY = WORLD + "/region"
REGION_BASENAME = "r.0.0.mca"
MAX_OWNED_REGION_ENTRIES = 4096
STAGES = ("preaction", "candidate", "rollback")
# Only these literal, non-sensitive phases may escape as a public diagnostic.
PHASES = (
    "app_state_query", "app_stopped_verified",
    "file_stat", "file_stat_verified",
    "file_stat_listing_absent", "file_stat_listing_present",
    "file_stat_listing_inconclusive",
    "download_request", "download_route_verified",
    "download_job", "download_job_completed",
    "bytes_fetch", "bytes_verified", "anvil_decode", "anvil_verified",
)


def record_phase(stage: str, phase: str, reporter=None) -> None:
    require(stage in STAGES and phase in PHASES, "BACKEND_PHASE_CODE_INVALID")
    if reporter is not None:
        reporter(stage + "." + phase)



def classify_failed_stat(*, call, stage: str, on_phase=None) -> None:
    """One extra fixed-path, read-only census after a failed native stat.

    This is a diagnostic, never a fallback source of world bytes or authority.
    A missing directory, provider error or malformed list is INCONCLUSIVE.
    No raw paths, listing names, provider responses or errors reach the caller.
    """
    try:
        rows = call("filesystem.listdir", [REGION_DIRECTORY])
    except Exception:
        record_phase(stage, "file_stat_listing_inconclusive", on_phase)
        raise Refused("BACKEND_REGION_STAT_CENSUS_INCONCLUSIVE") from None
    if (type(rows) is not list or len(rows) > MAX_OWNED_REGION_ENTRIES
            or any(type(row) is not dict
                   or type(row.get("name")) is not str
                   or type(row.get("type")) is not str
                   for row in rows)):
        record_phase(stage, "file_stat_listing_inconclusive", on_phase)
        raise Refused("BACKEND_REGION_STAT_CENSUS_INVALID") from None
    matched = [row for row in rows if row["name"] == REGION_BASENAME]
    if not matched:
        record_phase(stage, "file_stat_listing_absent", on_phase)
        raise Refused("BACKEND_REGION_NOT_LISTED_AFTER_STOP") from None
    if len(matched) != 1 or matched[0]["type"] != "FILE":
        record_phase(stage, "file_stat_listing_inconclusive", on_phase)
        raise Refused("BACKEND_REGION_CENSUS_ENTRY_UNSAFE") from None
    record_phase(stage, "file_stat_listing_present", on_phase)
    raise Refused("BACKEND_REGION_STAT_REFUSED_BUT_FILE_LISTED") from None


def capture(*, call, wait_job, fetch_bytes, stage: str, on_phase=None) -> dict:
    """Only after existing *actual* guest runner verified owned App then stop.

    The runner MUST independently bind the current authenticated DDP session,
    exact native service/world, player action, signed request, and App stop.
    It must not publish the raw Anvil region, signed session or download URL.
    """
    require(stage in STAGES, "BACKEND_STAGE_NOT_ADMITTED")
    record_phase(stage, "app_state_query", on_phase)
    require(app_state(call) == "STOPPED", "BACKEND_QUIESCENCE_NOT_OBSERVED")
    record_phase(stage, "app_stopped_verified", on_phase)
    record_phase(stage, "file_stat", on_phase)
    try:
        stat = call("filesystem.stat", [PATH])
    except Exception:
        # The 019 real guest died here with only RuntimeError. Distinguish a
        # missing fixed region entry from a provider/stat refusal, without
        # reflecting private middleware error strings or accepting a fallback.
        classify_failed_stat(call=call, stage=stage, on_phase=on_phase)
        raise AssertionError("unreachable")
    require(type(stat) is dict and stat.get("type") == "FILE" and
            type(stat.get("size")) is int and
            8192 <= stat["size"] <= MAX_REGION, "BACKEND_REGION_FILE_NOT_EXACT")
    record_phase(stage, "file_stat_verified", on_phase)
    record_phase(stage, "download_request", on_phase)
    row = call("core.download", [
        "filesystem.get", [PATH], "g4-owned-region-" + stage + ".mca", True])
    require(type(row) is list and len(row) == 2 and
            type(row[0]) is int and row[0] > 0 and
            type(row[1]) is str and
            row[1].startswith("/_download/") and
            len(row[1]) <= 300 and
            ".." not in row[1] and "?" not in row[1] and "#" not in row[1],
            "BACKEND_DOWNLOAD_ROUTE_INVALID")
    record_phase(stage, "download_route_verified", on_phase)
    record_phase(stage, "download_job", on_phase)
    wait_job(row[0], "G4 read-only owned Anvil file download")
    record_phase(stage, "download_job_completed", on_phase)
    record_phase(stage, "bytes_fetch", on_phase)
    blob = fetch_bytes(row[1])
    require(type(blob) is bytes and len(blob) == stat["size"],
            "BACKEND_DOWNLOADED_FILE_DRIFT")
    record_phase(stage, "bytes_verified", on_phase)
    record_phase(stage, "anvil_decode", on_phase)
    result = inspect(blob, stage)
    record_phase(stage, "anvil_verified", on_phase)
    # The host transfer API is separate from independent receipt admission:
    # this module cannot prove the caller ran under authorized guest identity.
    result.update({
        "classification": "SOURCE_ONLY_OWNED_ANVIL_DOWNLOAD_SEAM",
        "downloaded_file_size": len(blob),
        "requested_native_app": APP,
        "requested_native_world_file_fixed": True,
        "requested_native_world": "rdtepool/minecraft-vanilla-263-t6-world",
        "read_only_middleware_calls": True,
        "live_guest_identity_independently_verified": False,
        "backend_independent_world_oracle_pass": False,
        "raw_region_published": False,
        "next_gate": "EXACT_LIVE_GUEST_RUNNER_AND_INDEPENDENT_RECEIPT_BINDING",
    })
    return result
