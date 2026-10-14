#!/usr/bin/env python3
"""Bounded G3 native-world rollback mechanics for an isolated TrueNAS RDTE guest.

This is NOT a COLLAGE-authorized APPLY, online player authentication, generic
snapshot manager, production NAS operator, or evidence of a successful guest.
The existing native T6 runner owns the authenticated session, exact App/world,
signed artifact, stop/start calls, lifecycle receipts and final owned cleanup.
This module supplies only fixed identity/snapshot/rollback preconditions.
"""
from __future__ import annotations

# Native guest executes scripts as top-level modules; public unit tests import
# them through the scripts package. Share the same pinned artifact constants.
try:
    from .qualify_vanilla263_native_lantern_stage import WORLD, TARGET, SHA, NAME
except ImportError:
    from qualify_vanilla263_native_lantern_stage import WORLD, TARGET, SHA, NAME

APP = "rdte-t6-minecraft-vanilla-263"
DATASET = "rdtepool/minecraft-vanilla-263-t6-world"
SNAPSHOT = DATASET + "@op4g-pre-lantern"
SCHEMA = "supracraft.native-vanilla263-rdte-rollback-mechanics/1"


class Refused(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise Refused(code)


def app_state(call):
    rows = call("app.query", [[["id", "=", APP]]])
    require(type(rows) is list and len(rows) == 1 and
            type(rows[0]) is dict and rows[0].get("name", APP) == APP,
            "G3_APP_OWNER_NOT_EXACT")
    state = rows[0].get("state")
    require(state in {"STOPPED", "RUNNING"}, "G3_APP_UNSAFE_STATE")
    return state


def _snapshot_rows(call):
    rows = call("zfs.snapshot.query", [[["id", "=", SNAPSHOT]]])
    require(type(rows) is list and len(rows) <= 1 and
            all(type(row) is dict and row.get("id") == SNAPSHOT for row in rows),
            "G3_SNAPSHOT_QUERY_AMBIGUOUS")
    return rows


def _artifact_present(call):
    rows = call("filesystem.listdir", [WORLD + "/datapacks"])
    require(type(rows) is list and len(rows) <= 4096 and all(
        type(row) is dict and type(row.get("name")) is str and
        len(row["name"]) < 260 for row in rows),
        "G3_DATA_PACK_INVENTORY_UNSAFE")
    # Compare only exact basename; no traversal, glob or deletion.
    return any(row["name"] == NAME for row in rows)


def take_owned_pre_stage_snapshot(call):
    """Called only after existing T6 owner App is verified STOPPED.

    Must precede the actual signed 739-byte ZIP stage. Refuse preexisting
    snapshots and world release conflicts; don't rename foreign snapshots.
    """
    require(app_state(call) == "STOPPED", "G3_QUIESCE_REQUIRED")
    require(not _artifact_present(call), "G3_CANDIDATE_ALREADY_PRESENT")
    require(_snapshot_rows(call) == [], "G3_SNAPSHOT_REPLAY_REFUSED")
    row = call("zfs.snapshot.create", [{
        "dataset": DATASET, "name": SNAPSHOT.rsplit("@", 1)[1],
        "recursive": False, "exclude": [], "suspend_vms": False,
        "vmware_sync": False,
    }])
    require(type(row) is dict and row.get("id") == SNAPSHOT,
            "G3_SNAPSHOT_RESULT_NOT_EXACT")
    require(len(_snapshot_rows(call)) == 1, "G3_SNAPSHOT_NOT_DURABLE")
    return {
        "schema": SCHEMA, "phase": "baseline_snapshotted",
        "classification": "G3_DISPOSABLE_MECHANICS_ONLY",
        "snapshot_owned": True, "snapshot_id_verified": True,
        "candidate_sha256": SHA, "candidate_present_before_stage": False,
        "world_activation_authorized_by_collage": False,
        "actual_player_gameplay_verified": False,
        "physical_true_nas_mutated": False,
    }


def restore_owned_baseline_after_injected_fault(call, wait_job, wait_app, wait_status):
    """Fixed rollback after independent native byte stage and app re-install.

    Caller independently verifies exact ZIP bytes and healthy running App.
    This function injects an explicit failed release decision: never promote.
    Stop -> rollback exact owned snapshot -> restart -> health recheck.
    """
    require(app_state(call) == "RUNNING", "G3_PREFAULT_APP_NOT_RUNNING")
    require(_artifact_present(call), "G3_CANDIDATE_MISSING_PREFAULT")
    require(len(_snapshot_rows(call)) == 1, "G3_SNAPSHOT_NOT_DURABLE")
    wait_job(call("app.stop", [APP]), "G3 pre-rollback quiesce")
    require(app_state(call) == "STOPPED", "G3_STOP_UNCONFIRMED")
    response = call("zfs.snapshot.rollback", [SNAPSHOT, {
        "recursive": False, "recursive_clones": False, "force": False,
        "recursive_rollback": False,
    }])
    require(response is None or response is True, "G3_ROLLBACK_REFUSED")
    require(not _artifact_present(call), "G3_ROLLBACK_LEFT_CANDIDATE")
    wait_job(call("app.start", [APP]), "G3 after-rollback resume")
    wait_app()
    wait_status("g3-rollback")
    require(app_state(call) == "RUNNING", "G3_RESTORED_APP_NOT_RUNNING")
    require(not _artifact_present(call), "G3_RESTART_REINTRODUCED_CANDIDATE")
    require(len(_snapshot_rows(call)) == 1, "G3_ROLLBACK_SNAPSHOT_NOT_DURABLE")
    return {
        "schema": SCHEMA, "phase": "injected_fault_rolled_back",
        "classification": "G3_DISPOSABLE_MECHANICS_ONLY",
        "snapshot_id_verified": True, "release_fault_injected": True,
        "candidate_absent_after_rollback": True,
        "native_app_running_after_rollback": True,
        "native_game_status_rechecked": True,
        "candidate_sha256": SHA, "collage_managed_deployment": False,
        "world_activation_authorized_by_collage": False,
        "actual_player_gameplay_verified": False,
        "physical_true_nas_mutated": False,
    }
