#!/usr/bin/env python3
"""Independent EXACT TrueNAS 25.04.2.6 / vanilla26.3 native guest receipt oracle.

Cannot accept Paper T6 evidence, source-only control, an OCI-only container,
offline Java protocol from another host, or a provider's mere RUNNING status.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

from admit_vanilla263_native_t6_control import (
    APP, CONTROL_SHA, MIDDLEWARE, OCI, PRODUCER, TARGET, WORLD,
)

SCHEMA = "truenas-minecraft-vanilla263-t6/v1"
STATUS_SCHEMA = "minecraft-java-status-oracle/v1"
IMAGE_SHA = OCI.split("@sha256:", 1)[1]


def check(root: dict, *, require_collage: bool = False,
          require_lantern_staged: bool = False,
          require_native_rollback: bool = False,
          require_native_client_visibility: bool = False,
          require_native_backend_region: bool = False) -> None:
    def need(condition: bool, reason: str) -> None:
        if not condition:
            raise ValueError(reason)
    need(type(root) is dict and root.get("contract") == "gha-kvm-system-lab/v1",
         "guest root receipt schema")
    target = root.get("target") or {}
    need(type(target) is dict and
         target.get("product") == "truenas" and
         target.get("version") == TARGET and
         target.get("rung") == "T6", "wrong exact guest identity")
    need(root.get("classification") == "SUPPORTED" and
         root.get("oracleSatisfied") is True and
         root.get("phase") == "foundry-materialization",
         "guest/root unsupported")
    source = root.get("source") or {}
    need(type(source) is dict and
         source.get("system_version_expected") == "TrueNAS-" + TARGET and
         source.get("middleware_commit") == MIDDLEWARE and
         source.get("foundry_profile_blob") == "631467044411c96a0fe6d361688b99a794f07c80",
         "guest exact source/profile mismatch")
    shape = (root.get("requested_shape") or {}).get("app") or {}
    need(type(shape) is dict and
         shape.get("name") == APP and
         shape.get("catalog_app") == "minecraft" and
         shape.get("catalog_version_candidate") == "1.15.31" and
         shape.get("minecraft_version") == "26.3" and
         shape.get("minecraft_protocol") == 777,
         "wrong native workload shape")
    p = root.get("foundry_materialization") or {}
    need(type(p) is dict and
         p.get("schema") == SCHEMA and
         p.get("classification") == "SUPPORTED" and
         p.get("oracleSatisfied") is True and
         p.get("product") == "vanilla-26.3" and
         p.get("target") == TARGET,
         "wrong product guest oracle")
    need(p.get("foundry_ref") == PRODUCER and
         p.get("control_sha256") == CONTROL_SHA,
         "guest product signer/control mismatch")
    need(p.get("catalog_version_verified") is True,
         "exact native catalog not verified by guest")
    observed = p.get("observed_image_reference")
    need(isinstance(observed, str) and
         (observed == OCI or
          observed == OCI.split(":2026.10.0-java25")[0] + "@sha256:" + IMAGE_SHA) and
         p.get("image_digest_qualification") == "SOURCE_AND_GUEST_REF_MATCH",
         "native running OCI image digest not verified")
    need(p.get("world_retained_on_delete") is True and
         p.get("world_rebound_after_reinstall") is True,
         "independent world not retained")
    readiness = p.get("readiness") or {}
    need(type(readiness) is dict, "guest readiness stages absent")
    for phase in ("first", "restart", "redeploy", "reinstall"):
        stage = readiness.get(phase) or {}
        protocol = stage.get("protocol") or {}
        level = stage.get("level") or {}
        need(type(protocol) is dict and
             protocol.get("schema") == STATUS_SCHEMA and
             protocol.get("classification") == "SUPPORTED" and
             protocol.get("oracleSatisfied") is True and
             protocol.get("java_version") == "26.3" and
             protocol.get("server_implementation") == "vanilla" and
             protocol.get("status_name_contract") == "vanilla_exact" and
             protocol.get("server_protocol") == 777 and
             protocol.get("status_packet_valid") is True and
             protocol.get("players_counter_valid") is True,
             "independent vanilla protocol not accepted at " + phase)
        need(type(level) is dict and
             type(level.get("size")) is int and level["size"] > 0,
             "independent owned world level.dat not observed at " + phase)
    cleanup = p.get("cleanup") or {}
    need(type(cleanup) is dict and
         all(cleanup.get(k) is True for k in (
             "attempted", "zero_residue", "app_absent",
             "owned_world_dataset_absent")),
         "native App/ZFS world cleanup left residue")
    need(p.get("secret_values_captured") is False,
         "guest receipt admits secrets")
    need((root.get("foundry_materialization") or {}).get("target") == TARGET,
         "guest receipt cross-target mismatch")
    if require_lantern_staged:
        stage = p.get("lantern_artifact_stage") or {}
        need(type(stage) is dict and
             stage.get("schema") == "supracraft.native-vanilla263-lantern-artifact-stage/1" and
             stage.get("classification") == "REAL_NATIVE_GUEST_ARTIFACT_BYTES_STAGED" and
             stage.get("artifact_sha256") ==
                "da25005e8729e6f013f7108ac5b8869dd46323befc78efdae18221b26cafe5f8" and
             stage.get("download_readback_sha256") ==
                "da25005e8729e6f013f7108ac5b8869dd46323befc78efdae18221b26cafe5f8" and
             stage.get("world_id") == "lantern-rdte" and
             stage.get("native_app") == APP and
             stage.get("native_truenas_version") == TARGET and
             stage.get("zfs_world_owned") is True and
             stage.get("app_quiesced_before_write") is True and
             stage.get("persisted_on_restart") is True and
             stage.get("persisted_on_reinstall") is True and
             stage.get("artifact_gameplay_effect_verified") is False and
             stage.get("collage_managed_deployment") is False and
             stage.get("principal_authorized_to_apply") is False and
             stage.get("physical_truenas_apply") == "HOLD",
             "actual native Lantern ZIP byte stage/retention was not qualified")
    if require_native_client_visibility:
        need(require_native_rollback and require_lantern_staged and require_collage,
             "native client requires exact G2 and G3")
        profile = p.get("native_player_profile") or {}
        gameplay = p.get("native_player_gameplay") or {}
        need(type(profile) is dict and profile.get("schema") ==
             "minecraft-vanilla263-disposable-loopback-player/1" and
             profile.get("classification") == "DISPOSABLE_OVERLAY_BOUND" and
             profile.get("rcon_enabled") is False and
             profile.get("client_online_account_qualified") is False and
             profile.get("physical_truenas_apply") == "HOLD" and
             type(gameplay) is dict and
             gameplay.get("same_native_guest_client_causal_visibility") is True and
             gameplay.get("backend_independent_world_oracle_pass") is False and
             gameplay.get("collage_managed_deployment") is False and
             gameplay.get("physical_true_nas_apply") == "HOLD",
             "native offline client path not independently verified")
        for name in ("candidate", "rollback"):
            client = gameplay.get(name) or {}
            need(type(client) is dict and client.get("schema") ==
                 "supracraft.native-vanilla263-mineflayer-causal/1" and
                 client.get("classification") == "CLIENT_CAUSAL_VISIBILITY_ONLY" and
                 client.get("stage") == name and
                 client.get("client_protocol777_connected_and_spawned") is True and
                 client.get("offline_synthetic_player_caused_core_placement") is True and
                 client.get("client_saw_expected_datapack_effect") is (name == "candidate") and
                 client.get("client_saw_expected_no_datapack_effect") is (name == "rollback") and
                 client.get("native_guest_backend_independent_oracle_qualified") is False and
                 client.get("stock_mojang_client_qualified") is False and
                 client.get("online_account_qualified") is False and
                 client.get("collage_mutation_authorized") is False and
                 client.get("physical_true_nas_apply") == "HOLD",
                 "native offline client causal stage missing")
    if require_native_backend_region:
        need(require_native_client_visibility and require_native_rollback and
             require_collage and require_lantern_staged,
             "backend world region requires G2/G3 and same native client")
        proof = p.get("native_backend_world") or {}
        need(type(proof) is dict and
             proof.get("schema") == "supracraft.native-vanilla263-live-backend-region/1" and
             proof.get("classification") == "LIVE_NATIVE_BACKEND_THREE_CHECKPOINTS" and
             proof.get("same_owned_guest_three_checkpoints") is True and
             proof.get("backend_independent_world_oracle_pass") is True and
             proof.get("collage_mutation_authorized") is False and
             proof.get("physical_true_nas_apply") == "HOLD",
             "live three checkpoint backend admission unproven")
        prep = proof.get("preparation") or {}
        need(type(prep) is dict and
             prep.get("schema") == "supracraft.native-vanilla263-mineflayer-causal/1" and
             prep.get("classification") == "FIXED_PLAYER_FIXTURE_PREPARATION_ONLY" and
             prep.get("stage") == "candidate-prep" and
             prep.get("client_protocol777_connected_and_spawned") is True and
             prep.get("client_fixture_prepared_without_core_placement") is True and
             prep.get("native_guest_backend_independent_oracle_qualified") is False and
             prep.get("collage_mutation_authorized") is False and
             prep.get("physical_true_nas_apply") == "HOLD",
             "independent backend preaction preparation absent")
        blocks = {
            "preaction": ["minecraft:air", "minecraft:iron_bars", "minecraft:black_concrete"],
            "candidate": ["minecraft:redstone_block", "minecraft:air", "minecraft:sea_lantern"],
            "rollback": ["minecraft:redstone_block", "minecraft:iron_bars", "minecraft:black_concrete"],
        }
        hashes = set()
        for stage, expected in blocks.items():
            observed = proof.get(stage) or {}
            digest = observed.get("region_sha256")
            need(type(observed) is dict and
                 observed.get("schema") == "supracraft.native-vanilla263-server-owned-anvil/1" and
                 observed.get("classification") == "LIVE_NATIVE_STOPPED_OWNER_ANVIL_READBACK" and
                 observed.get("stage") == stage and
                 observed.get("block_states") == expected and
                 observed.get("coordinates") == [[0,70,0],[2,70,0],[1,70,1]] and
                 observed.get("block_state_expectations_matched") is True and
                 observed.get("requested_native_app") == APP and
                 observed.get("requested_native_world") ==
                   "rdtepool/minecraft-vanilla-263-t6-world" and
                 observed.get("requested_native_world_file_fixed") is True and
                 observed.get("read_only_middleware_calls") is True and
                 observed.get("live_guest_identity_independently_verified") is True and
                 observed.get("native_guest_server_owned_bytes_proven") is True and
                 observed.get("server_quiescence_proven") is True and
                 observed.get("raw_region_published") is False and
                 observed.get("collage_mutation_authorized") is False and
                 observed.get("physical_true_nas_apply") == "HOLD" and
                 type(observed.get("downloaded_file_size")) is int and
                 8192 <= observed["downloaded_file_size"] <= 64*1024*1024 and
                 type(digest) is str and len(digest) == 64 and
                 all(c in "0123456789abcdef" for c in digest),
                 "native server-owned Anvil stage missing or corrupted: " + stage)
            hashes.add(digest)
            readiness = (p.get("readiness") or {}).get("g4-" + stage) or {}
            need(type(readiness) is dict and
                 (readiness.get("protocol") or {}).get("oracleSatisfied") is True and
                 type((readiness.get("level") or {}).get("size")) is int and
                 readiness["level"]["size"] > 0,
                 "native backend stage restart/health missing: " + stage)
        need(len(hashes) == 3, "backend world snapshot hash replay")
    if require_native_rollback:
        need(require_lantern_staged and require_collage,
             "native rollback requires independently qualified G2 and artifact")
        rb = p.get("native_world_rollback") or {}
        need(type(rb) is dict and
             rb.get("schema") == "supracraft.native-vanilla263-rdte-rollback-mechanics/1" and
             rb.get("classification") == "G3_DISPOSABLE_MECHANICS_ONLY" and
             rb.get("phase") == "injected_fault_rolled_back" and
             rb.get("snapshot_owned") is True and
             rb.get("snapshot_id_verified") is True and
             rb.get("candidate_present_before_stage") is False and
             rb.get("release_fault_injected") is True and
             rb.get("candidate_absent_after_rollback") is True and
             rb.get("native_app_running_after_rollback") is True and
             rb.get("native_game_status_rechecked") is True and
             rb.get("candidate_sha256") ==
               "da25005e8729e6f013f7108ac5b8869dd46323befc78efdae18221b26cafe5f8" and
             rb.get("collage_managed_deployment") is False and
             rb.get("world_activation_authorized_by_collage") is False and
             rb.get("actual_player_gameplay_verified") is False and
             rb.get("physical_true_nas_mutated") is False,
             "native disposable rollback receipt missing")
        restored = (p.get("readiness") or {}).get("g3-rollback") or {}
        proto = restored.get("protocol") or {}
        level = restored.get("level") or {}
        need(type(restored) is dict and type(proto) is dict and
             proto.get("oracleSatisfied") is True and
             type(level) is dict and type(level.get("size")) is int and
             level["size"] > 0,
             "native rollback independently healthy world not observed")
    if require_collage:
        observer = p.get("collage_readback") or {}
        need(type(observer) is dict and
             observer.get("schema") == "semper-supra.collage-native-readback-p2/1" and
             observer.get("classification") == "PROVIDER_READBACK_MATCH" and
             observer.get("source_profile") == "vanilla263" and
             observer.get("source_sha") == "2b6abe1141e65b8c6872eeba6c8ae39f5a9635f8" and
             observer.get("native_app") == APP and
             observer.get("truenas_version") == TARGET and
             observer.get("world_id") == "lantern-rdte" and
             observer.get("service_id") == "11111111-1111-4111-8111-111111111111" and
             observer.get("ownership_fields_matched") == 6 and
             observer.get("transport") == "isolated_guest_tls_verified" and
             observer.get("credential_scope") == "APPS_READ" and
             observer.get("credential_mutation_phase") ==
                 "disposable_guest_setup_before_observation" and
             observer.get("observation_mutation_count") == 0 and
             observer.get("world_artifact_format_verified") is False and
             observer.get("world_activated") is False and
             observer.get("cloudnet_adoption_executed") is False and
             observer.get("physical_true_nas_mutated") is False and
             isinstance(observer.get("tls_cert_sha256"), str) and
             len(observer["tls_cert_sha256"]) == 64,
             "independent scoped native vanilla readback missing or unqualified")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--receipt", required=True, type=Path)
    p.add_argument("--require-collage-readback", action="store_true")
    p.add_argument("--require-lantern-staged", action="store_true")
    p.add_argument("--require-native-rollback", action="store_true")
    p.add_argument("--require-native-client-visibility", action="store_true")
    p.add_argument("--require-native-backend-region", action="store_true")
    a = p.parse_args()
    try:
        check(json.loads(a.receipt.read_text(encoding="utf-8")),
              require_collage=a.require_collage_readback,
              require_lantern_staged=a.require_lantern_staged,
              require_native_rollback=a.require_native_rollback,
              require_native_client_visibility=a.require_native_client_visibility,
              require_native_backend_region=a.require_native_backend_region)
    except (OSError, ValueError, TypeError) as ex:
        # Error messages generated by check() are constant, never propagate
        # arbitrary provider receipt fields, credentials or real addresses.
        msg = str(ex) if str(ex) in {
            "guest root receipt schema", "wrong exact guest identity",
            "guest/root unsupported", "guest exact source/profile mismatch",
            "wrong native workload shape", "wrong product guest oracle",
            "guest product signer/control mismatch",
            "exact native catalog not verified by guest",
            "native running OCI image digest not verified",
            "independent world not retained", "guest readiness stages absent",
            "native App/ZFS world cleanup left residue",
            "guest receipt admits secrets", "guest receipt cross-target mismatch",
            "native rollback requires independently qualified G2 and artifact",
            "native disposable rollback receipt missing",
            "native rollback independently healthy world not observed",
            "native client requires exact G2 and G3",
            "native offline client path not independently verified",
            "native offline client causal stage missing",
        } or str(ex).startswith((
            "independent vanilla protocol not accepted at ",
            "independent owned world level.dat not observed at ",
        )) else "guest receipt unreadable/invalid"
        print("Vanilla263 native T6 acceptance REFUSED: " + msg, file=sys.stderr)
        return 2
    print("Vanilla263 native T6 SUPPORTED: exact guest/catalog/Java25/protocol777/world/cleanup")
    return 0


if __name__ == "__main__":
    sys.exit(main())
