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


def check(root: dict, *, require_collage: bool = False) -> None:
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
         shape.get("catalog_version_candidate") == "1.15.30" and
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
    if require_collage:
        observer = p.get("collage_readback") or {}
        need(type(observer) is dict and
             observer.get("schema") == "semper-supra.collage-native-readback-p2/1" and
             observer.get("classification") == "PROVIDER_READBACK_MATCH" and
             observer.get("source_profile") == "vanilla263" and
             observer.get("source_sha") == "17dfacc4351053fa06f8bdbaed7d931c97c1707e" and
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
    a = p.parse_args()
    try:
        check(json.loads(a.receipt.read_text(encoding="utf-8")),
              require_collage=a.require_collage_readback)
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
