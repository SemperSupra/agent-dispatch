#!/usr/bin/env python3
"""OP-4B independent immutable Foundry control admission for vanilla 26.3.

This deliberately does NOT create a TrueNAS App or generalize old Paper T6.
Native guest selector must remain unavailable until an independent guest probe
and exact guest receipt gate exist. No physical TrueNAS APPLY is authorized.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SCHEMA = "semper-supra.minecraft-vanilla-263-truenas-t6-control/1"
PRODUCER = "5ee204df205edfd531304441fd1a6a24004557b1"
CONTROL_SHA = "59516bbbcb1750af6f0cb1c624756f08113a070acc11c60affe94d2bbd8d8dd5"
APPS_REF = "95b0cc78e75fcd4b128f4ef2f8428034d981f7c2"
OCI = ("ghcr.io/itzg/minecraft-server:2026.10.0-java25@sha256:"
       "5a2ab74ae179c11e2dbbce67f307cdcf2c1257b3abb0f654d3a310b3d8ea57da")
TARGET = "25.04.2.6"
MIDDLEWARE = "244b717370fe35fb9eefc3096acfbc25f12b57b6"
PROFILE_BLOB = "631467044411c96a0fe6d361688b99a794f07c80"
APP = "rdte-t6-minecraft-vanilla-263"
WORLD = "rdtepool/minecraft-vanilla-263-t6-world"
OWNER = {
    "SUPRACRAFT_COLLAGE_MANAGED": "true",
    "SUPRACRAFT_COLLAGE_SCHEMA": "1",
    "SUPRACRAFT_COLLAGE_MANAGER_ID": "manager-rdte",
    "SUPRACRAFT_COLLAGE_FLEET_ID": "rdte",
    "SUPRACRAFT_COLLAGE_SERVICE_ID": "11111111-1111-4111-8111-111111111111",
    "SUPRACRAFT_COLLAGE_WORLD_ID": "lantern-rdte",
}
RECEIPT = "semper-supra.minecraft-vanilla263-t6-consumer-admission/1"


class Refused(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Refused(reason)


def canonical_hash(doc: dict) -> str:
    return hashlib.sha256(json.dumps(doc, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()


def verify(control: dict, *, expected_producer: str = PRODUCER,
           expected_digest: str = CONTROL_SHA) -> dict:
    """Verify entire canonical signer/digest and critical materialization invariants."""
    require(type(control) is dict and control.get("schema") == SCHEMA,
            "VANILLA_CONTROL_SCHEMA_DRIFT")
    signed = dict(control)
    signature = signed.pop("control_sha256", None)
    require(re.fullmatch(r"[0-9a-f]{40}", expected_producer) is not None,
            "FOUNDRY_IMMUTABLE_REF_REQUIRED")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_digest) is not None,
            "CANONICAL_DIGEST_REQUIRED")
    require(control.get("foundry_ref") == expected_producer == PRODUCER,
            "FOUNDRY_PRODUCER_REF_DRIFT")
    require(signature == canonical_hash(signed) == expected_digest == CONTROL_SHA,
            "CANONICAL_CONTROL_SHA_DRIFT")
    target = control.get("target") or {}
    require(type(target) is dict and
            target.get("truenas_version") == TARGET and
            target.get("expected_system_version") == "TrueNAS-" + TARGET and
            target.get("middleware_commit") == MIDDLEWARE and
            target.get("profile_git_blob_sha") == PROFILE_BLOB,
            "NATIVE_GUEST_TARGET_DRIFT")
    source = control.get("source") or {}
    require(type(source) is dict and
            source.get("apps_commit") == APPS_REF and
            source.get("catalog_app") == "community/minecraft" and
            source.get("catalog_version") == "1.15.31" and
            source.get("library_version") == "2.3.16" and
            source.get("image_reference") == OCI and
            isinstance(source.get("source_compose_sha256"), str) and
            re.fullmatch("[0-9a-f]{64}", source["source_compose_sha256"]) and
            isinstance(source.get("values_raw_sha256"), str) and
            re.fullmatch("[0-9a-f]{64}", source["values_raw_sha256"]),
            "NATIVE_CATALOG_SOURCE_DRIFT")
    runtime = control.get("runtime") or {}
    require(type(runtime) is dict and
            runtime.get("app_name") == APP and
            runtime.get("catalog_app") == "minecraft" and
            runtime.get("train") == "community" and
            runtime.get("catalog_version_candidate") == "1.15.31" and
            runtime.get("minecraft_version") == "26.3" and
            runtime.get("minecraft_protocol") == 777 and
            runtime.get("java_version") == 25 and
            runtime.get("image_selector") == "j25_image" and
            runtime.get("required_independent_world_dataset") == WORLD and
            runtime.get("status_oracle") == "minecraft-java-status-oracle/v1",
            "NATIVE_VANILLA_PRODUCT_DRIFT")
    values = runtime.get("values_template") or {}
    require(type(values) is dict, "NATIVE_VALUES_SCHEMA_DRIFT")
    minecraft = values.get("minecraft") or {}
    require(type(minecraft) is dict and
            minecraft.get("type") == "VANILLA" and
            minecraft.get("version") == "26.3" and
            minecraft.get("image_selector") == "j25_image" and
            minecraft.get("eula") is True and
            minecraft.get("online_mode") is True and
            minecraft.get("enable_rcon") is False and
            minecraft.get("rcon_password") == "",
            "NATIVE_VANILLA_RUNTIME_INPUT_DRIFT")
    envs = minecraft.get("additional_envs")
    require(type(envs) is list and len(envs) == len(OWNER) and
            all(type(v) is dict and set(v) == {"name", "value"} for v in envs) and
            {v["name"]: v["value"] for v in envs} == OWNER,
            "NATIVE_OWNERSHIP_DRIFT")
    storage = values.get("storage") or {}
    mounts = storage.get("additional_storage")
    require(type(storage) is dict and
            (storage.get("data") or {}).get("type") == "ix_volume" and
            type(mounts) is list and len(mounts) == 1 and
            type(mounts[0]) is dict and
            mounts[0].get("mount_path") == "/data/world" and
            mounts[0].get("type") == "host_path" and
            mounts[0].get("read_only") is False and
            (mounts[0].get("host_path_config") or {}).get("path") ==
            "/opt/tests/collage-vanilla-263-world",
            "NATIVE_WORLD_OWNER_BOUNDARY_DRIFT")
    network = values.get("network") or {}
    require(type(network) is dict and network.get("host_network") is False and
            (network.get("server_port") or {}).get("port_number") == 25565 and
            (network.get("server_port") or {}).get("bind_mode") == "published",
            "NATIVE_PORT_POLICY_DRIFT")
    evidence = control.get("evidence") or {}
    require(type(evidence) is dict and evidence.get("source_render_pass") is True and
            all(evidence.get(field) is False for field in (
                "live_catalog_version_verified", "native_guest_created",
                "gameplay_qualified_by_native_guest",
                "external_world_retention_qualified_by_native_guest",
                "collage_managed_deployment_qualified",
                "physical_truenas_qualified")) and
            control.get("operational_selection") is False and
            control.get("physical_truenas_apply") == "HOLD",
            "SOURCE_ONLY_GUEST_OR_PHYSICAL_PROMOTION_DRIFT")
    return {
        "schema": RECEIPT,
        "classification": "SOURCE_CONTROL_READY_GUEST_NOT_DISPATCHED",
        "product": "minecraft-vanilla-263",
        "foundry_ref": expected_producer,
        "control_sha256": expected_digest,
        "truenas_version": TARGET,
        "catalog_version": "1.15.31",
        "minecraft_version": "26.3",
        "minecraft_protocol": 777,
        "java_version": 25,
        "image_sha256": OCI.split("@sha256:", 1)[1],
        "world_id": OWNER["SUPRACRAFT_COLLAGE_WORLD_ID"],
        "native_guest_created": False,
        "native_guest_qualified": False,
        "physical_truenas_apply": "HOLD",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--control", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    try:
        require(a.control.is_file() and a.control.stat().st_size <= 128 * 1024,
                "CONTROL_MISSING_OR_OVERSIZED")
        result = verify(json.loads(a.control.read_text(encoding="utf-8")))
        ok = True
    except (OSError, ValueError, TypeError) as ex:
        raw = str(ex)
        reason = raw if re.fullmatch("[A-Z0-9_]{3,90}", raw) else "SOURCE_CONTROL_INVALID"
        result = {"schema": RECEIPT, "classification": "REFUSED",
                  "failure_code": reason, "native_guest_qualified": False,
                  "physical_truenas_apply": "HOLD"}
        ok = False
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"classification": result["classification"],
                      "failure_code": result.get("failure_code")}, sort_keys=True))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
