#!/usr/bin/env python3
"""Read-only Foundry Element Web F0-F5 source-to-guest admission membrane.

Consumes the real Foundry v1 artifact and the existing Agent Dispatch source
gate. Never connects to TrueNAS or mutates it. A source verdict is not an
F0-F5 qualification, launch approval, or physical APPLY authorization.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from truenas_foundry_artifact_gate import admit, ArtifactGateError

EXPECTED_IMAGE = (
    "ghcr.io/element-hq/element-web:v1.12.30@sha256:"
    "3e7dbd4424de9e11c812bc740acf2725b2abe66ea0d0802023b56fd85d3fa09a"
)
OWNED_FILE = "/mnt/rdtepool/rdte-foundry-element-web-f0f5/config.json"
CONFIG_TARGET = "/app/config.json"
MAX_CONTAINER_MEMORY_BYTES = 4 * 1024 * 1024 * 1024


def preflight(artifact: dict, *, target_version: str, source_ref: str,
              source_tree_sha256: str, profile_path: str) -> dict:
    source_receipt = admit(
        artifact,
        target_version=target_version,
        source_ref=source_ref,
        source_tree_sha256=source_tree_sha256,
        profile_path=profile_path,
    )
    compose = artifact["create_payload"]["custom_compose_config"]
    services = compose["services"]
    if set(services) != {"element-web"}:
        raise ArtifactGateError("Element Web fixture requires one named element-web service")
    service = services["element-web"]
    if service.get("image") != EXPECTED_IMAGE:
        raise ArtifactGateError("Element Web image differs from pinned exact source")
    if service.get("user") != "568:568" or "ALL" not in service.get("cap_drop", []):
        raise ArtifactGateError("Element Web non-root/cap-drop source policy drift")
    if service.get("network_mode") == "host":
        raise ArtifactGateError("Element Web must not use host networking")
    ports = service.get("ports")
    if not isinstance(ports, list) or len(ports) != 1:
        raise ArtifactGateError("Element Web must expose exactly one app port")
    port = ports[0]
    if (not isinstance(port, dict) or str(port.get("target")) != "8080"
            or str(port.get("published")) != "8080" or port.get("protocol") != "tcp"):
        raise ArtifactGateError("Element Web 8080/tcp runtime port identity drift")
    limits = (service.get("deploy") or {}).get("resources", {}).get("limits", {})
    memory = limits.get("memory")
    try:
        parsed_mem = int(memory)
    except (TypeError, ValueError):
        raise ArtifactGateError("Element Web resource ceiling is missing") from None
    if not 0 < parsed_mem <= MAX_CONTAINER_MEMORY_BYTES:
        raise ArtifactGateError("Element Web resource ceiling exceeds bounded 4RDTE budget")
    health = (service.get("healthcheck") or {}).get("test")
    if not isinstance(health, list) or not any("/version" in str(a) for a in health):
        raise ArtifactGateError("Element Web semantic HTTP /version healthcheck is missing")

    # F5 requires actual app-owned configuration. The default real Foundry
    # artifact has no /app/config.json bind: never infer persistence from
    # RUNNING, /version, or another product's retained-data receipt.
    volumes = service.get("volumes") or []
    binds = []
    for item in volumes:
        if not isinstance(item, dict):
            raise ArtifactGateError("Element Web expects normalized Compose volume objects")
        if item.get("target") == CONFIG_TARGET:
            binds.append((item.get("type"), item.get("source"), item.get("read_only")))
    if not binds:
        classification = "SOURCE_ADMITTED_LIVE_BLOCKED"
        blocking = ["OWNED_CONFIG_JSON_BIND_MISSING", "LIVE_DDP_SEMANTIC_OWNERSHIP_CLEANUP_UNPROVEN"]
    elif (len(binds) != 1 or binds[0][0] != "bind"
          or binds[0][1] != OWNED_FILE or binds[0][2] is not True):
        raise ArtifactGateError("Element Web config file bind is not the exact read-only owned host path")
    else:
        classification = "SOURCE_LAYOUT_READY_NOT_RUN"
        blocking = ["LIVE_DDP_SEMANTIC_OWNERSHIP_CLEANUP_UNPROVEN",
                    "INDEPENDENT_LIVE_ADMISSION_REVIEW"]
    return {
        "schema": "truenas-foundry-element-web-source-preflight/v1",
        "classification": classification,
        "source_admission": source_receipt["classification"],
        "target_version": target_version,
        "artifact_sha256": artifact["artifact_sha256"],
        "materialization_identity": artifact["materialization_identity"],
        "image": EXPECTED_IMAGE,
        "config_bind_checked": bool(binds),
        "blocking_gates": blocking,
        "live_execution_admitted": False,
        "f0_f5_qualified": False,
        "physical_apply_authority": "HOLD",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", type=Path, required=True)
    ap.add_argument("--target-version", required=True)
    ap.add_argument("--source-ref", required=True)
    ap.add_argument("--source-tree-sha256", required=True)
    ap.add_argument("--profile-path", required=True)
    args = ap.parse_args()
    try:
        doc = json.loads(args.artifact.read_text(encoding="utf-8"))
        result = preflight(
            doc, target_version=args.target_version, source_ref=args.source_ref,
            source_tree_sha256=args.source_tree_sha256, profile_path=args.profile_path)
    except (ArtifactGateError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({
            "schema": "truenas-foundry-element-web-source-preflight/v1",
            "classification": "SOURCE_REJECTED",
            "live_execution_admitted": False,
            "f0_f5_qualified": False,
            "physical_apply_authority": "HOLD",
            "cause_type": type(exc).__name__,
        }, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
