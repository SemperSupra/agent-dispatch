#!/usr/bin/env python3
"""Read-only admission of the ACTUAL Foundry v1 immutable deployment artifact.

Authority: SemperSupra/truenas-app-foundry tools/package_truenas_deployment_artifact.py
and tools/foundry_inventory_materialize.py. This does NOT contact TrueNAS,
construct a synthetic lifecycle plan, or grant physical APPLY/release authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

SCHEMA = "truenas-foundry-deployment-artifact/v1"
TARGET = "truenas-scale-apps"
DIGEST = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
IMAGE = re.compile(r"^\\S+@sha256:[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z]([-a-z0-9]*[a-z0-9])?$")
METHODS = {"app.query", "app.config", "app.create", "app.update"}


class ArtifactGateError(ValueError):
    pass


def canonical_sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArtifactGateError(message)


def admit(doc: dict, *, target_version: str, source_ref: str,
          source_tree_sha256: str, profile_path: str) -> dict:
    """Verify producer's exact schema/digests, not invented adapter fields."""
    require(isinstance(doc, dict), "artifact must be an object")
    require(doc.get("schema") == SCHEMA, "unsupported Foundry deployment artifact schema")
    require(doc.get("runtime_target") == TARGET, "invalid target runtime")
    artifact_sha = doc.get("artifact_sha256")
    require(isinstance(artifact_sha, str) and bool(DIGEST.fullmatch(artifact_sha)),
            "malformed artifact digest")
    unsealed = dict(doc)
    unsealed.pop("artifact_sha256")
    require(canonical_sha(unsealed) == artifact_sha, "artifact bytes differ from digest")
    name = doc.get("app_name")
    require(isinstance(name, str) and len(name) <= 40 and NAME.fullmatch(name) is not None,
            "invalid TrueNAS application name")
    require(name not in {"garm", "foliorelay", "foliorelay-291"} and
            not name.startswith(("production-", "system-", "foliorelay-")),
            "protected app ownership boundary")
    compose_sha = doc.get("compose_sha256")
    require(isinstance(compose_sha, str) and bool(DIGEST.fullmatch(compose_sha)),
            "malformed Compose digest")
    require(doc.get("materialization_identity") == "sha256:" + compose_sha,
            "materialization identity mismatch")
    create = doc.get("create_payload")
    update = doc.get("update_payload")
    require(isinstance(create, dict) and isinstance(update, dict), "missing App payloads")
    require(create.get("custom_app") is True and create.get("app_name") == name,
            "not a named Foundry Custom App")
    compose = create.get("custom_compose_config")
    require(isinstance(compose, dict) and isinstance(compose.get("services"), dict) and
            bool(compose["services"]), "missing actual normalized Compose services")
    require(canonical_sha(compose) == compose_sha, "Compose payload differs from digest")
    require(update.get("custom_compose_config") == compose, "update differs from create")
    require(set(doc.get("required_methods") or []) == METHODS, "unexpected required methods")

    # A live semantic oracle is mandatory at runtime. Source admission cannot
    # infer it from a RUNNING middleware state.
    for svc in compose["services"].values():
        require(isinstance(svc, dict), "malformed Compose service")
        image = svc.get("image")
        require(isinstance(image, str) and IMAGE.fullmatch(image) is not None,
                "runtime service image must be digest-pinned")
        require(svc.get("privileged") is not True and svc.get("network_mode") != "host"
                and svc.get("pid") != "host" and svc.get("ipc") != "host",
                "privileged or host-mode service is not admitted")
        require(not svc.get("devices") and not svc.get("cap_add"),
                "raw devices or capabilities require separate policy")
    provenance = doc.get("provenance")
    require(isinstance(provenance, dict) and provenance.get("source") == "foundry-inventory",
            "unbound inventory provenance")
    require(provenance.get("target_version") == target_version and
            provenance.get("target_profile") == profile_path,
            "exact TrueNAS target/profile mismatch")
    require(provenance.get("source_tree_sha256") == source_tree_sha256 and
            isinstance(source_tree_sha256, str) and
            source_tree_sha256.startswith("sha256:") and
            bool(DIGEST.fullmatch(source_tree_sha256[7:])),
            "source tree identity mismatch")
    source = provenance.get("source_identity")
    require(isinstance(source, dict) and source.get("kind") == "foundry-repository",
            "missing Foundry-owned source")
    require(COMMIT.fullmatch(source_ref) is not None and source.get("ref") == source_ref,
            "unpinned or mismatched Foundry source revision")
    require(source.get("repository") == "https://github.com/SemperSupra/truenas-app-foundry.git",
            "wrong source repository")
    require(provenance.get("catalog_validator") == "PASS",
            "actual upstream catalog source validator not accepted")
    require(provenance.get("app_id") == "foundry-rdte-probe",
            "generic artifact gate not admitted for other candidates yet")

    return {
        "schema": "truenas-foundry-artifact-admission/v1",
        "classification": "SOURCE_ADMITTED_NOT_RUN",
        "runtime_support_claim": "OPEN",
        "f0_f5_qualified": False,
        "independent_live_readback_confirmed": False,
        "physical_apply_authority": "HOLD",
        "app_name": name,
        "target_version": target_version,
        "artifact_sha256": artifact_sha,
        "materialization_identity": doc["materialization_identity"],
        "source_tree_sha256": source_tree_sha256,
        "source_revision": source_ref,
        "next_gate": "EXACT_ARTIFACT_LIVE_TRUE_NAS_OBSERVE_PLAN_EXECUTE_ORACLE_CLEANUP",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--artifact", required=True, type=Path)
    p.add_argument("--target-version", required=True)
    p.add_argument("--source-ref", required=True)
    p.add_argument("--source-tree-sha256", required=True)
    p.add_argument("--profile-path", required=True)
    a = p.parse_args()
    try:
        result = admit(json.loads(a.artifact.read_text(encoding="utf-8")),
                       target_version=a.target_version, source_ref=a.source_ref,
                       source_tree_sha256=a.source_tree_sha256,
                       profile_path=a.profile_path)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result = {"schema": "truenas-foundry-artifact-admission/v1",
                  "classification": "SOURCE_REJECTED", "f0_f5_qualified": False,
                  "runtime_support_claim": "OPEN", "physical_apply_authority": "HOLD",
                  "reason_type": type(exc).__name__}
        print(json.dumps(result, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
