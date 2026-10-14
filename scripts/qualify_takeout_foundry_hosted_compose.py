#!/usr/bin/env python3
"""Source-only official Foundry hostpath plan for public synthetic Takeout.

Creates a disposable, isolated hostpath variant of the pinned public Foundry
candidate inside an ephemeral checkout, then renders via official iX library.
No secrets, production paths, Docker actions or TrueNAS host are accessed here.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import yaml

PUBLIC_FOUNDRY_HEAD = "b5005f1c354ea994d04baf45bfb559506b2ae309"
SOURCE = "candidates/takeout-synthetic-app/ix-dev/community/takeoutsynthetic"
ARCHIVE = "/mnt/rdtepool/takeout-synthetic/archives"
STATE = "/mnt/rdtepool/takeout-synthetic/state"
EXPECTED_CONFIG = "sha256:86de81f4401811f145c0569a210482a559746aa337f28554bb751ece08f77b7c"
ORIGINAL_IMAGE = "ghcr.io/sempersupra/takeout-synthetic:0.0.0-UNPUBLISHED"
LOCAL_IMAGE = "takeout-synthetic:local"


def checked(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def qualify(root: Path, output: Path) -> dict:
    # Caller independently checks its checkout identity against this commit.
    root = root.resolve()
    source = root / SOURCE
    checked(source.is_dir(), "FOUNDRY_SOURCE_MISSING")
    target = root / "candidates/takeout-synthetic-app/hostpath-probe-only/ix-dev/community/takeoutsynthetic"
    checked(not target.exists(), "EPHEMERAL_SOURCE_ALREADY_EXISTS")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target)
    defaults = yaml.safe_load((target / "ix_values.yaml").read_text())
    questions = yaml.safe_load((target / "questions.yaml").read_text())
    values = yaml.safe_load((source / "templates/test_values/basic-values.yaml").read_text())
    for role, path in (("archives", ARCHIVE), ("state", STATE)):
        conf = {
            "type": "host_path",
            "host_path_config": {
                "path": path, "acl_enable": False, "auto_permissions": False,
            },
        }
        defaults["storage"][role] = copy.deepcopy(conf)
        values["storage"][role] = copy.deepcopy(conf)
        item = next(x for x in questions["questions"] if x["variable"] == "storage")
        slot = next(x for x in item["schema"]["attrs"] if x["variable"] == role)
        slot["schema"]["attrs"] = [
            {"variable": "type", "label": "Storage Type",
             "schema": {"type": "string", "default": "host_path", "hidden": True,
                        "required": True, "enum": [{"value": "host_path", "description": "Disposable host dataset"}]}},
            {"variable": "host_path_config", "label": "Existing guest dataset",
             "schema": {"type": "dict", "attrs": [
                 {"variable": "path", "label": "Path",
                  "schema": {"type": "hostpath", "required": True, "default": path}},
                 {"variable": "acl_enable", "label": "ACL",
                  "schema": {"type": "boolean", "default": False}},
                 {"variable": "auto_permissions", "label": "Auto permissions",
                  "schema": {"type": "boolean", "default": False}},
             ]}},
        ]
    values.pop("ix_volumes", None)
    (target / "ix_values.yaml").write_text(yaml.safe_dump(defaults, sort_keys=False))
    (target / "questions.yaml").write_text(yaml.safe_dump(questions, sort_keys=False))
    values_path = target / "templates/test_values/hostpath-probe-values.yaml"
    values_path.write_text(yaml.safe_dump(values, sort_keys=False))
    manifest = json.loads((root / "candidates/takeout-synthetic-app/candidate.json").read_text())
    checked(manifest["source_only"] is True and manifest["product_image"] == "UNPUBLISHED",
            "CANDIDATE_NOT_ON_HOLD")
    checked(manifest["claims"]["physical_apply"] == "HOLD", "PHYSICAL_HOLD_BROKEN")
    checked(manifest["claims"]["disposable_truenas"] == "NOT_RUN", "GUEST_HOLD_BROKEN")
    checked(manifest["synthetic_transport_evidence"]["loaded_image_config_sha256"] == EXPECTED_CONFIG,
            "PRODUCER_CONFIG_MISMATCH")
    manifest["source_path"] = target.relative_to(root).as_posix()
    manifest["phase"] = "EPHEMERAL_HOSTPATH_SOURCE_PROBE_NOT_DEPLOYABLE"
    manifest_path = target.parents[2] / "hostpath-probe-candidate.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True))
    private_compose = output.with_name("official-hostpath-original.json")
    command = [sys.executable, str(root / "tools/render_truenas_candidate.py"),
               "--candidate", str(manifest_path), "--values", str(values_path),
               "--output-compose", str(private_compose)]
    finished = subprocess.run(command, cwd=root, text=True, capture_output=True)
    checked(finished.returncode == 0, "OFFICIAL_HOSTPATH_SOURCE_RENDER_FAILED")
    original = json.loads(private_compose.read_text())
    services = original["services"]
    checked(set(services) == {"takeoutsynthetic"}, "UNEXPECTED_SERVICE_OR_PERMISSION_SIDECAR")
    worker = services["takeoutsynthetic"]
    checked(worker["image"] == ORIGINAL_IMAGE, "UNEXPECTED_ORIGINAL_SOURCE_IMAGE")
    checked(worker.get("restart") == "no", "ONE_SHOT_RESTART_UNSAFE")
    checked(worker.get("read_only") is True, "WORKER_ROOTFS_NOT_READ_ONLY")
    checked(str(worker.get("user")) in ("10001", "10001:10001"), "WORKER_NOT_ROOTLESS")
    checked(not worker.get("ports") and not worker.get("privileged"), "PUBLIC_PORT_OR_PRIVILEGE")
    checked(not any("docker.sock" in str(x) for x in worker.get("volumes", [])),
            "DOCKER_SOCKET_MOUNT")
    volumes = json.dumps(worker.get("volumes", []))
    checked(ARCHIVE in volumes and STATE in volumes and
            "/archive" in volumes and "/state" in volumes, "RETENTION_PATH_DRIFT")
    candidate = copy.deepcopy(original)
    candidate["services"]["takeoutsynthetic"]["image"] = LOCAL_IMAGE
    reverse = copy.deepcopy(candidate)
    reverse["services"]["takeoutsynthetic"]["image"] = ORIGINAL_IMAGE
    checked(reverse == original, "LOCAL_IMAGE_DIFF_EXCEEDED_ONE_FIELD")
    output.write_text(json.dumps(candidate, sort_keys=True, indent=2) + "\n")
    output.chmod(0o600)
    return {
        "classification": "HOSTED_OFFICIAL_SOURCE_COMPOSE_INTEGRATION_PREFLIGHT",
        "official_source": PUBLIC_FOUNDRY_HEAD,
        "upstream_renderer": manifest["source_materializer"]["commit"],
        "expected_loaded_config": EXPECTED_CONFIG,
        "original_compose_digest": sha256(private_compose.read_bytes()),
        "image-bound_compose_digest": sha256(output.read_bytes()),
        "diff": "/services/takeoutsynthetic/image",
        "services": sorted(services),
        "archive_host": ARCHIVE, "state_host": STATE,
        "app_runtime": "NOT_RUN_YET",
        "truenas_guest": "NOT_RUN",
        "physical_apply": "HOLD",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--foundry-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        result = qualify(args.foundry_root, args.output)
    except (OSError, KeyError, ValueError, subprocess.SubprocessError):
        print(json.dumps({"status": "BLOCKED", "classification": "SOURCE_RENDER_UNQUALIFIED"}))
        return 2
    print(json.dumps({"status": "PASS", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
