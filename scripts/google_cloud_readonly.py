#!/usr/bin/env python3
"""Strict Google Cloud read-only metadata rep for one trusted GitHub Actions job.

No user-supplied commands. Never publish Cloud project numbers/IDs, API responses
or credential data. A receipt proves the probe's observations, not external IAM acceptance.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

EXPECTED = {
    "GITHUB_REPOSITORY": "SemperSupra/agent-dispatch",
    "GITHUB_REPOSITORY_ID": "1350205857",
    "GITHUB_REPOSITORY_OWNER_ID": "68664496",
    "GITHUB_WORKFLOW_REF": (
        "SemperSupra/agent-dispatch/.github/workflows/"
        "google-cloud-readonly.yml@refs/heads/main"
    ),
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_RUN_ATTEMPT": "1",
}
RECEIPT_FIELDS = frozenset({
    "schema_version", "status", "source_sha", "run_id", "run_attempt",
    "repository_id", "event_name", "project_metadata_verified",
})
PROJECT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def admitted(env: dict[str, str]) -> bool:
    return all(type(env.get(key)) is str and env[key] == value for key, value in EXPECTED.items()) \
        and bool(SHA_PATTERN.fullmatch(env.get("GITHUB_SHA", ""))) \
        and bool(re.fullmatch(r"[1-9][0-9]*", env.get("GITHUB_RUN_ID", "")))


def validate_receipt(receipt: object, env: dict[str, str]) -> bool:
    return (
        admitted(env)
        and isinstance(receipt, dict)
        and set(receipt) == RECEIPT_FIELDS
        and receipt["schema_version"] == 1
        and receipt["status"] == "verified"
        and receipt["source_sha"] == env["GITHUB_SHA"]
        and receipt["run_id"] == env["GITHUB_RUN_ID"]
        and type(receipt["run_attempt"]) is int
        and receipt["run_attempt"] == 1
        and receipt["repository_id"] == EXPECTED["GITHUB_REPOSITORY_ID"]
        and receipt["event_name"] == "workflow_dispatch"
        and receipt["project_metadata_verified"] is True
    )


def probe(env: dict[str, str], destination: Path) -> int:
    if not admitted(env):
        return 2
    project_id = env.get("GOOGLE_RO_PROJECT_ID", "")
    if not PROJECT_ID_PATTERN.fullmatch(project_id):
        return 2
    try:
        result = subprocess.run(
            ["gcloud", "--quiet", "projects", "describe", project_id,
             "--format=json(projectNumber)"],
            timeout=35, check=False, capture_output=True, text=True,
            env={**os.environ, "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"},
        )
        # Suppress stdout AND stderr from gcloud even on failure.
        if result.returncode != 0 or len(result.stdout) > 4096:
            return 3
        response = json.loads(result.stdout)
        if not isinstance(response, dict):
            return 3
        number = response.get("projectNumber")
        if not isinstance(number, (str, int)) or not str(number).isdigit():
            return 3
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return 3
    receipt = {
        "schema_version": 1,
        "status": "verified",
        "source_sha": env["GITHUB_SHA"],
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": 1,
        "repository_id": EXPECTED["GITHUB_REPOSITORY_ID"],
        "event_name": "workflow_dispatch",
        "project_metadata_verified": True,
    }
    if not validate_receipt(receipt, env):
        return 3
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON property")
        result[key] = value
    return result


def verify(path: Path, env: dict[str, str]) -> int:
    try:
        raw = path.read_text(encoding="utf-8")
        if len(raw) > 4096:
            return 4
        receipt = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, ValueError, UnicodeError):
        return 4
    return 0 if validate_receipt(receipt, env) else 4


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--probe", type=Path)
    mode.add_argument("--verify", type=Path)
    args = ap.parse_args(argv)
    rc = probe(os.environ, args.probe) if args.probe else verify(args.verify, os.environ)
    print("google_cloud_readonly_pass" if rc == 0 else "google_cloud_readonly_not_verified")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
