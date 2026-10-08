#!/usr/bin/env python3
"""Materialize exact WinBot 9.5 candidate graph as unreferenced Git blobs.

This creates no refs, workflow dispatches, PR merges, guests or runner jobs.
The final wrapper is still dormant until explicitly committed as a new path
following cheap qualification and heavyweight-lane admission.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import winbot_95_readiness_patch as control
import winbot_95_receipt_patch as receipt

REPO = "SemperSupra/agent-dispatch"
OLD_MASTER = "a54acfb36516bae9605ab13ec0ac7724d17abadc"
OLD_MANIFEST = "6b0871d9e9309228ac470362d6a7b81f733521c1"
CANDIDATE_CONTROL = "e0853ca10c7b2474010fc271a73808f90afd0d94"
CANDIDATE_RECEIPT_WRAPPER = "8de3136c2e053b131ae83827676d54d0dc03362f"
SOURCE = "90d5d8a7244b781c28d438d9ba01155735c765b7"
PROJECTION = "d4120a901d7855a9e0d7bc5f805d5e4b0dad8380abf52322c90f9981094d8b45"
BRANCH = "exp/winbot-95-bounded-diagnostic-20261009"
WRAPPER_PATH = ".github/workflows/winbot-95-diagnostic-a-only.yml"


def call(method: str, endpoint: str, payload: dict | None = None) -> dict:
    token = os.environ["GH_TOKEN"]
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.github.com/repos/" + REPO + endpoint,
        data=data, method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def read_blob(sha: str) -> bytes:
    obj = call("GET", "/git/blobs/" + sha)
    if obj["sha"] != sha or obj["encoding"] != "base64":
        raise ValueError("Git source identity mismatch")
    raw = base64.b64decode(obj["content"])
    if len(raw) != obj["size"] or control.git_blob_sha(raw) != sha:
        raise ValueError("Git source content mismatch")
    return raw


def create_blob(raw: bytes) -> str:
    expected = control.git_blob_sha(raw)
    obj = call("POST", "/git/blobs", {
        "content": base64.b64encode(raw).decode("ascii"),
        "encoding": "base64",
    })
    if obj["sha"] != expected or read_blob(expected) != raw:
        raise ValueError("Git object write/readback mismatch")
    return expected


def change_once(data: str, old: str, new: str) -> str:
    if data.count(old) != 1:
        raise ValueError("wrapper pinned anchor mismatch")
    return data.replace(old, new, 1)


def run() -> None:
    candidate = control.patch_control(read_blob(control.PARENT_BLOB))
    wrapper = receipt.patch_receipt(read_blob(receipt.PARENT_WORKFLOW_BLOB))
    if control.git_blob_sha(candidate) != CANDIDATE_CONTROL:
        raise ValueError("cheap qualified control candidate drift")
    if receipt.git_blob_sha(wrapper) != CANDIDATE_RECEIPT_WRAPPER:
        raise ValueError("cheap qualified receipt candidate drift")
    manifest = json.loads(read_blob(OLD_MANIFEST))
    master = json.loads(read_blob(OLD_MASTER))
    if (manifest["readiness_control_blob"] != control.PARENT_BLOB
        or master["control_manifest_sha"] != OLD_MANIFEST
        or master["construction"]["readiness_control"] != control.PARENT_BLOB
        or manifest["source_revision"] != SOURCE or master["source_revision"] != SOURCE
        or manifest["projection_identity_sha256"] != PROJECTION
        or master["projection_identity_sha256"] != PROJECTION):
        raise ValueError("parent graph authority mismatch")
    entries = [entry for entry in manifest["entries"] if entry["path"] == "rdte/gha/full-rdte.ps1"]
    if len(entries) != 1 or entries[0]["git_blob_sha"] != control.PARENT_BLOB:
        raise ValueError("unexpected control manifest entry")
    manifest["readiness_control_blob"] = CANDIDATE_CONTROL
    entries[0]["git_blob_sha"] = CANDIDATE_CONTROL
    manifest["profile"] = "AuthorityReadiness95BoundedDiagnostic"
    next_manifest = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    next_manifest_sha = control.git_blob_sha(next_manifest)
    master["control_manifest_sha"] = next_manifest_sha
    master["construction"]["readiness_control"] = CANDIDATE_CONTROL
    master["construction"]["bounded_failure_diagnostic"] = "9.5 ten boolean flags; fail-closed terminal early exit"
    master["construction"]["parent_control_manifest"] = OLD_MANIFEST
    master["construction"]["cheap_qualification_run"] = 37854376785
    master["construction"]["cheap_qualification_candidate_control"] = CANDIDATE_CONTROL
    master["construction"]["cheap_qualification_candidate_receipt_wrapper"] = CANDIDATE_RECEIPT_WRAPPER
    master["construction"]["qualification_authority"] = "SemperSupra/agent-dispatch-private#406"
    master["construction"]["launch_scope"] = "A-only; never seed or terminal before admission"
    master["construction"]["source_unchanged"] = True
    master["construction"]["projection_unchanged"] = True
    master["construction"]["guest_credentials_run_owned"] = True
    master["construction"]["bounded_receipt_only"] = True
    master["construction"]["cleanup_required"] = True
    master["construction"]["seed_and_terminal_dormant"] = True
    master["construction"]["graph_parent"] = OLD_MASTER
    next_master = (json.dumps(master, indent=2) + "\n").encode("utf-8")
    next_master_sha = control.git_blob_sha(next_master)
    w = wrapper.decode("utf-8")
    w = change_once(w, "name: WinBot Exact-NAT-Placement Windows A-Only",
                    "name: WinBot 9.5 Bounded Readiness Windows A-Only")
    w = change_once(w, "'exp/windows-sealed-public-execution'",
                    "'" + BRANCH + "'")
    w = change_once(w, "'.github/workflows/winbot-exact-nat-placement-a-only.yml'",
                    "'" + WRAPPER_PATH + "'")
    for key, old, new in (
        ("MASTER_MANIFEST_SHA", OLD_MASTER, next_master_sha),
        ("EXPECTED_CONTROL_MANIFEST_SHA", OLD_MANIFEST, next_manifest_sha),
        ("EXPECTED_A_ONLY_CONTROL_BLOB", control.PARENT_BLOB, CANDIDATE_CONTROL),
    ):
        w = change_once(w, key + ": '" + old + "'", key + ": '" + new + "'")
    w = change_once(w, "'winbot-exact-nat-placement-a-only-20261008-01'",
                    "'winbot-95-bounded-diagnostic-a-only-20261009-01'")
    if w.count("agent-dispatch-heavyweight-rdte") != 1:
        raise ValueError("shared heavyweight admission missing")
    if "queue: max" not in w or "cancel-in-progress: false" not in w:
        raise ValueError("shared heavyweight fail-closed queue missing")
    # Do not mutate permitted public-safe projection, or loosen selectors.
    if SOURCE not in w or PROJECTION not in w:
        raise ValueError("source/projection identity drift")
    new_wrapper = w.encode("utf-8")
    created = {
        "control_blob": create_blob(candidate),
        "control_manifest_blob": create_blob(next_manifest),
        "master_manifest_blob": create_blob(next_master),
        "dormant_wrapper_blob": create_blob(new_wrapper),
    }
    result = {
        "classification": "EXACT_GRAPH_MATERIALIZED_DORMANT",
        "authority": "SemperSupra/agent-dispatch-private#406",
        "product_source_revision": SOURCE,
        "projection_identity_sha256": PROJECTION,
        "cheap_qualification_run": 37854376785,
        "cheap_qualification_pass": True,
        "graph": created,
        "wrapper_path_when_admitted": WRAPPER_PATH,
        "heavy_guest_launched": False,
        "seed_or_terminal_launched": False,
        "credential_imported": False,
        "execution_admitted": False,
    }
    output = Path(os.environ["RUNNER_TEMP"]) / "winbot-95-graph.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    # Git status is a discoverable, secret-free receipt pointer. No refs change.
    result_bytes = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8")
    receipt_blob = create_blob(result_bytes)
    call("POST", "/statuses/" + os.environ["GITHUB_SHA"], {
        "state": "success",
        "context": "winbot-95-exact-graph",
        "description": "receipt_git_blob=" + receipt_blob,
        "target_url": "https://api.github.com/repos/" + REPO + "/git/blobs/" + receipt_blob,
    })
    print(json.dumps({"receipt_git_blob": receipt_blob, **result}, sort_keys=True))


if __name__ == "__main__":
    run()
