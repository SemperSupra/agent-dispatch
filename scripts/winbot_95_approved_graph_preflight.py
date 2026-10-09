#!/usr/bin/env python3
"""Fail-closed, one-run WinBot A-only graph preflight. Read-only, no guest launches.

Reads only immutable Git blobs from this public repo, verifies upstream owner
authorization and qualified source projection, and writes a bounded hash-only
receipt. Neither secrets nor source bytes are printed or uploaded.
"""
from __future__ import annotations
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request

REPO = "SemperSupra/agent-dispatch"
SOURCE = "33f047df21269d8556b47f3cda7122ca22ca88ad"
PROJECTION = "270ab93819eb7f0a1c95bdb38f27233af6396bd9cd978aedc47f734ae150deee"
STAGE = "fea7b9871e8d569f5cd868b85f2f9870249be71c"
MASTER = "4e0ccb1bddebe23dc3bb3a9a6c4ab243a1d3c339"
CONTROL_MANIFEST = "82afbd00d434ee84f796f073a9ef15f90a306afe"
POLICY = "3d731c0f25b988b142943ede71c7a83d94e2f01c"
WRAPPER = "bdec421862fd8ecd57ca494e0ff92773bf8cc209"
CONTROL = "8426b7490f6d46fffd35085647fdea680f7ba669"
ORIGINAL_MASTER = "2c45ff5e113603fe016982bcc411915f2d6d6d01"
ORIGINAL_STAGE = "0efa30b3c585a7a5fbee2271040cb8046d7ec262"
ASSIGNMENT = "winbot-95-owner-approved-a-only-20261009-01"
APPROVAL = "SemperSupra/agent-dispatch-private#406 comment 6076235901"
BATCHES = [
    "6bbefc02be214378b59857e5f6c6f568420cdd50",
    "0e21df5bd48a0963964b311b5c16c71400d10f25",
    "496abd7fbdded9d20b453db19a2677bcc209ce0b",
    "f8210dcb9ba9159866f382bdd5d4761cce8999d7",
    "04c2f47bf384bdb67fbd52798a48021e3042ca65",
    "978a4f88ad795da2faad723c68cf2269ddfad429",
    "45a3efe809ee8079885cb1ee6cc22fe01e381f93",
    "02d5784f74d95d70349e89fe7b12f4476ce2b6e6",
    "6d5696cfccdd3568ca6325e960a34ef91f87dace",
]

def git_hash(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

def read_blob(sha: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("invalid immutable Git object reference")
    req = urllib.request.Request(
        "https://api.github.com/repos/" + REPO + "/git/blobs/" + sha,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        obj = json.load(response)
    if obj.get("sha") != sha or obj.get("encoding") != "base64":
        raise ValueError("Git object SHA/encoding mismatch")
    raw = base64.b64decode(obj["content"], validate=False)
    if obj["size"] != len(raw) or git_hash(raw) != sha:
        raise ValueError("Git blob byte hash mismatch")
    return raw

def require(cond: bool, reason: str) -> None:
    if not cond:
        raise ValueError(reason)

def main() -> None:
    master = json.loads(read_blob(MASTER))
    controls = json.loads(read_blob(CONTROL_MANIFEST))
    policy = json.loads(read_blob(POLICY))
    wrapper = read_blob(WRAPPER).decode("utf-8-sig")
    original = json.loads(read_blob(ORIGINAL_MASTER))
    require(master["source_revision"] == SOURCE and
            master["projection_identity_sha256"] == PROJECTION and
            master["control_manifest_sha"] == CONTROL_MANIFEST and
            master["source_batch_manifests"] == BATCHES,
            "master exact-source graph mismatch")
    require(master["projected_file_count"] == 82 and master["projected_bytes"] == 1054722,
            "projection capacity mismatch")
    require(master["construction"]["stage_provision_blob"] == STAGE and
            master["construction"]["projection_policy_authorization_blob"] == POLICY and
            master["construction"]["projection_policy_authorization_dle"] == APPROVAL and
            master["construction"]["approved_for_single_a_only_run"] is True and
            master["construction"]["seed_and_terminal_dormant"] is True and
            master["construction"]["retry_requires_new_owner_approval"] is True and
            master["construction"]["graph_parent"] == ORIGINAL_MASTER,
            "scoped single-run master policy mismatch")
    require(original["source_revision"] != SOURCE and
            original["projection_identity_sha256"] != PROJECTION,
            "qualified parent must remain immutable")
    require(controls["source_revision"] == SOURCE and
            controls["projection_identity_sha256"] == PROJECTION and
            controls["stage_provision_blob"] == STAGE and
            controls["readiness_control_blob"] == CONTROL,
            "control manifest source/runner mismatch")
    control_entries = {e["path"]: e["git_blob_sha"] for e in controls["entries"]}
    require(set(control_entries) == {
        "rdte/gha/media/windows-enterprise-eval-x64.json",
        "rdte/gha/qualification.json",
        "rdte/gha/projection-policy.json",
        "rdte/gha/full-rdte.ps1",
    } and control_entries["rdte/gha/projection-policy.json"] == POLICY and
        control_entries["rdte/gha/full-rdte.ps1"] == CONTROL,
        "control manifest permitted object set mismatch")
    auth = policy.get("authorization", {})
    require(policy["state"] == "authorized" and
            auth.get("approved_revision") == SOURCE and
            auth.get("approved_manifest_sha256") == PROJECTION and
            auth.get("owner_dle") == APPROVAL and
            "one sealed A-only" in auth.get("scope", "") and
            auth.get("parent_policy_blob") == "225dcb07e9d6c322098f629592f86244c8d372d5",
            "owner source/projection authorization is not exact")
    rules = policy["rules"]
    require(all(rules[k] is True for k in (
        "tracked_files_only", "require_clean_worktree", "deny_local_runtime_state",
        "deny_git_metadata", "deny_workflows", "deny_binary_payloads",
        "deny_iso_vhd_vhdx", "deny_credentials_and_keys", "per_file_sha256_manifest")),
        "least-data projection policy weakened")
    require(rules["max_file_bytes"] == 524288 and
            rules["max_projected_bytes"] == 8388608 and
            rules["max_capsule_base64_chars"] == 60000,
            "bounded projection policy modified")
    batches = [json.loads(read_blob(sha)) for sha in BATCHES]
    entries = [e for b in batches for e in b["entries"]]
    original_batches = [json.loads(read_blob(sha)) for sha in original["source_batch_manifests"]]
    old = {e["path"]: e for b in original_batches for e in b["entries"]}
    require(len(entries) == len(old) == 82 and len({e["path"] for e in entries}) == 82,
            "unexpected projected file count or path duplication")
    def verify(e: dict) -> dict:
        path = e["path"]
        require(path in old, "unapproved new path in projected source")
        require(path.startswith(("guest/", "host/", "rdte/")) and
                not path.startswith((".git/", ".github/")) and
                ".." not in Path(path).parts and not path.startswith("/"),
                "projection path exceeds allowed namespace")
        if path == "guest/tools/stage-provision.ps1":
            require(e["git_blob_sha"] == STAGE and e["size"] == 47102 and
                    old[path]["git_blob_sha"] == ORIGINAL_STAGE and
                    old[path]["size"] == 45578, "only approved guest stage may change")
        else:
            require(e == old[path], "unapproved second projected source change")
        raw = read_blob(e["git_blob_sha"])
        require(len(raw) == e["size"] and len(raw) <= rules["max_file_bytes"],
                "per-file payload policy mismatch")
        return {"path": path, "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}
    require(all(b["source_revision"] == SOURCE for b in batches),
            "source batch authority not exact")
    with ThreadPoolExecutor(max_workers=8) as pool:
        projection_files = list(pool.map(verify, sorted(entries, key=lambda e: e["path"])))
    total = sum(e["bytes"] for e in projection_files)
    identity = hashlib.sha256(json.dumps({
        "source_revision": SOURCE, "projected_files": projection_files,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    require(total == master["projected_bytes"] and identity == PROJECTION,
            "full file-byte-projected SHA256 does not match authorized identity")
    control = read_blob(CONTROL).decode("utf-8-sig")
    stage = read_blob(STAGE).decode("utf-8-sig")
    for marker in (
        "OpenSSH.Server~~~~0.0.1.0",
        "Set-Service -Name sshd -StartupType Automatic",
        "Start-Service -Name sshd",
        "$criticalGsudo",
        "$criticalSshCapability",
        "Critical WinBot runtime readiness failed; refusing to write .provisioned",
        "Python package setup failed; continuing with independent critical tools",
        "OpenSSH critical setup failed",
    ):
        require(marker in stage, "approved stage security invariant absent")
    for marker in (
        "9.5/9-ready", "dependency_probe", "critical_failure_flags",
        "deterministic_nat_absent", "auth",
    ):
        require(marker in control or marker in wrapper, "A-only validated control marker absent")
    for pin in (MASTER, CONTROL_MANIFEST, SOURCE, PROJECTION, STAGE, ASSIGNMENT):
        require(pin in wrapper, "owner-approved dormant wrapper pin absent")
    require(wrapper.count("agent-dispatch-heavyweight-rdte") == 1 and
            "queue: max" in wrapper and "cancel-in-progress: false" in wrapper and
            "name: WinBot 9.5 Owner-Approved Product Fix A-Only" in wrapper and
            "'.github/workflows/winbot-95-owner-approved-a-only.yml'" in wrapper,
            "heavyweight admission wrapper selectors drift")
    for forbidden in (
        "New-WinBotWorkCell -CustomName $vmNameB", "Invoke-SeedFinalization",
        "canary_survived_rematerialization",
    ):
        require(forbidden not in control, "A-only control is not A-only")
    # Exercise PowerShell parsers separately on Windows in cheap CI, without
    # making the source-bearing scripts CI artifacts or running a VM.
    if os.environ.get("RUNNER_OS") == "Windows":
        root = Path(os.environ["RUNNER_TEMP"])
        (root / "winbot-a-only-exact-control.ps1").write_bytes(read_blob(CONTROL))
        (root / "winbot-approved-exact-stage.ps1").write_bytes(read_blob(STAGE))
    receipt = {
        "classification": "EXACT_ONE_RUN_OWNER_APPROVED_A_ONLY_GRAPH_PREFLIGHT",
        "authority": APPROVAL,
        "source_revision": SOURCE,
        "projection_sha256": PROJECTION,
        "stage_git_blob": STAGE,
        "master_manifest_blob": MASTER,
        "control_manifest_blob": CONTROL_MANIFEST,
        "projection_policy_blob": POLICY,
        "dormant_wrapper_blob": WRAPPER,
        "full_file_byte_projection_rehashed": True,
        "projection_file_count": len(projection_files),
        "projected_bytes": total,
        "credential_imported": False,
        "graph_mutation": False,
        "guest_launched": False,
        "one_run_owner_approval_verified": True,
        "seed_admitted": False,
        "terminal_admitted": False,
    }
    root = Path(os.environ["RUNNER_TEMP"])
    (root / "winbot-95-approved-graph-preflight.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))

if __name__ == "__main__":
    main()
