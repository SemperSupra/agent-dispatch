#!/usr/bin/env python3
"""Cheap, non-guest qualification of the WinBot 9.5 patch graph."""
from __future__ import annotations
import base64
import difflib
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


def get_exact_blob(sha: str) -> bytes:
    repo = os.environ.get("GITHUB_REPOSITORY", "SemperSupra/agent-dispatch")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"https://api.github.com/repos/{repo}/git/blobs/{sha}", headers=headers)
    with urllib.request.urlopen(req, timeout=60) as response:
        result = json.load(response)
    data = base64.b64decode(result["content"], validate=False)
    assert result["sha"] == sha and result["encoding"] == "base64"
    assert len(data) == result["size"] and control.git_blob_sha(data) == sha
    return data


def verify() -> None:
    src = get_exact_blob(control.PARENT_BLOB)
    workflow = get_exact_blob(receipt.PARENT_WORKFLOW_BLOB)
    next_control = control.patch_control(src)
    next_workflow = receipt.patch_receipt(workflow)
    assert next_control == control.patch_control(src)
    assert next_workflow == receipt.patch_receipt(workflow)
    for fn, bad in [(control.patch_control, src + b"\n"), (receipt.patch_receipt, workflow + b"\n")]:
        try:
            fn(bad)
            raise AssertionError("bad parent accepted")
        except ValueError:
            pass
    old = src.decode("utf-8-sig")
    new = next_control.decode("utf-8")
    for unchanged in (
        "Get-HostedNatPlacement", "network_provider = 'deterministic-netnat'",
        "New-NetNat -Name $ownedNatName", "deterministic_nat_absent",
        "Remove-RunWorkCell", "AuthorityRepairDiagnosticV2"
    ):
        assert unchanged in old and unchanged in new
    assert "([string]$provisionPhase -eq '9.5/9-ready')" in new
    assert "CriticalFailureMarkerState" in new and "CriticalFailureFlags" in new
    assert new.count("CriticalFailureMarkerState") >= 2
    assert "ConvertFrom-Json -AsHashtable" not in new  # guest PS 5.1
    changed_lines = [
        line[1:] for line in difflib.unified_diff(old.splitlines(), new.splitlines())
        if line.startswith("+") and not line.startswith("+++")
    ]
    additions = "\n".join(changed_lines).lower()
    for forbidden in (".api_token", ".vm-password", "rawlog", "write-host", "computername"):
        assert forbidden not in additions, forbidden
    wrapper = next_workflow.decode("utf-8")
    assert wrapper.count("critical_failure_marker_state = $criticalState") == 1
    assert wrapper.count("critical_failure_flags = $criticalFlags") == 1
    assert "critical_failure_flags = $r.work_cells.a.critical_failure_flags" not in wrapper
    assert "ConvertFrom-Json -AsHashtable -Depth 100" in wrapper
    for pinned in (
        "90d5d8a7244b781c28d438d9ba01155735c765b7",
        "d4120a901d7855a9e0d7bc5f805d5e4b0dad8380abf52322c90f9981094d8b45",
        "agent-dispatch-heavyweight-rdte", "cancel-in-progress: false"
    ):
        assert pinned in wrapper
    for name in control.FLAGS:
        assert new.count("'" + name + "'") >= 1
        assert "'" + name + "'" in wrapper
    out = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "winbot-95-static"
    out.mkdir(parents=True, exist_ok=True)
    (out / "candidate-control.ps1").write_bytes(next_control)
    (out / "candidate-workflow.yml").write_bytes(next_workflow)
    result = {
        "classification": "CHEAP_STATIC_CANDIDATE_ONLY",
        "parent_control_blob": control.PARENT_BLOB,
        "candidate_control_blob": control.git_blob_sha(next_control),
        "parent_workflow_blob": receipt.PARENT_WORKFLOW_BLOB,
        "candidate_workflow_blob": receipt.git_blob_sha(next_workflow),
        "product_source_revision": "90d5d8a7244b781c28d438d9ba01155735c765b7",
        "projection_identity": "d4120a901d7855a9e0d7bc5f805d5e4b0dad8380abf52322c90f9981094d8b45",
        "heavy_guest_launched": False,
    }
    (out / "qualification.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    verify()
