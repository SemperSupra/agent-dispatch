#!/usr/bin/env python3
"""Run one approved public-source agent assignment on the existing Jules plane."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import os
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

import jules


ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "jules-public-source-result"
APPROVED = {
    "foliorelay-keycloak-audit-001": {
        "workset_id": "foliorelay-keycloak-source-audit-20261024",
        "delegation_id": "keycloak-catalog-source-audit",
        "repository": "SemperSupra/truenas-app-foundry",
        "branch": "main",
        "task_path": "tasks/foliorelay-keycloak-catalog-audit.md",
        "task_sha256": "4b565342fec28c06589c1f913b78c884875d8f94aedba312281a541e7acef0ec",
    }
}
TERMINAL = {"COMPLETED", "FAILED", "AWAITING_PLAN_APPROVAL", "AWAITING_USER_FEEDBACK", "PAUSED"}
SESSION_ID = re.compile(r"^[A-Za-z0-9_-]+$")
RECIPIENT = re.compile(r"^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$")
MAX_SEALED_PLAINTEXT_BYTES = 1024 * 1024
SEALED_FINDING_PREFIX = "# Unreviewed Jules public-source finding\n\n"


def approved_assignment(workset_id: str, delegation_id: str, assignment_id: str) -> dict:
    entry = APPROVED.get(assignment_id)
    if entry is None or entry["workset_id"] != workset_id or entry["delegation_id"] != delegation_id:
        raise ValueError("assignment is not registered for this exact workset and delegation")
    return entry


def task_text(entry: dict) -> str:
    tasks_root = (ROOT / "tasks").resolve()
    path = ROOT / entry["task_path"]
    if path.is_symlink() or tasks_root not in path.resolve().parents or path.suffix != ".md":
        raise ValueError("approved task path is unsafe")
    value = path.read_text(encoding="utf-8")
    if not value.strip():
        raise ValueError("approved task is empty")
    if hashlib.sha256(value.encode()).hexdigest() != entry["task_sha256"]:
        raise ValueError("approved task bytes differ from the registered digest")
    return value


def pages(path: str, field: str, *, maximum: int = 20) -> list[dict]:
    values: list[dict] = []
    token = None
    for _ in range(maximum):
        query = {"pageSize": "100"}
        if token:
            query["pageToken"] = token
        data = jules.request("GET", path + "?" + urllib.parse.urlencode(query))
        items = data.get(field, [])
        if not isinstance(items, list):
            raise ValueError("provider list response is malformed")
        values.extend(item for item in items if isinstance(item, dict))
        token = data.get("nextPageToken")
        if not token:
            return values
    raise ValueError("provider pagination exceeded the bounded limit")


def reject_existing_session(title: str) -> None:
    matches = [s for s in pages("/sessions", "sessions") if s.get("title") == title]
    if matches:
        raise ValueError("assignment already has a native session; manual reconciliation is required")


def reject_prior_workflow_run(title: str) -> None:
    """Actions concurrency serializes the group; any earlier attempt consumes it."""
    token = os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT")
    if not token or repository != "SemperSupra/agent-dispatch" or not run_id or attempt != "1":
        raise ValueError("exact first-attempt GitHub workflow identity is required")
    found_current = False
    for page in range(1, 11):
        url = (f"https://api.github.com/repos/{repository}/actions/workflows/"
               f"jules-public-source-agent.yml/runs?event=workflow_dispatch&per_page=100&page={page}")
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
                                                  "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.load(response)
        runs = data.get("workflow_runs")
        if not isinstance(runs, list):
            raise ValueError("GitHub workflow run list is malformed")
        for run in runs:
            if str(run.get("id")) == run_id:
                found_current = True
            elif run.get("display_title") == title:
                raise ValueError("assignment has a prior workflow attempt; manual reconciliation is required")
        if len(runs) < 100:
            break
    else:
        raise ValueError("GitHub workflow history exceeded bounded inspection")
    if not found_current:
        raise ValueError("current workflow run was not visible in bounded inspection")


def native_id(session: dict) -> str:
    value = session.get("id") or str(session.get("name", "")).removeprefix("sessions/")
    if not isinstance(value, str) or not SESSION_ID.fullmatch(value):
        raise ValueError("provider session identity is missing or malformed")
    return value


def final_message(session_id: str) -> str:
    activities = pages("/sessions/" + session_id + "/activities", "activities")
    messages = [a for a in activities if isinstance(a.get("agentMessaged"), dict)
                and isinstance(a["agentMessaged"].get("agentMessage"), str)
                and a["agentMessaged"]["agentMessage"].strip()]
    if not messages:
        raise ValueError("completed native session has no agent message")
    messages.sort(key=lambda item: item.get("createTime", ""))
    return messages[-1]["agentMessaged"]["agentMessage"]


def structured_finding(result: str) -> bool:
    required = ("evidence", "conclusion", "falsification test", "remaining unknowns", "next gate")
    return all(re.search(r"(?im)^#{1,3}\s*" + re.escape(section) + r"\s*$", result) for section in required)


def write_receipt(**fields: object) -> None:
    RESULT_DIR.mkdir(exist_ok=True)
    (RESULT_DIR / "receipt.json").write_text(json.dumps(fields, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sealed_finding_plaintext(message: str) -> bytes:
    """Enforce the private pickup's 1 MiB limit on the FULL decrypted envelope."""
    plaintext = (SEALED_FINDING_PREFIX + message + "\n").encode("utf-8")
    if len(plaintext) > MAX_SEALED_PLAINTEXT_BYTES:
        raise ValueError("wrapped native finding exceeds sealed-result budget")
    return plaintext


def seal_finding(message: str, recipient: str) -> tuple[str, int]:
    if not RECIPIENT.fullmatch(recipient):
        raise ValueError("valid age X25519 recipient is required")
    payload = sealed_finding_plaintext(message)
    RESULT_DIR.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="public-agent-finding-") as temp_name:
        plaintext = Path(temp_name) / "finding.md"
        plaintext.write_bytes(payload)
        ciphertext = RESULT_DIR / "result.age"
        subprocess.run(["age", "--encrypt", "--recipient", recipient, "--output", str(ciphertext),
                        str(plaintext)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    blob = ciphertext.read_bytes()
    return hashlib.sha256(blob).hexdigest(), len(blob)


def execute(workset_id: str, delegation_id: str, assignment_id: str, recipient: str, *, poll_seconds: int = 15, max_polls: int = 180) -> dict:
    entry = approved_assignment(workset_id, delegation_id, assignment_id)
    if not RECIPIENT.fullmatch(recipient):
        raise ValueError("valid age X25519 recipient is required")
    prompt = task_text(entry)
    jules.preflight_public_source(argparse.Namespace(repository=entry["repository"], branch=entry["branch"]))
    source = jules.resolve_source(entry["repository"])
    title = f"sidecar:{workset_id}:{delegation_id}:{assignment_id}"
    reject_prior_workflow_run(title)
    reject_existing_session(title)
    session = jules.request("POST", "/sessions", {
            "prompt": prompt,
            "title": title,
            "sourceContext": {"source": source["name"], "githubRepoContext": {"startingBranch": entry["branch"]}},
            "requirePlanApproval": False,
            "automationMode": "AUTOMATION_MODE_UNSPECIFIED",
        })
    session_id = native_id(session)
    correlation = hashlib.sha256(session_id.encode()).hexdigest()[:16]
    common = {"assignment_id": assignment_id, "workset_id": workset_id, "delegation_id": delegation_id,
              "repository": entry["repository"], "branch": entry["branch"],
              "task_sha256": hashlib.sha256(prompt.encode()).hexdigest(), "native_correlation": correlation,
              "independent_acceptance": "not-run"}
    write_receipt(**common, status="dispatched", provider_state=session.get("state", "STATE_UNSPECIFIED"))
    for _ in range(max_polls):
        session = jules.request("GET", "/sessions/" + session_id)
        state = session.get("state")
        if state in TERMINAL:
            break
        time.sleep(poll_seconds)
    else:
        write_receipt(**common, status="unknown", provider_state="TIMEOUT")
        raise ValueError("provider session did not reach a terminal state; no retry is authorized")
    if state != "COMPLETED":
        write_receipt(**common, status="provider-stopped", provider_state=state)
        raise ValueError("provider session stopped without a completed audit")
    message = final_message(session_id)
    sealed_sha256, sealed_bytes = seal_finding(message, recipient)
    structured = structured_finding(message)
    status = "provider-completed" if structured else "provider-completed-unstructured"
    write_receipt(**common, status=status, provider_state=state,
                  sealed_sha256=sealed_sha256, sealed_bytes=sealed_bytes,
                  run_id=os.environ.get("GITHUB_RUN_ID"), run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"))
    if not structured:
        raise ValueError("completed native session has no structured final finding; sealed result requires private review")
    return {"status": "provider-completed", "assignment_id": assignment_id, "native_correlation": correlation,
            "independent_acceptance": "not-run"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workset-id", required=True)
    parser.add_argument("--delegation-id", required=True)
    parser.add_argument("--assignment-id", required=True)
    parser.add_argument("--age-recipient", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(execute(args.workset_id, args.delegation_id, args.assignment_id, args.age_recipient)))
    except (ValueError, SystemExit, OSError, subprocess.CalledProcessError) as exc:
        print("public-source agent stopped: " + str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
