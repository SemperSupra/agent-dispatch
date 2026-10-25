#!/usr/bin/env python3
"""Run one approved public-source agent assignment on the existing Jules plane."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import urllib.parse
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
    }
}
TERMINAL = {"COMPLETED", "FAILED", "AWAITING_PLAN_APPROVAL", "AWAITING_USER_FEEDBACK", "PAUSED"}
SESSION_ID = re.compile(r"^[A-Za-z0-9_-]+$")


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


def matching_session(title: str, source_name: str, branch: str) -> dict | None:
    matches = [s for s in pages("/sessions", "sessions") if s.get("title") == title]
    if len(matches) > 1:
        raise ValueError("multiple native sessions match the one-use assignment")
    if not matches:
        return None
    context = matches[0].get("sourceContext", {})
    if context.get("source") != source_name or context.get("githubRepoContext", {}).get("startingBranch") != branch:
        raise ValueError("native session title matches but Source context differs")
    return matches[0]


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


def write_receipt(**fields: object) -> None:
    RESULT_DIR.mkdir(exist_ok=True)
    (RESULT_DIR / "receipt.json").write_text(json.dumps(fields, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def execute(workset_id: str, delegation_id: str, assignment_id: str, *, poll_seconds: int = 15, max_polls: int = 180) -> dict:
    entry = approved_assignment(workset_id, delegation_id, assignment_id)
    prompt = task_text(entry)
    jules.preflight_public_source(argparse.Namespace(repository=entry["repository"], branch=entry["branch"]))
    source = jules.resolve_source(entry["repository"])
    title = f"sidecar:{workset_id}:{delegation_id}:{assignment_id}"
    session = matching_session(title, source["name"], entry["branch"])
    if session is None:
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
    RESULT_DIR.mkdir(exist_ok=True)
    (RESULT_DIR / "finding.md").write_text("# Unreviewed Jules public-source finding\n\n" + message + "\n", encoding="utf-8")
    write_receipt(**common, status="provider-completed", provider_state=state,
                  finding_sha256=hashlib.sha256(message.encode()).hexdigest())
    return {"status": "provider-completed", "assignment_id": assignment_id, "native_correlation": correlation,
            "independent_acceptance": "not-run"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workset-id", required=True)
    parser.add_argument("--delegation-id", required=True)
    parser.add_argument("--assignment-id", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(execute(args.workset_id, args.delegation_id, args.assignment_id)))
    except (ValueError, SystemExit) as exc:
        print("public-source agent stopped: " + str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
