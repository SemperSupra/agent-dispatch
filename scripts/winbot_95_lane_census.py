#!/usr/bin/env python3
"""Fail-closed, public-repository heavyweight-lane census for WinBot 9.5.

Runs only in cheap GHA. Does not dispatch, cancel, or mutate execution jobs.
Checks current workflow source at each running SHA for the shared group marker.
"""
from __future__ import annotations
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request

REPO = "SemperSupra/agent-dispatch"
GROUP = "agent-dispatch-heavyweight-rdte"
STATUSES = ("in_progress", "queued", "waiting", "requested", "pending")
LIMIT = 500

def get(path: str) -> dict:
    req = urllib.request.Request(
        "https://api.github.com/repos/" + REPO + path,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.load(response)

def set_status(state: str, desc: str) -> None:
    url = "https://api.github.com/repos/" + REPO + "/statuses/" + os.environ["GITHUB_SHA"]
    data = json.dumps({
        "state": state, "context": "winbot-95-heavyweight-census",
        "description": desc[:140],
        "target_url": "https://github.com/" + REPO + "/actions/runs/" + os.environ["GITHUB_RUN_ID"],
    }).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=60) as response:
        json.load(response)

def main() -> None:
    runs: dict[int, dict] = {}
    uncertain: list[int] = []
    for status in STATUSES:
        for page in range(1, 7):
            obj = get("/actions/runs?per_page=100&page=" + str(page) + "&status=" + status)
            rows = obj.get("workflow_runs", [])
            for row in rows:
                if not isinstance(row.get("id"), int):
                    raise ValueError("malformed workflow census entry")
                runs[row["id"]] = row
            if len(rows) < 100:
                break
        else:
            raise ValueError("workflow census pagination bound exceeded")
    if len(runs) > LIMIT:
        raise ValueError("too many live runs to classify")
    heavy: list[dict] = []
    cache: dict[tuple[str, str], bool] = {}
    for row in runs.values():
        sha = row.get("head_sha")
        path = (row.get("path") or "").split("@", 1)[0]
        if (not sha or not path.startswith(".github/workflows/")
                or row.get("head_repository", {}).get("full_name") != REPO):
            uncertain.append(row["id"])
            continue
        key = (path, sha)
        if key not in cache:
            encoded_path = urllib.parse.quote(path, safe="/")
            try:
                file = get("/contents/" + encoded_path + "?ref=" + sha)
                raw = base64.b64decode(file["content"]) if file.get("encoding") == "base64" else b""
                cache[key] = GROUP.encode() in raw
            except Exception:
                uncertain.append(row["id"])
                continue
        if cache[key]:
            heavy.append({"run_id": row["id"], "status": row["status"], "workflow": row.get("name")})
    state = "error" if uncertain else ("pending" if heavy else "success")
    info = {
        "classification": "PUBLIC_REPO_SHARED_HEAVYWEIGHT_CENSUS",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "shared_group": GROUP,
        "repository": REPO,
        "active_or_queued_runs_examined": len(runs),
        "heavyweight_runs": heavy,
        "uncertain_run_ids": uncertain,
        "admission_clear": state == "success",
        "non_atomic_snapshot": True,
        "no_launch": True,
    }
    output = Path(os.environ["RUNNER_TEMP"]) / "winbot-95-lane-census.json"
    output.write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")
    set_status(state, "heavy=" + str(len(heavy)) + "; unknown=" + str(len(uncertain)) +
               "; examined=" + str(len(runs)))
    print(json.dumps(info, sort_keys=True))
    if uncertain:
        raise SystemExit("lane census incomplete; fail closed")

if __name__ == "__main__":
    main()
