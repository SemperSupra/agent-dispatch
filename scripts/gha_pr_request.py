#!/usr/bin/env python3
"""Public-synthetic PR manifest selection for Agent Dispatch #747.

Preflight only: no dispatch, network, credentials, or workload execution.
Native pull_request merge checkout is required; never trust event-body paths.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys

from gha_workload_request import Denied, plan

PR_PATH = re.compile(r"^requests/gha/pr-[a-z0-9][a-z0-9-]{2,60}\.json$")


def select_changed(entries, planner=plan):
    """Select exactly one newly added, isolated public-synthetic request."""
    if not isinstance(entries, list) or len(entries) > 256:
        raise Denied("PR_DIFF_UNBOUNDED")
    candidates = [path for status, path in entries
                  if PR_PATH.fullmatch(path)]
    if not candidates:
        return None
    if len(candidates) != 1 or len(entries) != 1 or entries[0][0] != "A":
        raise Denied("PR_REQUEST_NOT_ISOLATED_NEW_FILE")
    path = candidates[0]
    approved = planner(path)
    if approved["runner"] != "ubuntu-24.04" or approved["data_class"] != "public-synthetic":
        raise Denied("PR_REQUEST_PROFILE_DENIED")
    if approved["workload"] not in ("arithmetic-oracle", "sealed-contract-native"):
        raise Denied("PR_REQUEST_WORKLOAD_DENIED")
    if approved["max_attempts"] != 1 or approved["max_cost_usd"] != 0:
        raise Denied("PR_REQUEST_BUDGET_DENIED")
    return {"request_path": path, "request_sha256": approved["request_sha256"],
            "assignment_id": approved["assignment_id"], "runner": approved["runner"]}


def native_changed_files():
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        raise Denied("NATIVE_PR_EVENT_REQUIRED")
    expected = os.environ.get("GITHUB_SHA", "")
    try:
        cp = subprocess.run(["git", "rev-list", "--parents", "-n", "1", "HEAD"],
                            capture_output=True, timeout=10, check=True)
        refs = cp.stdout.decode("ascii").split()
        if len(refs) != 3 or refs[0] != expected:
            raise Denied("NATIVE_MERGE_COMMIT_REQUIRED")
        diff = subprocess.run(["git", "diff", "--no-renames", "--name-status", "-z",
                               refs[1], refs[0]], capture_output=True, timeout=10,
                              check=True)
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise Denied("PR_GIT_DIFF_UNAVAILABLE") from exc
    if len(diff.stdout) > 65536:
        raise Denied("PR_DIFF_UNBOUNDED")
    fields = diff.stdout.decode("utf-8", errors="strict").split("\x00")
    if fields[-1] == "":
        fields.pop()
    if len(fields) % 2:
        raise Denied("PR_DIFF_INVALID")
    return [(fields[i], fields[i + 1]) for i in range(0, len(fields), 2)]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--github-output")
    args = p.parse_args()
    try:
        selected = select_changed(native_changed_files())
        result = {"selected": selected is not None, **(selected or {})}
        if args.github_output:
            with open(args.github_output, "a", encoding="utf-8") as fh:
                fh.write("selected=" + str(result["selected"]).lower() + "\n")
                if selected:
                    for key, value in selected.items():
                        fh.write(key + "=" + value + "\n")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Denied, ValueError, OSError):
        print("PR_REQUEST_DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
