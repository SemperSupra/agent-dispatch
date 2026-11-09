#!/usr/bin/env python3
"""A strict PR-event adapter for the existing reviewed public CPU request executor.

The PR only contributes ONE new public-synthetic request JSON; it cannot
change executable code, workflow, or credentials in this admission lane.
This is a non-privileged fallback, NOT Agent Dispatch workset authorization.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import gha_workload_request as typed

ROOT = Path(__file__).resolve().parents[1]
PR_FILE = re.compile(r"^requests/gha/pr-[a-z0-9][a-z0-9-]{2,57}\.json$")
SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_EVENT_BYTES = 131072


class Denied(ValueError):
    pass


def git(*args: str) -> str:
    try:
        cp = subprocess.run(["git", *args], cwd=ROOT, check=True,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=8)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Denied("PR_GIT_IDENTITY_UNAVAILABLE") from exc
    if len(cp.stdout) > 8192:
        raise Denied("PR_CHANGED_FILES_TOO_LARGE")
    try:
        return cp.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Denied("PR_CHANGED_FILES_INVALID") from exc


def strict_json(raw: bytes):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Denied("DUPLICATE_JSON_FIELD")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=no_duplicates)
    except (ValueError, UnicodeDecodeError) as exc:
        if isinstance(exc, Denied):
            raise
        raise Denied("PR_JSON_INVALID") from exc


def admit(*, environment: dict[str, str] | None = None, event: dict | None = None) -> dict | None:
    env = environment if environment is not None else os.environ
    if (env.get("GITHUB_EVENT_NAME") != "pull_request"
            or env.get("GITHUB_RUN_ATTEMPT") != "1"):
        raise Denied("PR_EVENT_OR_REPLAY_DENIED")
    if event is None:
        p = Path(env.get("GITHUB_EVENT_PATH", "/nonexistent"))
        try:
            if p.is_symlink() or p.stat().st_size > MAX_EVENT_BYTES:
                raise Denied("PR_EVENT_FILE_DENIED")
            event = strict_json(p.read_bytes())
        except OSError as exc:
            raise Denied("PR_EVENT_FILE_UNAVAILABLE") from exc
    if not isinstance(event, dict) or event.get("action") != "opened":
        raise Denied("PR_NOT_NEWLY_OPENED")
    pr = event.get("pull_request")
    if not isinstance(pr, dict):
        raise Denied("PR_EVENT_SHAPE_INVALID")
    owner = env.get("GITHUB_REPOSITORY", "")
    head = pr.get("head")
    base = pr.get("base")
    if (not owner or not isinstance(head, dict) or not isinstance(base, dict)
            or not isinstance(head.get("repo"), dict)
            or not isinstance(base.get("repo"), dict)
            or head["repo"].get("full_name") != owner
            or base["repo"].get("full_name") != owner):
        raise Denied("PR_CROSS_REPOSITORY_DENIED")
    head_sha, base_sha, merge_sha = head.get("sha"), base.get("sha"), env.get("GITHUB_SHA")
    if any(not isinstance(x, str) or not SHA.fullmatch(x) for x in (head_sha, base_sha, merge_sha)):
        raise Denied("PR_SHA_INVALID")
    if (git("rev-parse", "HEAD").strip() != merge_sha
            or git("rev-parse", "HEAD^1").strip() != base_sha
            or git("rev-parse", "HEAD^2").strip() != head_sha):
        raise Denied("PR_MERGE_HEAD_DRIFT")
    changed = git("diff", "--name-only", "-z", "HEAD^1", "HEAD").rstrip("\x00").split("\x00")
    added = git("diff", "--diff-filter=A", "--name-only", "-z", "HEAD^1", "HEAD").rstrip("\x00").split("\x00")
    if not any(p.startswith("requests/gha/pr-") for p in changed):
        return None  # Ordinary PRs are NOT PR-lane assignments.
    if len(changed) != 1 or changed != added or not PR_FILE.fullmatch(changed[0]):
        raise Denied("PR_NOT_EXACTLY_ONE_NEW_REQUEST")
    path = changed[0]
    file = ROOT / path
    if file.is_symlink() or not file.is_file() or file.stat().st_size > typed.MAX_BYTES:
        raise Denied("PR_REQUEST_FILE_DENIED")
    doc = strict_json(file.read_bytes())
    if not isinstance(doc, dict) or doc.get("assignment_id") != Path(path).stem:
        raise Denied("PR_ASSIGNMENT_FILE_ID_MISMATCH")
    plan = typed.plan(path)  # native schema, digest, fixed profile and cost validator
    if (plan["runner"] != "ubuntu-24.04" or plan["workload"] != "arithmetic-oracle"
            or plan["timeout_seconds"] > 60 or plan["data_class"] != "public-synthetic"
            or plan["max_attempts"] != 1 or plan["max_cost_usd"] != 0):
        raise Denied("PR_PROFILE_NOT_ADMITTED")
    return {"request_path": path, "request_sha256": plan["request_sha256"],
            "assignment_id": plan["assignment_id"], "source_sha": merge_sha,
            "pr_head_sha": head_sha, "pr_base_sha": base_sha,
            "runner": plan["runner"], "workload": plan["workload"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--action", choices=("plan", "run"), required=True)
    ap.add_argument("--github-output", default="")
    ap.add_argument("--digest", default="")
    ap.add_argument("--receipt", default="")
    args = ap.parse_args()
    try:
        plan = admit()
        if args.action == "plan":
            if plan is None:
                if not args.github_output:
                    raise Denied("GITHUB_OUTPUT_REQUIRED")
                with open(args.github_output, "a", encoding="utf-8") as fh:
                    fh.write("admitted=false\n")
                print("PUBLIC_PR_REQUEST_NOT_APPLICABLE")
                return 0
            if not args.github_output:
                raise Denied("GITHUB_OUTPUT_REQUIRED")
            with open(args.github_output, "a", encoding="utf-8") as fh:
                fh.write("admitted=true\n")
                for k in ("request_path", "request_sha256", "assignment_id", "pr_head_sha"):
                    fh.write(k + "=" + plan[k] + "\n")
            print("PUBLIC_PR_REQUEST_ADMITTED=true")
            return 0
        if plan is None or args.digest != plan["request_sha256"] or not args.receipt:
            raise Denied("PR_REQUEST_DIGEST_OR_RECEIPT_DENIED")
        result = typed.run(plan["request_path"], plan["request_sha256"])
        p = Path(args.receipt)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print("PUBLIC_PR_REQUEST_QUALIFIED=" + str(result["qualified"]).lower())
        return 0 if result["qualified"] is True else 2
    except (Denied, typed.Denied, OSError, ValueError) as exc:
        print("PUBLIC_PR_REQUEST_DENIED=" + (str(exc) if isinstance(exc, Denied) else "SOURCE_CONTRACT_DENIED"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
