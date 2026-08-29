#!/usr/bin/env python3
"""Hardened Jules REST API adapter for the agent-dispatch Phase 0 experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import NoReturn

BASE_URL = "https://jules.googleapis.com/v1alpha"
ROOT = Path(__file__).resolve().parents[1]
TASK_REGISTRY = ROOT / "config" / "tasks.json"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def request(method: str, path: str, body: dict | None = None) -> dict:
    key = os.environ.get("JULES_API_KEY")
    if not key:
        fail("Jules credential is not configured")
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={
            "x-goog-api-key": key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            payload = response.read()
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as exc:
        # Do not echo provider response bodies in a public Actions log; they can
        # contain private source names or other account metadata.
        fail(f"Jules API request failed with HTTP {exc.code}")
    except urllib.error.URLError:
        fail("Jules API request failed")


def load_targets() -> dict[str, dict]:
    raw = os.environ.get("JULES_TARGETS_JSON")
    if not raw:
        fail("Jules target policy is not configured")
    try:
        targets = json.loads(raw)
    except json.JSONDecodeError:
        fail("Jules target policy is invalid JSON")
    if not isinstance(targets, dict):
        fail("Jules target policy must be a JSON object")
    return targets


def resolve_target(target_id: str) -> tuple[str, str]:
    if not ID_RE.fullmatch(target_id):
        fail("Invalid target identifier")
    entry = load_targets().get(target_id)
    if not isinstance(entry, dict):
        fail("Target is not approved")
    repository = entry.get("repository")
    branch = entry.get("branch")
    if not isinstance(repository, str) or repository.count("/") != 1:
        fail("Approved target policy is malformed")
    if not isinstance(branch, str) or not branch or any(c in branch for c in "\r\n"):
        fail("Approved target policy is malformed")
    return repository, branch


def load_task(task_id: str) -> str:
    if not ID_RE.fullmatch(task_id):
        fail("Invalid task identifier")
    try:
        registry = json.loads(TASK_REGISTRY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("Task registry is unavailable")
    rel = registry.get(task_id) if isinstance(registry, dict) else None
    if not isinstance(rel, str):
        fail("Task is not approved")

    tasks_root = (ROOT / "tasks").resolve()
    candidate = ROOT / rel
    if candidate.is_symlink():
        fail("Approved task file may not be a symlink")
    path = candidate.resolve()
    if tasks_root not in path.parents or path.suffix.lower() != ".md":
        fail("Task registry entry violates path policy")
    if not path.is_file():
        fail("Approved task file is unavailable")
    return path.read_text(encoding="utf-8")


def list_sources() -> list[dict]:
    sources: list[dict] = []
    token = None
    while True:
        query = {"pageSize": "100"}
        if token:
            query["pageToken"] = token
        result = request("GET", "/sources?" + urllib.parse.urlencode(query))
        sources.extend(result.get("sources", []))
        token = result.get("nextPageToken")
        if not token:
            return sources


def resolve_source(repo_full_name: str) -> dict:
    owner, repo = repo_full_name.split("/", 1)
    matches = []
    for source in list_sources():
        gh = source.get("githubRepo", {})
        if gh.get("owner", "").lower() == owner.lower() and gh.get("repo", "").lower() == repo.lower():
            matches.append(source)
    if not matches:
        fail("Approved target is not available through Jules Sources")
    if len(matches) != 1:
        fail("Approved target resolves ambiguously through Jules Sources")
    return matches[0]


def dispatch(args: argparse.Namespace) -> None:
    repository, branch = resolve_target(args.target)
    prompt = load_task(args.task)
    source = resolve_source(repository)
    body = {
        "prompt": prompt,
        "title": f"agent-dispatch:{args.target}:{args.task}",
        "sourceContext": {
            "source": source["name"],
            "githubRepoContext": {"startingBranch": branch},
        },
        "requirePlanApproval": False,
        "automationMode": "AUTO_CREATE_PR",
    }
    result = request("POST", "/sessions", body)
    session_id = str(result.get("id") or "")
    correlation = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:12] if session_id else None
    # Public workflow output intentionally omits repository, branch, session ID,
    # provider URL, prompt, source identifier, activities, patches and PR URLs.
    print(json.dumps({
        "accepted": bool(session_id),
        "target": args.target,
        "task": args.task,
        "correlation": correlation,
    }, indent=2))


def status(args: argparse.Namespace) -> None:
    # Intended for trusted/local use only. There is deliberately no public
    # GitHub Actions status workflow because its output can disclose private
    # target and PR metadata.
    session_id = args.session.removeprefix("sessions/")
    result = request("GET", f"/sessions/{urllib.parse.quote(session_id, safe='')}")
    prs = []
    for output in result.get("outputs", []) or []:
        pr = output.get("pullRequest")
        if pr:
            prs.append({"url": pr.get("url"), "title": pr.get("title")})
    print(json.dumps({
        "id": result.get("id"),
        "state": result.get("state"),
        "url": result.get("url"),
        "pullRequests": prs,
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("dispatch", help="create an approved Jules session")
    p.add_argument("--target", required=True, help="approved opaque target ID")
    p.add_argument("--task", required=True, help="approved task ID")
    p.set_defaults(func=dispatch)

    p = sub.add_parser("status", help="retrieve a Jules session result (trusted/local use)")
    p.add_argument("session")
    p.set_defaults(func=status)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
