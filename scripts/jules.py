#!/usr/bin/env python3
"""Minimal Jules REST API adapter for the agent-dispatch Phase 0 experiment."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = "https://jules.googleapis.com/v1alpha"


def request(method: str, path: str, body: dict | None = None) -> dict:
    key = os.environ.get("JULES_API_KEY")
    if not key:
        raise SystemExit("JULES_API_KEY is not set")
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
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Jules API HTTP {exc.code}: {detail}") from exc


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
    try:
        owner, repo = repo_full_name.split("/", 1)
    except ValueError as exc:
        raise SystemExit("repository must be owner/repo") from exc
    matches = []
    for source in list_sources():
        gh = source.get("githubRepo", {})
        if gh.get("owner", "").lower() == owner.lower() and gh.get("repo", "").lower() == repo.lower():
            matches.append(source)
    if not matches:
        raise SystemExit(
            f"{repo_full_name} is not visible through Jules Sources. "
            "Connect/authorize it in the Jules web app first."
        )
    if len(matches) != 1:
        raise SystemExit(f"ambiguous Jules source for {repo_full_name}")
    return matches[0]


def dispatch(args: argparse.Namespace) -> None:
    source = resolve_source(args.repository)
    body = {
        "prompt": args.prompt,
        "title": args.title or f"agent-dispatch: {args.repository}",
        "sourceContext": {
            "source": source["name"],
            "githubRepoContext": {"startingBranch": args.branch},
        },
        "requirePlanApproval": args.require_plan_approval,
    }
    if args.auto_create_pr:
        body["automationMode"] = "AUTO_CREATE_PR"
    result = request("POST", "/sessions", body)
    # Deliberately emit only control-plane metadata, not activities or patches.
    print(json.dumps({
        "id": result.get("id"),
        "name": result.get("name"),
        "state": result.get("state"),
        "url": result.get("url"),
        "target": args.repository,
        "branch": args.branch,
    }, indent=2))


def status(args: argparse.Namespace) -> None:
    session_id = args.session.removeprefix("sessions/")
    result = request("GET", f"/sessions/{urllib.parse.quote(session_id, safe='')}")
    prs = []
    for output in result.get("outputs", []) or []:
        pr = output.get("pullRequest")
        if pr:
            prs.append({
                "url": pr.get("url"),
                "title": pr.get("title"),
            })
    print(json.dumps({
        "id": result.get("id"),
        "name": result.get("name"),
        "state": result.get("state"),
        "url": result.get("url"),
        "pullRequests": prs,
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("dispatch", help="create a Jules session")
    p.add_argument("--repository", required=True, help="target owner/repo")
    p.add_argument("--branch", default="main")
    p.add_argument("--prompt", required=True)
    p.add_argument("--title")
    p.add_argument("--auto-create-pr", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--require-plan-approval", action=argparse.BooleanOptionalAction, default=False)
    p.set_defaults(func=dispatch)

    p = sub.add_parser("status", help="retrieve a Jules session result")
    p.add_argument("session")
    p.set_defaults(func=status)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
