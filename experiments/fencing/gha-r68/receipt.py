#!/usr/bin/env python3
"""Read-only native GitHub Actions run correlation probe (R68, public CI only).
No workflow dispatch, retry, provider mutation, or receipt acceptance by itself.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

class ReceiptError(Exception):
    pass

def verify(run, repository, run_id, attempt, event):
    if not isinstance(run, dict):
        raise ReceiptError("INVALID_RUN_OBJECT")
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        raise ReceiptError("INVALID_EXPECTED_RUN_ID")
    if type(run.get("id")) is not int or run["id"] != run_id:
        raise ReceiptError("RUN_ID_MISMATCH")
    if type(run.get("run_attempt")) is not int or run["run_attempt"] != attempt:
        raise ReceiptError("ATTEMPT_MISMATCH")
    actual_repo = run.get("repository")
    if not isinstance(actual_repo, dict) or actual_repo.get("full_name") != repository:
        raise ReceiptError("REPOSITORY_MISMATCH")
    if run.get("event") != event:
        raise ReceiptError("EVENT_MISMATCH")
    if type(run.get("workflow_id")) is not int or run["workflow_id"] <= 0:
        raise ReceiptError("WORKFLOW_ID_MISSING")
    head = run.get("head_sha")
    if not isinstance(head, str) or not SHA.fullmatch(head):
        raise ReceiptError("HEAD_SHA_INVALID")
    if run.get("status") not in ("queued", "in_progress", "completed", "waiting", "pending", "requested"):
        raise ReceiptError("STATUS_UNKNOWN")
    return {
        "source": "native_github_actions_run_get",
        "repository": repository,
        "run_id": run_id,
        "run_attempt": attempt,
        "workflow_id": run["workflow_id"],
        "api_head_sha": head,
        "event": event,
        "native_status": run["status"],
        "native_conclusion": run.get("conclusion"),
        "receipt_class": "CORRELATION_ONLY",
        "native_dispatch_mutation": "NOT_PERFORMED",
        "external_effect_commit": "NOT_PROVEN",
        "lost_ack_exactly_once": "NOT_PROVEN",
        "release_gate": "HOLD_REAL_SINK_FENCING",
    }

def native():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ReceiptError("NOT_NATIVE_GHA")
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        raise ReceiptError("NOT_ADMITTED_EVENT")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not REPO.fullmatch(repository) or repository != "SemperSupra/agent-dispatch":
        raise ReceiptError("REPOSITORY_NOT_PUBLIC_FIXTURE")
    api = os.environ.get("GITHUB_API_URL", "")
    if api != "https://api.github.com":
        raise ReceiptError("API_ORIGIN_NOT_ADMITTED")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise ReceiptError("NO_READ_ONLY_TOKEN")
    run_id = int(os.environ["GITHUB_RUN_ID"])
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    url = api + "/repos/" + repository + "/actions/runs/" + str(run_id)
    request = urllib.request.Request(url, method="GET", headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "r68-public-receipt-probe",
    })
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler()).open(request, timeout=15) as result:
            if result.status != 200:
                raise ReceiptError("UNEXPECTED_HTTP_STATUS")
            data = result.read(262145)
            if len(data) > 262144:
                raise ReceiptError("RESPONSE_TOO_LARGE")
    except urllib.error.HTTPError as exc:
        raise ReceiptError("NATIVE_API_HTTP_" + str(exc.code)) from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ReceiptError("NATIVE_API_UNAVAILABLE") from None
    run = json.loads(data)
    return verify(run, repository, run_id, attempt, "pull_request")

if __name__ == "__main__":
    try:
        if sys.argv[1:] != ["--native"]:
            raise ReceiptError("EXPECTED_NATIVE_ONLY")
        print(json.dumps(native(), sort_keys=True))
    except (ReceiptError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        code = str(exc) if isinstance(exc, ReceiptError) else "MALFORMED_NATIVE_INPUT"
        print(json.dumps({"r68_gha_native_receipt": "HOLD", "reason": code}))
        sys.exit(1)
