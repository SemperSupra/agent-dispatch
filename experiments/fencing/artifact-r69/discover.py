#!/usr/bin/env python3
"""Read-only enumeration of native GHA run candidates without using the run ID in the list request.
This is not proof of dispatch idempotency, reliable run discovery or a full lost-ACK recovery.
"""
import json
import os
import re
import sys
import time
import urllib.parse
from verify import get_json, Hold

SHA = re.compile(r"^[0-9a-f]{40}$")

def classify(payload, repository, workflow_id, head_sha, native_run_id):
    if repository != "SemperSupra/agent-dispatch" or \
       type(workflow_id) is not int or workflow_id < 1 or \
       not isinstance(head_sha,str) or not SHA.fullmatch(head_sha) or \
       type(native_run_id) is not int or native_run_id < 1:
        raise Hold("INVALID_DISCOVERY_SCOPE")
    if not isinstance(payload, dict) or type(payload.get("total_count")) is not int or \
       payload["total_count"] < 0 or payload["total_count"] > 100:
        raise Hold("PAGINATION_OR_COUNT_AMBIGUOUS")
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list) or len(runs)>100 or len(runs)!=payload["total_count"]:
        raise Hold("RUN_LIST_INCONSISTENT")
    candidates=[]
    seen=set()
    for run in runs:
        if not isinstance(run,dict):
            raise Hold("INVALID_RUN")
        rid=run.get("id")
        if type(rid) is not int or rid < 1 or rid in seen:
            raise Hold("DUPLICATE_OR_INVALID_RUN_ID")
        seen.add(rid)
        if type(run.get("workflow_id")) is not int or run["workflow_id"] < 1:
            raise Hold("INVALID_WORKFLOW_ID")
        run_repository=run.get("repository")
        if not isinstance(run_repository,dict):
            raise Hold("INVALID_RUN_REPOSITORY")
        if run["workflow_id"] != workflow_id or \
           run.get("head_sha") != head_sha or \
           run.get("event") != "pull_request" or \
           run_repository.get("full_name") != repository:
            raise Hold("PROVIDER_RETURNED_CROSS_SCOPE_RUN")
        candidates.append(rid)
    if native_run_id not in candidates:
        raise Hold("CURRENT_RUN_ABSENT_FROM_CANDIDATES")
    return {"r70_native_candidate_enumeration":"PASS",
            "candidate_count":len(candidates),
            "classification":"ONE_CANDIDATE_AT_READBACK" if len(candidates)==1 else
                             "AMBIGUOUS_MULTIPLE_CANDIDATES_HOLD",
            "contains_current_run":True,
            "list_query_used_run_id":False,
            "cross_host_effect_commit":"NOT_PROVEN",
            "no_ack_run_discovery_complete":"NOT_PROVEN",
            "snapshot_eventual_consistency":"NOT_PROVEN",
            "exactly_once_dispatch":"NOT_PROVEN",
            "release_gate":"HOLD"}

def enumerate_candidates(read_json, sleep, repo, workflow_id, head, self_id):
    """At most five read-only snapshots; only missing visibility is retried.

    The known self ID is an oracle, never a query parameter. A single snapshot
    is not a stable uniqueness or lost-ACK recovery guarantee.
    """
    q=urllib.parse.urlencode({"event":"pull_request","head_sha":head,"per_page":"100"})
    path=f"/repos/{repo}/actions/workflows/{workflow_id}/runs?"+q
    for attempt in range(5):
        try:
            return classify(read_json(path),repo,workflow_id,head,self_id)
        except Hold as e:
            if str(e)!="CURRENT_RUN_ABSENT_FROM_CANDIDATES" or attempt==4:
                raise
            sleep(2)

def main():
    env=os.environ
    if env.get("GITHUB_ACTIONS")!="true" or env.get("GITHUB_EVENT_NAME")!="pull_request":
        raise Hold("PUBLIC_PR_RUN_ONLY")
    repo=env.get("GITHUB_REPOSITORY")
    token=env.get("GITHUB_TOKEN")
    head=env.get("SOURCE_HEAD_SHA")
    if repo!="SemperSupra/agent-dispatch" or not token or not SHA.fullmatch(head or ""):
        raise Hold("PUBLIC_SOURCE_NOT_ADMITTED")
    self_id=int(env["GITHUB_RUN_ID"])
    run=get_json(f"/repos/{repo}/actions/runs/{self_id}",token)
    if not isinstance(run,dict):
        raise Hold("SELF_NATIVE_RUN_MISMATCH")
    wf_id=run.get("workflow_id")
    if type(run.get("id")) is not int or run["id"]!=self_id or \
       type(wf_id) is not int or wf_id<=0 or \
       run.get("head_sha")!=head or run.get("event")!="pull_request":
        raise Hold("SELF_NATIVE_RUN_MISMATCH")
    # No run ID in the discovery request. Source head and native workflow ID are known.
    return enumerate_candidates(lambda path:get_json(path,token),time.sleep,
                                repo,wf_id,head,self_id)

if __name__=="__main__":
    try:
        if sys.argv[1:]!=["--native"]: raise Hold("EXPECTED_NATIVE_ONLY")
        print(json.dumps(main(),sort_keys=True))
    except (Hold,TypeError,ValueError,KeyError) as e:
        print(json.dumps({"r70_native_candidate_enumeration":"HOLD",
                          "reason":str(e) if isinstance(e,Hold) else "INPUT_INVALID"}))
        sys.exit(1)
