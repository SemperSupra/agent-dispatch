#!/usr/bin/env python3
"""Read-only native GitHub branch-rules census. Never tests or creates protected external witness."""
import json
import os
import sys
import urllib.error
import urllib.request

class Hold(Exception):
    pass

def assess(items):
    if not isinstance(items,list) or len(items)>100:
        raise Hold("NATIVE_RULE_LIST_INVALID_OR_TRUNCATED")
    seen=set()
    for obj in items:
        if not isinstance(obj,dict) or not isinstance(obj.get("type"),str):
            raise Hold("RULE_OBJECT_INVALID")
        t=obj["type"]
        if len(t)>80:
            raise Hold("RULE_TYPE_INVALID")
        seen.add(t)
    no_force="non_fast_forward" in seen
    no_delete="deletion" in seen
    pr_review="pull_request" in seen
    return {"r70_native_public_rules_census":"PASS",
            "public_branch":"main",
            "applicable_native_rule_count":len(items),
            "no_force_rule_visible":no_force,
            "deletion_rule_visible":no_delete,
            "pull_request_rule_visible":pr_review,
            "read_only_observation":True,
            "policy_evidence":"BOTH_RULE_TYPES_VISIBLE" if no_force and no_delete else
                               "HOLD_RULES_NOT_SUFFICIENT",
            "protected_external_high_water":"NOT_TESTED",
            "bypass_actors_and_admin_reset":"NOT_TESTED",
            "actual_non_fast_forward_denial":"NOT_TESTED",
            "separate_writer_credentials":"NOT_TESTED",
            "production_authority":"HOLD"}

def native():
    e=os.environ
    if e.get("GITHUB_ACTIONS")!="true" or e.get("GITHUB_EVENT_NAME")!="pull_request":
        raise Hold("NATIVE_PUBLIC_PR_ONLY")
    if e.get("GITHUB_REPOSITORY")!="SemperSupra/agent-dispatch":
        raise Hold("WRONG_REPOSITORY")
    token=e.get("GITHUB_TOKEN")
    if not token:
        raise Hold("READ_TOKEN_MISSING")
    req=urllib.request.Request(
        "https://api.github.com/repos/SemperSupra/agent-dispatch/rules/branches/main",
        headers={"Authorization":"Bearer "+token, "Accept":"application/vnd.github+json",
                 "X-GitHub-Api-Version":"2022-11-28",
                 "User-Agent":"r70-public-rules-census"})
    try:
        with urllib.request.urlopen(req,timeout=20) as response:
            if response.status!=200:
                raise Hold("NATIVE_RULES_STATUS_UNKNOWN")
            raw=response.read(131073)
            if len(raw)>131072:
                raise Hold("RULES_RESPONSE_OVERSIZE")
    except urllib.error.HTTPError as error:
        raise Hold("PROVIDER_HTTP_"+str(error.code)) from None
    except (urllib.error.URLError,TimeoutError):
        raise Hold("RULES_PROVIDER_UNAVAILABLE") from None
    return assess(json.loads(raw))

if __name__=="__main__":
    try:
        if sys.argv[1:]!=["--native"]:
            raise Hold("NATIVE_ONLY")
        print(json.dumps(native(),sort_keys=True))
    except (Hold,ValueError,TypeError) as error:
        print(json.dumps({"r70_native_public_rules_census":"HOLD",
                          "reason":str(error) if isinstance(error,Hold) else "MALFORMED_RESPONSE"}))
        sys.exit(1)
