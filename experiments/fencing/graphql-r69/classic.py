#!/usr/bin/env python3
"""Read-only classic GitHub branch protection status; not a protected-witness proof."""
import json
import os
import sys
import urllib.error
import urllib.request

class Hold(Exception):
    pass

def classify(code, body):
    if code == 404:
        return {"r70_native_classic_branch_protection":"PASS_READONLY",
                "endpoint_observation":"NOT_FOUND",
                "classic_protection":"NOT_VISIBLE",
                "ruleset_comparison":"SEPARATELY_REQUIRED",
                "force_push_denial":"NOT_VERIFIED",
                "deletion_denial":"NOT_VERIFIED",
                "protected_external_high_water":"NOT_PROVEN",
                "production_authority":"HOLD"}
    if code != 200 or not isinstance(body,dict):
        raise Hold("INVALID_PROVIDER_CLASSIC_RESPONSE")
    def enabled(key):
        x=body.get(key)
        if x is None: return None
        if isinstance(x,dict) and type(x.get("enabled")) is bool:
            return x["enabled"]
        raise Hold("INVALID_BRANCH_PROTECTION_FIELD")
    return {"r70_native_classic_branch_protection":"PASS_READONLY",
            "endpoint_observation":"PROTECTION_CONFIG_VISIBLE",
            "classic_protection":"CONFIG_VISIBLE_NOT_TESTED",
            "enforce_admins_flag":enabled("enforce_admins"),
            "allow_force_pushes_flag":enabled("allow_force_pushes"),
            "allow_deletions_flag":enabled("allow_deletions"),
            "pull_request_review_settings_visible":isinstance(body.get("required_pull_request_reviews"),dict),
            "force_push_denial":"NOT_VERIFIED",
            "deletion_denial":"NOT_VERIFIED",
            "protected_external_high_water":"NOT_PROVEN",
            "production_authority":"HOLD"}

def native():
    e=os.environ
    if e.get("GITHUB_ACTIONS")!="true" or e.get("GITHUB_EVENT_NAME")!="pull_request":
        raise Hold("PUBLIC_PR_ONLY")
    if e.get("GITHUB_REPOSITORY")!="SemperSupra/agent-dispatch":
        raise Hold("PUBLIC_REPOSITORY_NOT_ADMITTED")
    token=e.get("GITHUB_TOKEN")
    if not token: raise Hold("READ_TOKEN_MISSING")
    req=urllib.request.Request(
        "https://api.github.com/repos/SemperSupra/agent-dispatch/branches/main/protection",
        headers={"Authorization":"Bearer "+token,
                 "Accept":"application/vnd.github+json",
                 "X-GitHub-Api-Version":"2022-11-28",
                 "User-Agent":"r70-public-classic-protection-census"})
    try:
        with urllib.request.urlopen(req,timeout=20) as response:
            if response.status != 200: raise Hold("HTTP_STATUS_UNEXPECTED")
            raw=response.read(65537)
            if len(raw)>65536: raise Hold("CLASSIC_RESPONSE_TOO_LARGE")
            body=json.loads(raw)
            return classify(200,body)
    except urllib.error.HTTPError as e:
        if e.code == 404: return classify(404,None)
        raise Hold("PROVIDER_HTTP_"+str(e.code)) from None
    except (urllib.error.URLError,TimeoutError):
        raise Hold("PROVIDER_UNAVAILABLE") from None

if __name__=="__main__":
    try:
        if sys.argv[1:]!=["--native"]:raise Hold("NATIVE_ONLY")
        print(json.dumps(native(),sort_keys=True))
    except (Hold,ValueError,TypeError) as e:
        print(json.dumps({"r70_native_classic_branch_protection":"HOLD",
                          "reason":str(e) if isinstance(e,Hold) else "MALFORMED_NATIVE_RESPONSE"}))
        sys.exit(1)
