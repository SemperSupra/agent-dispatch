#!/usr/bin/env python3
"""R69 public GHA native two-job artifact proof. Strict read-only consumer."""
import hashlib
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")

class Hold(Exception):
    pass

def unique(pairs):
    result = {}
    for k,v in pairs:
        if k in result: raise Hold("DUPLICATE_JSON_FIELD")
        result[k] = v
    return result

def validate_manifest(data, repo, run_id, attempt, head):
    if not isinstance(data, dict) or set(data) != {
        "class", "repository", "run_id", "run_attempt", "event", "source_head"
    }:
        raise Hold("BAD_MANIFEST_SCHEMA")
    if data != {"class":"synthetic-evidence-only", "repository":repo,
                "run_id":run_id, "run_attempt":attempt,
                "event":"pull_request", "source_head":head}:
        raise Hold("MANIFEST_IDENTITY_MISMATCH")
    return True

def validate_meta(items, repo_id, run_id, head, artifact_id, name, digest):
    if not isinstance(items, dict) or type(items.get("total_count")) is not int:
        raise Hold("BAD_ARTIFACT_LIST")
    # A partial or internally inconsistent artifact listing cannot establish
    # a unique receipt, even when the expected artifact is visible.
    artifacts = items.get("artifacts")
    if (items["total_count"] < 0 or items["total_count"] > 100 or
            not isinstance(artifacts, list) or
            len(artifacts) != items["total_count"]):
        raise Hold("PAGINATION_AMBIGUOUS")
    matches = [x for x in artifacts if isinstance(x, dict) and x.get("name")==name]
    if len(matches) != 1:
        raise Hold("DUPLICATE_OR_MISSING_ARTIFACT")
    artifact = matches[0]
    if type(artifact.get("id")) is not int or artifact["id"] != artifact_id or \
       artifact.get("expired") is not False or \
       artifact.get("digest") != "sha256:"+digest:
        raise Hold("ARTIFACT_ID_OR_DIGEST_MISMATCH")
    w = artifact.get("workflow_run")
    if not isinstance(w, dict) or type(w.get("id")) is not int or w["id"] != run_id or \
       type(w.get("repository_id")) is not int or w["repository_id"] != repo_id or \
       w.get("head_sha") != head:
        raise Hold("ARTIFACT_WORKFLOW_MISMATCH")
    return artifact

def validate_zip(payload, digest, repo, run_id, attempt, head):
    if not isinstance(payload, bytes) or len(payload) > 1048576:
        raise Hold("ARCHIVE_SIZE_INVALID")
    if hashlib.sha256(payload).hexdigest() != digest:
        raise Hold("ARCHIVE_DIGEST_MISMATCH")
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as z:
            entries = z.infolist()
            if len(entries)!=1 or entries[0].filename!="receipt.json" or \
               entries[0].file_size>4096 or entries[0].is_dir():
                raise Hold("ARCHIVE_LAYOUT_DENIED")
            content = z.read(entries[0])
            if len(content)>4096: raise Hold("MANIFEST_OVERSIZE")
        data=json.loads(content.decode("utf-8"), object_pairs_hook=unique)
    except (zipfile.BadZipFile, ValueError, UnicodeError, OSError):
        raise Hold("ARCHIVE_INVALID") from None
    return validate_manifest(data,repo,run_id,attempt,head)

def get_json(path, token):
    req=urllib.request.Request("https://api.github.com"+path,
       headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
                "X-GitHub-Api-Version":"2022-11-28","User-Agent":"r69-artifact-readback"})
    try:
        with urllib.request.urlopen(req,timeout=20) as response:
            if response.status!=200: raise Hold("PROVIDER_STATUS_UNEXPECTED")
            raw=response.read(524289)
            if len(raw)>524288: raise Hold("PROVIDER_RESPONSE_OVERSIZE")
    except urllib.error.HTTPError as e:
        raise Hold("PROVIDER_HTTP_"+str(e.code)) from None
    except (urllib.error.URLError,TimeoutError):
        raise Hold("PROVIDER_READ_UNAVAILABLE") from None
    return json.loads(raw,object_pairs_hook=unique)

class NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def validate_artifact_redirect(location):
    """Allow only ordinary HTTPS transport to the documented public artifact CDNs."""
    try:
        u = urllib.parse.urlsplit(location)
        host = (u.hostname or "").lower()
        port = u.port
    except (TypeError, ValueError):
        raise Hold("ARCHIVE_REDIRECT_ORIGIN_NOT_ADMITTED") from None
    if (u.scheme != "https" or not host or
            u.username is not None or u.password is not None or
            port not in (None, 443) or
            not (host.endswith(".blob.core.windows.net") or
                 host.endswith(".githubusercontent.com"))):
        raise Hold("ARCHIVE_REDIRECT_ORIGIN_NOT_ADMITTED")
    return location


def archive(artifact_id, token):
    # First request is *only* to api.github.com with the bearer token.
    req=urllib.request.Request(
        "https://api.github.com/repos/SemperSupra/agent-dispatch/actions/artifacts/"+str(artifact_id)+"/zip",
        headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
                 "User-Agent":"r69-artifact-readback"},method="GET")
    try:
        urllib.request.build_opener(NoFollow()).open(req,timeout=15)
        raise Hold("EXPECTED_302_NOT_RETURNED")
    except urllib.error.HTTPError as e:
        if e.code!=302: raise Hold("ARCHIVE_REDIRECT_HTTP_"+str(e.code)) from None
        location=e.headers.get("Location","")
    validate_artifact_redirect(location)
    # Completely new uncredentialed request. A second redirect must HOLD,
    # not follow an attacker-controlled URL or reuse the original token.
    request=urllib.request.Request(location,headers={"User-Agent":"r69-artifact-readback"})
    try:
        with urllib.request.build_opener(NoFollow()).open(request,timeout=25) as response:
            payload=response.read(1048577)
            if len(payload)>1048576: raise Hold("ARCHIVE_OVERSIZE")
    except (urllib.error.URLError, TimeoutError):
        raise Hold("ARCHIVE_CDN_UNAVAILABLE") from None
    return payload

def main():
    env=os.environ
    if env.get("GITHUB_ACTIONS")!="true" or env.get("GITHUB_EVENT_NAME")!="pull_request":
        raise Hold("NATIVE_PR_ONLY")
    repo=env.get("GITHUB_REPOSITORY")
    if repo!="SemperSupra/agent-dispatch": raise Hold("WRONG_REPOSITORY")
    token=env.get("GITHUB_TOKEN")
    if not token: raise Hold("READ_TOKEN_MISSING")
    run_id=int(env["GITHUB_RUN_ID"])
    attempt=int(env["GITHUB_RUN_ATTEMPT"])
    aid=int(env["EXPECTED_ARTIFACT_ID"])
    name=env.get("EXPECTED_ARTIFACT_NAME")
    digest=env.get("EXPECTED_ARTIFACT_DIGEST")
    head=env.get("SOURCE_HEAD_SHA","")
    if run_id<1 or attempt<1 or aid<1 or not DIGEST.fullmatch(digest or "") or \
       not SHA.fullmatch(head) or name!=f"r69-evidence-{run_id}-{attempt}":
        raise Hold("INVALID_EXPECTED_SOURCE")
    run=get_json(f"/repos/{repo}/actions/runs/{run_id}",token)
    if type(run.get("id")) is not int or run["id"]!=run_id or \
       type(run.get("run_attempt")) is not int or run["run_attempt"]!=attempt or \
       run.get("event")!="pull_request" or run.get("head_sha")!=head or \
       run.get("repository",{}).get("full_name")!=repo:
        raise Hold("NATIVE_RUN_IDENTITY_MISMATCH")
    repo_id=run["repository"]["id"]
    artifacts=get_json(f"/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100",token)
    validate_meta(artifacts,repo_id,run_id,head,aid,name,digest)
    validate_zip(archive(aid,token),digest,repo,run_id,attempt,head)
    return {"r69_native_artifact_custody":"PASS",
            "run_id":run_id,"run_attempt":attempt,"artifact_id":aid,
            "matched_native_run_and_artifact":True,"zip_sha256_verified":True,
            "contents_exactly_one_json_receipt":True,"public_repository_only":True,
            "external_effect_commit":"NOT_PROVEN",
            "lost_ack_id_discovery":"NOT_PROVEN",
            "production_authority":"HOLD"}

if __name__=="__main__":
    try:
        if sys.argv[1:]!=["--native"]: raise Hold("NATIVE_ONLY")
        print(json.dumps(main(),sort_keys=True))
    except (Hold,ValueError,TypeError,KeyError,json.JSONDecodeError) as e:
        print(json.dumps({"r69_native_artifact_custody":"HOLD",
                          "reason":str(e) if isinstance(e,Hold) else "MALFORMED_INPUT"}))
        sys.exit(1)
