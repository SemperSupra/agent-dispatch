#!/usr/bin/env python3
"""R69: read-only GitHub GraphQL schema qualification. NO mutation, no ref writes."""
import json
import os
import sys
import urllib.request
import urllib.error

QUERY = """query {
  ref: __type(name: "RefUpdate") {
    kind name inputFields { name type { kind name ofType { kind name } } }
  }
  input: __type(name: "UpdateRefsInput") {
    kind name inputFields { name type { kind name ofType { kind name } } }
  }
  mutation: __type(name: "Mutation") { fields { name } }
}"""

class Hold(Exception):
    pass

def validate(raw):
    if not isinstance(raw, dict) or raw.get("errors"):
        raise Hold("GRAPHQL_ERRORS_OR_MALFORMED")
    data = raw.get("data")
    if not isinstance(data, dict):
        raise Hold("SCHEMA_NOT_PRESENT")
    ref = data.get("ref")
    inp = data.get("input")
    mutation = data.get("mutation")
    if not all(isinstance(obj, dict) and obj.get("kind") == "INPUT_OBJECT"
               for obj in (ref, inp)):
        raise Hold("EXPECTED_INPUT_TYPES_MISSING")
    if not isinstance(mutation, dict):
        raise Hold("MUTATION_ROOT_NOT_VISIBLE")
    if ref.get("name") != "RefUpdate" or inp.get("name") != "UpdateRefsInput":
        raise Hold("INPUT_TYPE_NAME_MISMATCH")
    fields = ref.get("inputFields")
    if not isinstance(fields, list):
        raise Hold("REF_FIELDS_MISSING")
    names = [f.get("name") for f in fields if isinstance(f, dict)]
    if len(set(names)) != len(names) or not {"name", "beforeOid", "afterOid", "force"}.issubset(set(names)):
        raise Hold("REF_COMPARE_PRECONDITION_MISSING")
    types = {f["name"]: f.get("type") for f in fields if isinstance(f, dict)}
    if types.get("afterOid", {}).get("kind") != "NON_NULL" or \
       types.get("name", {}).get("kind") != "NON_NULL":
        raise Hold("REF_TARGET_FIELDS_NOT_REQUIRED")
    if types.get("beforeOid", {}).get("name") != "GitObjectID":
        raise Hold("BEFORE_OID_TYPE_UNEXPECTED")
    inputs = inp.get("inputFields")
    if not isinstance(inputs, list) or not {"repositoryId", "refUpdates"}.issubset(
        {v.get("name") for v in inputs if isinstance(v, dict)}
    ):
        raise Hold("ATOMIC_BATCH_FIELDS_MISSING")
    if "updateRefs" not in {
        f.get("name") for f in mutation.get("fields", []) if isinstance(f, dict)
    }:
        raise Hold("UPDATE_REFS_MUTATION_UNAVAILABLE")
    return {
        "r69_native_graphql_schema": "PASS",
        "provider": "GitHub GraphQL",
        "before_oid": "SCHEMA_PRESENT",
        "atomic_update_refs": "SCHEMA_PRESENT",
        "mutation_called": False,
        "credential": "READ_ONLY_EPHEMERAL",
        "real_cas_contention": "NOT_TESTED",
        "two_principals": "NOT_TESTED",
        "protected_no_force_reset": "NOT_TESTED",
        "production_authority": "HOLD"
    }

def native():
    if os.environ.get("GITHUB_ACTIONS") != "true" or \
       os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        raise Hold("NON_NATIVE_OR_WRONG_EVENT")
    if os.environ.get("GITHUB_REPOSITORY") != "SemperSupra/agent-dispatch":
        raise Hold("WRONG_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise Hold("READ_TOKEN_MISSING")
    data = json.dumps({"query":QUERY}).encode("utf-8")
    req = urllib.request.Request(
        "https://api.github.com/graphql",
        data=data, method="POST",
        headers={"Accept":"application/vnd.github+json",
                 "X-GitHub-Api-Version":"2022-11-28",
                 "Content-Type":"application/json",
                 "User-Agent":"r69-public-readonly-schema",
                 "Authorization":"Bearer "+token}
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            if response.status != 200:
                raise Hold("PROVIDER_NOT_OK")
            data = response.read(524289)
            if len(data) > 524288:
                raise Hold("PROVIDER_RESPONSE_TOO_LARGE")
    except urllib.error.HTTPError as e:
        raise Hold("PROVIDER_HTTP_"+str(e.code)) from None
    except (urllib.error.URLError, TimeoutError):
        raise Hold("PROVIDER_UNREACHABLE") from None
    return validate(json.loads(data))

if __name__ == "__main__":
    try:
        if sys.argv[1:] != ["--native"]: raise Hold("NATIVE_ONLY")
        print(json.dumps(native(), sort_keys=True))
    except (Hold, ValueError, TypeError, KeyError, json.JSONDecodeError) as e:
        print(json.dumps({"r69_native_graphql_schema":"HOLD",
                          "reason":str(e) if isinstance(e, Hold) else "MALFORMED_INPUT"}))
        sys.exit(1)
