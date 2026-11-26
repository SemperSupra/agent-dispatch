"""Independent frozen answer/scope oracle for a bounded public CPU experiment.

Checks normalized, allowlisted outputs, not raw completions. A score is a
measurement of this fixed constrained-output probe, never release authority.
"""
import re

HEX64 = re.compile(r"^[0-9a-f]{64}$")
POLICIES = ("plain","evidence-first")
# Values and visible source IDs are independently fixed, not imported
# from the model runner. The runner has no expected answers.
ALL_DEV = "d1,d2,d3"
BEFORE_REVISION = "a1,a2,a3,a5"
REVISION = "a1,a2,a3,a5,b1"
ALL_HELD = "a1,a2,a3,a4,a5,b1,c1"
GOLD = {
    "D1":("d1","Monday",ALL_DEV),
    "D2":("d2","closed",ALL_DEV),
    "D3":("d3","42",ALL_DEV),
    "H1":("b1","150",REVISION),
    "H2":("a1","120",BEFORE_REVISION),
    "H3":("a3","denied",REVISION),
    "H4":("a4","approved",ALL_HELD),
    "H5":("NONE","UNKNOWN",ALL_HELD),
    "H6":("a2","Friday",ALL_HELD),
    "H7":("NONE","UNKNOWN",ALL_HELD),
}
VALUES = {"120","150","Friday","denied","approved","pending","Monday","closed",
          "42","Tuesday","open","43","UNKNOWN"}
ERRORS = {"OUTPUT_BOUND","JSON_INVALID","SCHEMA_INVALID","SCOPE_INVALID","PAIR_INVALID"}
PINS = {
    "model_sha256":"9ee36184e616dfc76df4f5dd66f908dbde6979524ae36e6cefb67f532f798cb8",
    "engine_commit":"b4c0e00a4fcc0287d0bb32fd7cb0d8b286af73ed",
    "engine_asset_sha256":"a9b243a3bc4ca172010e96c64062fc02afd1dc4f8b699716f813ae6845ada4c6",
}


def grade(result):
    if (any(result.get(k) != v for k,v in PINS.items()) or
            result.get("model_inference") is not True or
            result.get("automatic_promotion") is not False or
            result.get("transport") != "pinned-loopback-completion" or
            type(result.get("model_calls")) is not int or result["model_calls"] != 20 or
            type(result.get("corpus_sha256")) is not str or
            not HEX64.fullmatch(result["corpus_sha256"])):
        raise ValueError("MODEL_SCOPE_OR_PINS_INVALID")
    rows = result.get("rows")
    if type(rows) is not list or len(rows) != 20:
        raise ValueError("MODEL_CASE_COUNT_INVALID")
    seen = set()
    generated_tokens = 0
    scores = {p:{split:{"count":0,"exact":0,"invalid":0,"wrong_source":0}
                 for split in ("dev","heldout")} for p in POLICIES}
    for row in rows:
        if type(row) is not list or len(row) != 10 or any(type(x) is not str for x in row[:8]):
            raise ValueError("MODEL_CASE_FIELDS_INVALID")
        identifier,policy,scope,status,source,value,output_sha,prompt_sha,duration,tokens = row
        if identifier not in GOLD or policy not in POLICIES or (identifier,policy) in seen:
            raise ValueError("MODEL_CASE_IDENTITY_INVALID")
        seen.add((identifier,policy))
        expected_source,expected_value,expected_scope = GOLD[identifier]
        if (scope != expected_scope or not HEX64.fullmatch(output_sha) or
                not HEX64.fullmatch(prompt_sha) or type(duration) is not int or
                not 0 <= duration <= 30_000 or type(tokens) is not int or
                not 1 <= tokens <= 80):
            raise ValueError("MODEL_CASE_SCOPE_INVALID")
        if status == "OK":
            if (source not in (*scope.split(","),"NONE") or value not in VALUES or
                    (source == "NONE") != (value == "UNKNOWN")):
                raise ValueError("MODEL_NORMALIZED_RESPONSE_INVALID")
        elif status not in ERRORS or (source,value) != ("INVALID","INVALID"):
            raise ValueError("MODEL_PARSE_STATUS_INVALID")
        generated_tokens += tokens
        split = "dev" if identifier.startswith("D") else "heldout"
        s = scores[policy][split]
        s["count"] += 1
        s["invalid"] += status != "OK"
        s["exact"] += status == "OK" and (source,value) == (expected_source,expected_value)
        s["wrong_source"] += status == "OK" and source not in ("NONE",expected_source)
    if seen != {(i,p) for i in GOLD for p in POLICIES}:
        raise ValueError("MODEL_CASES_INCOMPLETE")
    selected = max(POLICIES,key=lambda p:scores[p]["dev"]["exact"])
    held = scores[selected]["heldout"]
    return {"scores":scores,"selected_on_dev":selected,
            "exploratory_quality_gate":held["exact"] >= 6 and
                held["invalid"] == 0 and held["wrong_source"] == 0,
            "model_calls":20,"generated_tokens":generated_tokens,"promotion":"HOLD"}
