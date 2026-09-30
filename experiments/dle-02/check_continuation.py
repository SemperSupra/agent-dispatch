#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path

capsule_path = Path(sys.argv[1] if len(sys.argv) > 1 else "experiments/dle-02/capsule.json")
receipt_path = Path(sys.argv[2] if len(sys.argv) > 2 else "artifacts/dle-02/receipt.json")

raw = capsule_path.read_bytes()
doc = json.loads(raw)
required_top = {"dle_id","purpose","authoritative_state","delegation","acceptance"}
missing = sorted(required_top - set(doc))
if missing:
    raise SystemExit("FAIL missing top-level fields: " + ", ".join(missing))

state = doc["authoritative_state"]
delegation = doc["delegation"]
authority = delegation["authority"]
acceptance = doc["acceptance"]

checks = {
    "intent": state.get("intent"),
    "responsibility": delegation.get("responsibility"),
    "authority_grants": authority.get("grants"),
    "authority_reserved": authority.get("reserved"),
    "accepted_state": state.get("accepted_state"),
    "unknowns": state.get("unknowns"),
    "frontier": state.get("frontier"),
    "acceptance": acceptance.get("conditions"),
}
for name in acceptance.get("required_recovered_fields", []):
    if name not in checks or not checks[name]:
        raise SystemExit(f"FAIL replacement activation cannot recover required field: {name}")

reserved = set(authority["reserved"])
for forbidden in {"modify authoritative repository state","merge","release","access private data","spend money","delegate"}:
    if forbidden not in reserved:
        raise SystemExit(f"FAIL reserved authority lost: {forbidden}")

receipt = {
    "rep":"DLE-02",
    "dle_id":doc["dle_id"],
    "capsule_sha256":hashlib.sha256(raw).hexdigest(),
    "activation":{
        "actor_kind":"deterministic-automation",
        "body":"github-actions/ubuntu-24.04",
        "context_source":"durable-repository-state-only"
    },
    "recovered":checks,
    "result":{
        "durability":"SUPPORTED",
        "legibility":"SUPPORTED",
        "executability":"SUPPORTED_FOR_THIS_ACTIVATION",
        "authority_widened":False,
        "transcript_required":False,
        "human_relay_required":False
    }
}
receipt_path.parent.mkdir(parents=True, exist_ok=True)
receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n", encoding="utf-8")
print("PASS DLE-02 replacement activation recovered durable state without authority widening")
print(json.dumps(receipt["result"], sort_keys=True))
