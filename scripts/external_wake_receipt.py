"""Public-safe external clock receiver. This NEVER dispatches an actor or reads private authority."""
from __future__ import annotations
import datetime
import json
import os
import re
import sys
from typing import Any

_TIMER = re.compile(r"[a-z][a-z0-9-]{5,63}\Z")
_REV = re.compile(r"[a-f0-9]{16,128}\Z")


def validate(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"timer_id", "revision", "generation", "scheduled_for", "occurrence_id"}:
        raise ValueError("INVALID_PAYLOAD_SHAPE")
    timer_id, revision = payload["timer_id"], payload["revision"]
    if not isinstance(timer_id, str) or not _TIMER.fullmatch(timer_id):
        raise ValueError("INVALID_OPAQUE_TIMER_ID")
    if not isinstance(revision, str) or not _REV.fullmatch(revision):
        raise ValueError("INVALID_OPAQUE_REVISION")
    generation = payload["generation"]
    if type(generation) is not int or not (1 <= generation <= 100000000):
        raise ValueError("INVALID_GENERATION")
    slot = payload["scheduled_for"]
    if not isinstance(slot, str) or len(slot) > 32 or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z", slot):
        raise ValueError("INVALID_UTC_SLOT")
    try:
        parsed = datetime.datetime.fromisoformat(slot.replace("Z", "+00:00"))
        if parsed.utcoffset() != datetime.timedelta(0):
            raise ValueError("not UTC")
    except ValueError as e:
        raise ValueError("INVALID_UTC_SLOT") from e
    expected = f"{timer_id}:{generation}:{slot}"
    if payload["occurrence_id"] != expected:
        raise ValueError("INVALID_OCCURRENCE_CORRELATION")
    return {"schema": "agent-dispatch/external-wake-receipt/v1", "timer_id":timer_id,
            "revision":revision, "generation":generation, "scheduled_for":slot,
            "occurrence_id":expected,
            "status":"WAKE_EVENT_RECEIVED_NOT_WORK_ACCEPTED"}


def main() -> int:
    try:
        payload=json.loads(os.environ["EXTERNAL_WAKE_PAYLOAD"])
        receipt=validate(payload)
    except (KeyError, ValueError, TypeError) as e:
        print(f"WAKE_REJECTED: {type(e).__name__}", file=sys.stderr)
        return 2
    receipt["received_at_utc"]=datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    receipt["github_run_id"]=os.environ.get("GITHUB_RUN_ID", "UNKNOWN")
    with open("external-wake-receipt.json", "w", encoding="utf-8") as f:
        json.dump(receipt,f,sort_keys=True,indent=2)
        f.write("\n")
    print("WAKE_EVENT_RECEIVED_NOT_WORK_ACCEPTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
