from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RESOURCE = "q09-lifecycle-demo"
PROJECTION_ID = "projection:q09:v1"
REQUEST_KEYS = {"request_id", "resource", "projection_id", "cycle", "state_digest", "action", "patch"}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass
class Controller:
    state: dict[str, Any]
    cycle: int = 0
    projection_id: str = PROJECTION_ID
    pending: dict[str, dict[str, Any]] = field(default_factory=dict)
    consumed: set[str] = field(default_factory=set)

    def snapshot(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "cycle": self.cycle,
            "projection_id": self.projection_id,
            "pending": self.pending,
            "consumed": sorted(self.consumed),
        }

    @classmethod
    def restore(cls, snapshot: dict[str, Any]) -> "Controller":
        return cls(
            state=dict(snapshot["state"]),
            cycle=int(snapshot["cycle"]),
            projection_id=str(snapshot["projection_id"]),
            pending={k: dict(v) for k, v in snapshot["pending"].items()},
            consumed=set(snapshot["consumed"]),
        )

    def expected_action(self) -> tuple[str, dict[str, Any]]:
        if self.state.get("worker") == "dead":
            return "restart_worker", {"worker": "alive"}
        if int(self.state.get("backlog", 0)) > 0:
            return "drain_backlog", {"backlog": 0}
        return "no_action", {}

    def evaluate(self, request: dict[str, Any]) -> dict[str, str]:
        if set(request) != REQUEST_KEYS:
            return {"status": "REJECT", "reason": "schema_keys"}
        if request["resource"] != RESOURCE:
            return {"status": "REJECT", "reason": "wrong_resource"}
        if request["projection_id"] != self.projection_id:
            return {"status": "REJECT", "reason": "stale_projection"}
        if request["state_digest"] != digest(self.state):
            return {"status": "REJECT", "reason": "tampered_digest"}
        request_id = str(request["request_id"])
        if request_id in self.consumed:
            return {"status": "NOOP", "reason": "replay_after_consumption"}
        if request_id in self.pending:
            return {"status": "UNKNOWN", "reason": "pending_claim_ambiguous"}
        if request["cycle"] < self.cycle:
            return {"status": "NOOP", "reason": "stale_cycle"}
        if request["cycle"] > self.cycle:
            return {"status": "REJECT", "reason": "out_of_order_cycle"}
        action, patch = self.expected_action()
        if request["action"] != action:
            return {"status": "REJECT", "reason": "wrong_action"}
        if request["patch"] != patch:
            return {"status": "REJECT", "reason": "wrong_patch"}
        return {"status": "ACCEPT", "reason": "ready_to_claim"}

    def claim(self, request: dict[str, Any]) -> dict[str, str]:
        decision = self.evaluate(request)
        if decision["status"] != "ACCEPT":
            return decision
        request_id = str(request["request_id"])
        claim_id = digest({"request": request, "cycle": self.cycle})
        self.pending[request_id] = {"claim_id": claim_id, "request": request}
        return {"status": "CLAIMED", "reason": claim_id}

    def complete(self, request_id: str, claim_id: str) -> dict[str, str]:
        record = self.pending.get(request_id)
        if not record or record["claim_id"] != claim_id:
            return {"status": "REJECT", "reason": "claim_mismatch"}
        request = record["request"]
        for key, value in request["patch"].items():
            self.state[key] = value
        del self.pending[request_id]
        self.consumed.add(request_id)
        self.cycle += 1
        return {"status": "RECEIPT", "reason": "applied"}


def base_controller() -> Controller:
    return Controller(state={"worker": "alive", "backlog": 1})


def valid_request(controller: Controller, request_id: str = "req-0") -> dict[str, Any]:
    action, patch = controller.expected_action()
    return {
        "request_id": request_id,
        "resource": RESOURCE,
        "projection_id": controller.projection_id,
        "cycle": controller.cycle,
        "state_digest": digest(controller.state),
        "action": action,
        "patch": patch,
    }


def require(label: str, actual: dict[str, str], status: str, reason: str) -> dict[str, Any]:
    ok = actual == {"status": status, "reason": reason}
    if not ok:
        raise AssertionError(f"{label}: expected {status}/{reason}, got {actual}")
    return {"case": label, "status": "PASS", "observed": actual}


def identity_suite() -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    controller = base_controller()
    req = valid_request(controller)

    mutated = dict(req)
    mutated["resource"] = "wrong"
    results.append(require("wrong_resource", controller.evaluate(mutated), "REJECT", "wrong_resource"))

    mutated = dict(req)
    mutated["projection_id"] = "projection:q09:stale"
    results.append(require("stale_projection", controller.evaluate(mutated), "REJECT", "stale_projection"))

    mutated = dict(req)
    mutated["state_digest"] = "sha256:" + "0" * 64
    results.append(require("tampered_digest", controller.evaluate(mutated), "REJECT", "tampered_digest"))

    mutated = dict(req)
    mutated["cycle"] = controller.cycle + 1
    results.append(require("out_of_order_cycle", controller.evaluate(mutated), "REJECT", "out_of_order_cycle"))

    claim = controller.claim(req)
    if claim["status"] != "CLAIMED":
        raise AssertionError(f"claim failed: {claim}")
    claim_id = claim["reason"]
    results.append(require("duplicate_while_claimed", controller.evaluate(req), "UNKNOWN", "pending_claim_ambiguous"))

    receipt = controller.complete(req["request_id"], claim_id)
    results.append(require("completion_receipt", receipt, "RECEIPT", "applied"))

    # Exact old request now carries the old state digest. Reconstruct a replay using the new state digest
    # while retaining its consumed request identity; consumed identity must still dominate and NOOP.
    replay = dict(req)
    replay["state_digest"] = digest(controller.state)
    replay["cycle"] = controller.cycle
    results.append(require("replay_after_consumption", controller.evaluate(replay), "NOOP", "replay_after_consumption"))

    return {"suite": "identity", "result": "PASS", "cases": results}


def interruption_suite() -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    # Receiver interruption before claim: evaluation is read-only. Restore the exact snapshot and retry safely.
    controller = base_controller()
    req = valid_request(controller, "req-preclaim")
    before = controller.snapshot()
    first = controller.evaluate(req)
    results.append(require("preclaim_first_evaluation", first, "ACCEPT", "ready_to_claim"))
    after_evaluation = controller.snapshot()
    if after_evaluation != before:
        raise AssertionError("receiver evaluation mutated durable controller state")
    restarted = Controller.restore(before)
    second = restarted.evaluate(req)
    results.append(require("preclaim_retry_after_receiver_interrupt", second, "ACCEPT", "ready_to_claim"))

    # Actuator crash after claim/before receipt: persisted claim makes execution ambiguous.
    controller = base_controller()
    req = valid_request(controller, "req-postclaim")
    claim = controller.claim(req)
    if claim["status"] != "CLAIMED":
        raise AssertionError(f"claim failed: {claim}")
    persisted = controller.snapshot()
    restarted = Controller.restore(persisted)
    ambiguous = restarted.evaluate(req)
    results.append(require("postclaim_retry_is_unknown", ambiguous, "UNKNOWN", "pending_claim_ambiguous"))
    second_claim = restarted.claim(req)
    results.append(require("postclaim_no_blind_reclaim", second_claim, "UNKNOWN", "pending_claim_ambiguous"))

    if len(restarted.pending) != 1 or restarted.cycle != 0 or restarted.consumed:
        raise AssertionError("ambiguous post-claim state was silently advanced")

    return {
        "suite": "interruptions",
        "result": "PASS",
        "cases": results,
        "invariant": "ambiguous_after_claim_preserves_UNKNOWN_and_forbids_blind_retry",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("suite", choices=("identity", "interruptions"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    result = identity_suite() if args.suite == "identity" else interruption_suite()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
