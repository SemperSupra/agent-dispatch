from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ALLOWED_STATE_KEYS = {"resource", "worker", "backlog", "generation"}
RESOURCE = "q08-controller-demo"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def validate_state(state: dict[str, Any]) -> None:
    if set(state) != ALLOWED_STATE_KEYS:
        raise ValueError("invalid_state_keys")
    if state["resource"] != RESOURCE:
        raise ValueError("wrong_resource")
    if state["worker"] not in {"dead", "alive"}:
        raise ValueError("invalid_worker")
    if not isinstance(state["backlog"], int) or isinstance(state["backlog"], bool) or state["backlog"] < 0:
        raise ValueError("invalid_backlog")
    if not isinstance(state["generation"], int) or isinstance(state["generation"], bool) or state["generation"] < 0:
        raise ValueError("invalid_generation")


def decide(state: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    validate_state(state)
    if state["worker"] == "dead":
        action = "restart_worker"
        next_state = {**state, "worker": "alive", "generation": state["generation"] + 1}
    elif state["backlog"] > 0:
        action = "drain_backlog"
        next_state = {**state, "backlog": 0, "generation": state["generation"] + 1}
    else:
        action = "no_action"
        next_state = {**state, "generation": state["generation"] + 1}
    validate_state(next_state)
    return action, next_state


def run(input_path: Path, output_path: Path, receipt_path: Path) -> None:
    state = json.loads(input_path.read_text(encoding="utf-8"))
    validate_state(state)
    action, next_state = decide(state)
    receipt = {
        "resource": RESOURCE,
        "input_digest": digest(state),
        "input_generation": state["generation"],
        "action": action,
        "output_digest": digest(next_state),
        "output_generation": next_state["generation"],
        "result": "PASS",
    }
    output_path.write_text(json.dumps(next_state, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))


def verify_chain(root: Path) -> None:
    expected_states = [
        {"resource": RESOURCE, "worker": "dead", "backlog": 2, "generation": 0},
        {"resource": RESOURCE, "worker": "alive", "backlog": 2, "generation": 1},
        {"resource": RESOURCE, "worker": "alive", "backlog": 0, "generation": 2},
        {"resource": RESOURCE, "worker": "alive", "backlog": 0, "generation": 3},
    ]
    expected_actions = ["restart_worker", "drain_backlog", "no_action"]

    states: list[dict[str, Any]] = []
    for i in range(4):
        path = root / f"state-{i}" / f"state-{i}.json"
        state = json.loads(path.read_text(encoding="utf-8"))
        validate_state(state)
        states.append(state)
    if states != expected_states:
        raise SystemExit(f"state_chain_mismatch: {states!r}")

    for i, expected_action in enumerate(expected_actions, start=1):
        receipt_path = root / f"state-{i}" / f"receipt-{i}.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        prior = states[i - 1]
        current = states[i]
        checks = {
            "action": receipt.get("action") == expected_action,
            "input_digest": receipt.get("input_digest") == digest(prior),
            "output_digest": receipt.get("output_digest") == digest(current),
            "input_generation": receipt.get("input_generation") == prior["generation"],
            "output_generation": receipt.get("output_generation") == current["generation"],
            "result": receipt.get("result") == "PASS",
        }
        if not all(checks.values()):
            raise SystemExit(f"receipt_{i}_mismatch: {checks!r}")

    # Deterministic replay: each frozen prior state must generate exactly the recorded action/state.
    for i in range(1, 4):
        action, replay = decide(states[i - 1])
        if action != expected_actions[i - 1] or replay != states[i]:
            raise SystemExit(f"replay_mismatch_step_{i}")

    final = {
        "result": "PASS",
        "fresh_decision_jobs": 3,
        "durable_state_medium": "github_actions_artifacts",
        "actions": expected_actions,
        "final_state": states[-1],
        "continuity_in_process_memory_required": False,
    }
    (root / "q08-final-receipt.json").write_text(json.dumps(final, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(final, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    step = sub.add_parser("step")
    step.add_argument("--input", required=True, type=Path)
    step.add_argument("--output", required=True, type=Path)
    step.add_argument("--receipt", required=True, type=Path)

    verify = sub.add_parser("verify-chain")
    verify.add_argument("--root", required=True, type=Path)

    args = parser.parse_args()
    if args.command == "step":
        run(args.input, args.output, args.receipt)
    else:
        verify_chain(args.root)


if __name__ == "__main__":
    main()
