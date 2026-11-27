#!/usr/bin/env python3
"""Source-safe composition check for E3 embodiment control + E4 GHA adapter."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
PUBLIC_CONTROL = HERE.parent / "embodiment-control"
if PUBLIC_CONTROL.is_dir():
    sys.path.insert(0, str(PUBLIC_CONTROL))

from agent_dispatch_gha_actuator import SidecarAssignmentBinding, normalize_observation
from embodiment_control import ControlGrant, DurableAuthorityGrant, EmbodimentControl
from embodiment_semantics import BodyState

NOW = datetime(2026, 10, 2, 22, 0, tzinfo=timezone.utc)


def caller():
    return ControlGrant(
        principal_id="surface:synthetic",
        scopes=frozenset(
            {"embodiments:read", "embodiments:materialize", "embodiment-effects:write"}
        ),
        resources=frozenset({"workcell:*"}),
        expires_at=NOW + timedelta(hours=1),
    )


def authority():
    return DurableAuthorityGrant(
        authority_ref="github:public-safe-authority",
        actor_id="actor-a",
        actions=frozenset({"materialize"}),
        resources=frozenset({"workcell:*"}),
        expires_at=NOW + timedelta(hours=1),
    )


def binding():
    return SidecarAssignmentBinding(
        workset_ref="github-file:private/repo@branch:worksets/example.json",
        delegation_id="delegation-private",
        assignment_id="assignment-001",
    )


def observation(
    status,
    conclusion,
    *,
    strong_runtime_evidence=False,
    legacy_result_started_at=False,
):
    payload = {
        "assignment": {"assignment_id": "assignment-001"},
        "binding": {"target_kind": "github-actions"},
        "runs": [{"status": status, "conclusion": conclusion}],
    }
    if status == "completed" and legacy_result_started_at:
        payload["result"] = {
            "assignment_id": "assignment-001",
            "status": "completed",
            "started_at": "2026-10-02T20:00:00Z",
            "ended_at": "2026-10-02T20:00:30Z",
        }
    if strong_runtime_evidence:
        payload["runtime_evidence"] = {
            "assignment_id": "assignment-001",
            "started": True,
            "started_at": "2026-10-02T20:00:05Z",
            "source": "github-actions-job",
        }
    return payload


def create_dispatched(control, *, intent_id, body_id, effect_id):
    control.request_materialize(
        caller(),
        authority(),
        intent_id=intent_id,
        actor_id="actor-a",
        body_instance_id=body_id,
        resource="workcell:alpha",
        capability_class="gha-public-workcell",
        capabilities={"build"},
        now=NOW,
    )
    control.request_effect(
        caller(),
        effect_id=effect_id,
        intent_id=intent_id,
        kind="materialize",
        actuator_id="agent-dispatch:public-gha",
        now=NOW,
    )
    control.fabric.admit(body_id)
    control.fabric.dispatch(body_id)


def apply(control, effect_id, normalized):
    return control.reconcile_provider_observation(
        caller(),
        effect_id=effect_id,
        provider_runtime_observed=normalized["provider_runtime_observed"],
        provider_present_now=normalized["provider_present_now"],
        provider_exit_observed=normalized["provider_exit_observed"],
        now=NOW,
    )


def main():
    # A queued native run is not a body.
    queued_control = EmbodimentControl()
    create_dispatched(
        queued_control,
        intent_id="intent-queued",
        body_id="body-queued",
        effect_id="effect-queued",
    )
    queued = normalize_observation(observation("queued", None), binding())
    q = apply(queued_control, "effect-queued", queued)
    assert q["transitions"] == []
    assert q["instance"]["state"] == BodyState.MATERIALIZING.value
    assert q["instance"]["provider_present"] is False

    # Normal observed-running -> terminal lifecycle. Terminal status is enough
    # to prove exit because the body was independently observed running earlier.
    control = EmbodimentControl()
    create_dispatched(
        control,
        intent_id="intent-running",
        body_id="body-running",
        effect_id="effect-running",
    )
    running = normalize_observation(observation("in_progress", None), binding())
    r1 = apply(control, "effect-running", running)
    assert r1["transitions"] == ["provider_start_ack"]
    assert r1["instance"]["state"] == BodyState.MATERIALIZED.value
    assert r1["instance"]["provider_present"] is True

    terminal = normalize_observation(
        observation("completed", "success", legacy_result_started_at=True),
        binding(),
    )
    assert terminal["provider_runtime_observed"] is False
    assert terminal["provider_exit_observed"] is True
    r2 = apply(control, "effect-running", terminal)
    assert r2["transitions"] == ["provider_exit"]
    assert r2["instance"]["state"] == BodyState.DEMATERIALIZING.value
    assert r2["instance"]["provider_present"] is False

    # Current Sidecar terminal-first evidence does not prove that a body started.
    terminal_first = EmbodimentControl()
    create_dispatched(
        terminal_first,
        intent_id="intent-terminal",
        body_id="body-terminal",
        effect_id="effect-terminal",
    )
    unconfirmed = normalize_observation(
        observation("completed", "success", legacy_result_started_at=True),
        binding(),
    )
    blocked = apply(terminal_first, "effect-terminal", unconfirmed)
    assert blocked["transitions"] == ["block_unconfirmed_materialization"]
    assert blocked["instance"]["state"] == BodyState.BLOCKED.value
    assert blocked["instance"]["provider_present"] is False

    # A fresh immutable incarnation may be requested after the blocker.
    fresh = terminal_first.request_materialize(
        caller(),
        authority(),
        intent_id="intent-fresh",
        actor_id="actor-a",
        body_instance_id="body-fresh",
        resource="workcell:alpha",
        capability_class="gha-public-workcell",
        capabilities={"build"},
        now=NOW,
    )
    assert fresh["body_state"] == BodyState.REQUESTED.value

    # Future strong job/executor-start evidence permits terminal-first start+exit.
    proven = EmbodimentControl()
    create_dispatched(
        proven,
        intent_id="intent-proven",
        body_id="body-proven",
        effect_id="effect-proven",
    )
    strong = normalize_observation(
        observation("completed", "success", strong_runtime_evidence=True),
        binding(),
    )
    collapsed = apply(proven, "effect-proven", strong)
    assert collapsed["transitions"] == ["provider_start_ack", "provider_exit"]
    assert collapsed["instance"]["state"] == BodyState.DEMATERIALIZING.value

    # If stop wins before start evidence, terminal native execution settles absent.
    stopped = EmbodimentControl()
    create_dispatched(
        stopped,
        intent_id="intent-stopped",
        body_id="body-stopped",
        effect_id="effect-stopped",
    )
    stopped.fabric.request_stop("body-stopped")
    terminal_stopped = normalize_observation(
        observation("completed", "success", legacy_result_started_at=True),
        binding(),
    )
    settled = apply(stopped, "effect-stopped", terminal_stopped)
    assert settled["transitions"] == ["settle_provider_absent"]
    assert settled["instance"]["state"] == BodyState.DEMATERIALIZING.value
    assert settled["instance"]["provider_present"] is False

    print("GHA embodiment lifecycle composition: PASS")


if __name__ == "__main__":
    main()
