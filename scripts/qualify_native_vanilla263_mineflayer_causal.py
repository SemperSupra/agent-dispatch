#!/usr/bin/env python3
"""Protocol777 client-side causal action validator for disposable native TrueNAS.

Source and narrow runner-local worker seam only. A Mineflayer packet is NOT
an independent server world oracle, authenticated production client or COLLAGE
deployment authority. Actual guest admission and backend proof remain separate.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

try:
    from .qualify_native_vanilla263_loopback_player_overlay import runner_owned_loopback_forward
except ImportError:
    from qualify_native_vanilla263_loopback_player_overlay import runner_owned_loopback_forward

SCHEMA = "supracraft.native-vanilla263-mineflayer-causal/1"
STAGES = ("candidate", "rollback")
WORKER = Path(__file__).with_name("qualify_native_vanilla263_mineflayer_causal.js")


class Refused(RuntimeError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Refused(reason)


def validate(receipt: object, stage: str) -> dict:
    require(stage in STAGES and type(receipt) is dict and
            receipt.get("schema") == SCHEMA and
            receipt.get("classification") == "CLIENT_CAUSAL_VISIBILITY" and
            receipt.get("stage") == stage and
            receipt.get("requested_version") == "26.3" and
            receipt.get("negotiated_version") == "26.3" and
            type(receipt.get("protocol")) is int and receipt["protocol"] == 777 and
            type(receipt.get("negotiated_protocol")) is int and
            receipt["negotiated_protocol"] == 777 and
            receipt.get("offline_mode") is True and
            receipt.get("synthetic_bot") == "SupraCraftProbe" and
            receipt.get("operation") == "mineflayer.placeBlock" and
            receipt.get("connected_and_spawned") is True and
            receipt.get("fixture_via_bounded_bot_commands") is True and
            receipt.get("placed") is True and
            receipt.get("visible_effect_correct") is True and
            receipt.get("expected_datapack_present") is (stage == "candidate") and
            receipt.get("rcon_used") is False and
            receipt.get("backend_independent_oracle_qualified") is False and
            receipt.get("true_nas_physical_apply") is False and
            receipt.get("collage_mutation_authorized") is False and
            receipt.get("in_guest_server_world") is False and
            "error" not in receipt and "reason_code" not in receipt,
            "NATIVE_OFFLINE_PLAYER_CLIENT_CAUSAL_UNQUALIFIED")
    return {
        "schema": SCHEMA,
        "classification": "CLIENT_CAUSAL_VISIBILITY_ONLY",
        "stage": stage,
        "client_protocol777_connected_and_spawned": True,
        "offline_synthetic_player_caused_core_placement": True,
        "client_saw_expected_datapack_effect": stage == "candidate",
        "client_saw_expected_no_datapack_effect": stage == "rollback",
        "native_guest_backend_independent_oracle_qualified": False,
        "stock_mojang_client_qualified": False,
        "online_account_qualified": False,
        "collage_mutation_authorized": False,
        "physical_true_nas_apply": "HOLD",
    }


def run(*, stage: str, forward: str, state_dir: Path, node_path: Path) -> dict:
    require(stage in STAGES, "UNSUPPORTED_CLIENT_STAGE")
    host_port = runner_owned_loopback_forward(forward)
    require(isinstance(state_dir, Path) and state_dir.is_dir() and not state_dir.is_symlink(),
            "PLAYER_STATE_OWNER_MISSING")
    require(isinstance(node_path, Path) and node_path.is_dir() and
            not node_path.is_symlink(), "PINNED_CLIENT_DEPENDENCIES_MISSING")
    require(WORKER.is_file() and not WORKER.is_symlink(),
            "PINNED_CLIENT_WORKER_MISSING")
    output = state_dir / ("native-mineflayer-" + stage + ".json")
    require(not output.exists() and not output.is_symlink(),
            "PLAYER_RECEIPT_REPLAY_REFUSED")
    env = dict(os.environ, MC_PORT=str(host_port),
               SUPRACRAFT_NATIVE_STAGE=stage, BOT_RESULT_FILE=str(output),
               NODE_PATH=str(node_path))
    try:
        result = subprocess.run(
            ["node", str(WORKER)], cwd=str(WORKER.parent), env=env,
            capture_output=True, text=True, timeout=145, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("NATIVE_CLIENT_RUNTIME_UNAVAILABLE") from None
    # Never expose the worker's stdout/stderr, packets, kicks or provider errors.
    require(result.returncode == 0 and output.is_file() and
            not output.is_symlink() and 0 < output.stat().st_size < 8192,
            "NATIVE_CLIENT_RUNTIME_REFUSED")
    try:
        doc = json.loads(output.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError, OSError):
        raise Refused("NATIVE_CLIENT_RECEIPT_UNREADABLE") from None
    return validate(doc, stage)
