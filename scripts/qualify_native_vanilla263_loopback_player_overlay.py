#!/usr/bin/env python3
"""Source-only derived offline player profile for one disposable native TrueNAS guest.

The signed Foundry control is immutable. This is a separately named,
allowlisted RDTE overlay for live synthetic Mineflayer action tests, not a
general rendering service and never an operational configuration.
"""
from __future__ import annotations
import copy
import hashlib
import json
import re
from typing import Any

# Native guest imports from the scripts directory as top-level modules;
# repo-root cheap tests may also import the same module as scripts.*.
try:
    from .admit_vanilla263_native_t6_control import (
        APP, CONTROL_SHA, OWNER, Refused, TARGET, verify,
    )
except ImportError:
    from admit_vanilla263_native_t6_control import (
        APP, CONTROL_SHA, OWNER, Refused, TARGET, verify,
    )

PROFILE = "minecraft-vanilla263-disposable-loopback-player/1"
BOT_NAME = "SupraCraftProbe"
WORLD = "/mnt/rdtepool/minecraft-vanilla-263-t6-world"
HOST_FORWARD = "tcp:127.0.0.1:25580-:25580"

def runner_owned_loopback_forward(value: object) -> int:
    """Accept QEMU's allocated ephemeral host port, never broad guest ingress.

    The existing native T6 harness independently allocates an unused host port,
    forwarded to the *guest* :25580 on QEMU user networking. This parser
    checks only source shape; the live harness must still verify the actual
    localhost listener belongs to the newly spawned disposable guest.
    """
    require(type(value) is str and len(value) < 64,
            "PLAYER_FORWARD_NOT_ISOLATED_LOOPBACK")
    match = re.fullmatch(r"tcp:127[.]0[.]0[.]1:([1-9][0-9]{3,4})-:25580", value)
    require(match is not None, "PLAYER_FORWARD_NOT_ISOLATED_LOOPBACK")
    port = int(match.group(1))
    require(1024 < port < 65536 and port not in {25565, 443, 80},
            "PLAYER_FORWARD_NOT_ISOLATED_LOOPBACK")
    return port

def require(cond: bool, code: str) -> None:
    if not cond:
        raise Refused(code)

def derive(control: dict, admission: dict) -> dict[str, Any]:
    """Prepare a synthetic-world profile only; no RPC, filesystem, or guest."""
    verify(control)
    require(type(admission) is dict and
            admission.get("schema") == PROFILE and
            admission.get("rdte_disposable") is True and
            admission.get("experiment") == "offline-mineflayer-player-causal" and
            admission.get("physical_truenas_apply") == "HOLD" and
            admission.get("operational_selection") is False and
            admission.get("external_ingress") is False and
            admission.get("qemu_network") == "user" and
            runner_owned_loopback_forward(admission.get("host_forward")) > 0 and
            admission.get("guest_target") == "TrueNAS-" + TARGET and
            admission.get("authorized_bot") == BOT_NAME and
            set(admission) == {
                "schema", "rdte_disposable", "experiment",
                "physical_truenas_apply", "operational_selection",
                "external_ingress", "qemu_network", "host_forward",
                "guest_target", "authorized_bot",
            }, "NOT_DISPOSABLE_LOOPBACK_PLAYER_ADMISSION")
    values = copy.deepcopy(control["runtime"]["values_template"])
    mc = values["minecraft"]
    require(mc["online_mode"] is True and
            mc["enable_rcon"] is False and mc["rcon_password"] == "" and
            mc["ops"] == [] and mc["whitelist"] == [],
            "EXACT_BASELINE_AUTH_POLICY_DRIFT")
    require(values["network"]["host_network"] is False and
            values["network"]["server_port"]["bind_mode"] == "published" and
            values["network"]["server_port"]["port_number"] == 25565,
            "EXACT_BASELINE_NETWORK_POLICY_DRIFT")
    require(values["storage"]["additional_storage"][0]["mount_path"] == "/data/world" and
            {x["name"]: x["value"] for x in mc["additional_envs"]} == OWNER,
            "EXACT_BASELINE_WORLD_OWNER_DRIFT")
    # Only changes to gameplay authentication are the locally isolated
    # synthetic client identity and granting that bot in-game commands.
    # No RCON or remote management listener introduced, and all six
    # COLLAGE owner labels remain exact.
    mc["online_mode"] = False
    mc["ops"] = [BOT_NAME]
    # Identical site bindings as accepted guest native app probe.
    values["storage"]["additional_storage"][0]["host_path_config"]["path"] = WORLD
    values["network"]["server_port"]["port_number"] = 25580
    mc.pop("seed", None) if mc.get("seed") is None else None
    require(mc["enable_rcon"] is False and mc["rcon_password"] == "" and
            mc["whitelist"] == [] and mc["ops"] == [BOT_NAME] and
            mc["online_mode"] is False and
            {x["name"]: x["value"] for x in mc["additional_envs"]} == OWNER,
            "DISPOSABLE_PLAYER_OVERLAY_ESCAPED_ALLOWLIST")
    digest=hashlib.sha256(json.dumps(values,sort_keys=True,
                    separators=(",",":")).encode()).hexdigest()
    return {
        "schema": PROFILE,
        "classification": "SOURCE_ONLY_DISPOSABLE_PLAYER_VARIANT",
        "immutable_base_control_sha256": CONTROL_SHA,
        "app": APP,
        "truenas_version": TARGET,
        "minecraft_version": "26.3",
        "protocol": 777,
        "network": "QEMU_USER_LOOPBACK_ONLY_SOURCE_REQUIREMENT",
        "host_forward": admission["host_forward"],
        "host_port": runner_owned_loopback_forward(admission["host_forward"]),
        "bot": BOT_NAME,
        "derived_runtime_values_sha256": digest,
        "values": values,
        "online_account_auth_qualified": False,
        "in_guest_bot_connected": False,
        "datapack_effect_in_native_guest_qualified": False,
        "collage_managed_deployment": False,
        "physical_truenas_apply": "HOLD",
        "operational_selection": False,
    }
