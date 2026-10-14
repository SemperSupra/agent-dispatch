#!/usr/bin/env python3
"""Native Minecraft Paper T6 on one disposable TrueNAS RDTE target.

This is a product oracle over the existing TrueNAS Apps management API, not
another app-controller or a physical TrueNAS deployment operator.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import time

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for
from truenas_middleware_foliorelay_t6_probe import middleware_http_bytes, multipart_upload

# Only the disposable scoped credential-issuance RPC gets a longer DDP
# response deadline. The TrueNAS nested CPU/PAM workload may exceed the
# ordinary 8-second socket deadline. A timeout is NOT proof the RPC failed or
# that the key was not created: never retry this non-idempotent operation.
SCOPED_KEY_CREATE_TIMEOUT_SECONDS = 60.0


def scoped_ddp_call(ws, request_id, method, params, *, transport=ddp_call):
    """One bounded scoped exception to ordinary DDP transport timeouts.

    No role changes, TLS downgrades, credential retries or raw error logging.
    Existing request IDs must be unique before this function is called.
    """
    if method != "api_key.create":
        return transport(ws, request_id, method, params)
    prior = ws.sock.gettimeout()
    try:
        ws.sock.settimeout(max(prior or 0.0, SCOPED_KEY_CREATE_TIMEOUT_SECONDS))
        return transport(ws, request_id, method, params)
    finally:
        ws.sock.settimeout(prior)


def sequenced_guest_ddp_call(ws, *, transport=scoped_ddp_call):
    """Unique DDP correlation IDs, including after indeterminate timeouts."""
    next_id = 0

    def call(method, params):
        nonlocal next_id
        next_id += 1
        return transport(ws, str(next_id), method, params)

    return call


SCHEMA = "semper-supra.minecraft-paper-truenas-t6-control/1"
EXPECTED_TARGET = "25.04.1"
EXPECTED_PROFILE = "800aca038ded29e6a91bfc4c1b1fe2d2199182e8"
EXPECTED_APPS_COMMIT = "bb96ef6fd8c2708765012a4a3ca3739370a4f92c"
EXPECTED_IMAGE_FRAGMENT = "ghcr.io/itzg/minecraft-server:2026.9.2-java21@sha256:edf50d431ddc6f73929368e82f4334a405796874f7b0ae11f1edcbb267d670aa"
CATALOG_PROFILES = {
    "1.15.29": {
        "apps_commit": EXPECTED_APPS_COMMIT,
        "image": EXPECTED_IMAGE_FRAGMENT,
    },
    "1.15.30": {
        "apps_commit": "559b9fe85212c800bc6770f152a65211df137a44",
        "image": "ghcr.io/itzg/minecraft-server:2026.10.0-java21@sha256:d4057e7019e9b19f25e039d4a204cc502e1a112d1a2305966a534f3d7079e644",
    },
}
EXPECTED_MIDDLEWARE = "74ab5a2d373be4097dece257d00e1086376333ba"
APP = "rdte-t6-minecraft-paper"
DATASET = "rdtepool/minecraft-paper-t6-world"
WORLD = "/mnt/rdtepool/minecraft-paper-t6-world"
PORT = 25580
MC_TYPE = "PAPER"
MC_VERSION = "1.21.11"
MC_PROTOCOL = 774
MC_IMPLEMENTATION = "paper"
MC_STATUS_NAME_CONTRACT = "paper_brand_exact"
VANILLA263 = False
WORLD_LEVEL = WORLD + "/level.dat"
SENTINEL_PATH = WORLD + "/.supracraft-paper-t6-sentinel"
REQUIRED_OWNER = {
    "SUPRACRAFT_COLLAGE_MANAGED": "true",
    "SUPRACRAFT_COLLAGE_SCHEMA": "1",
    "SUPRACRAFT_COLLAGE_MANAGER_ID": "manager-rdte",
    "SUPRACRAFT_COLLAGE_FLEET_ID": "rdte",
    "SUPRACRAFT_COLLAGE_SERVICE_ID": "11111111-1111-4111-8111-111111111111",
    "SUPRACRAFT_COLLAGE_WORLD_ID": "world-rdte-001",
}


def configure_exact_vanilla263() -> None:
    """Explicit per-process T6 product profile, not a Paper acceptance alias.

    The old Paper behavior remains the default and all targets are exact.
    This process handles exactly one guest/product. The new source consumer
    independently checks the signed merged Foundry control before mutation.
    """
    global SCHEMA, EXPECTED_TARGET, EXPECTED_PROFILE, EXPECTED_APPS_COMMIT
    global EXPECTED_IMAGE_FRAGMENT, EXPECTED_MIDDLEWARE, APP, DATASET
    global WORLD, PORT, WORLD_LEVEL, SENTINEL_PATH, REQUIRED_OWNER
    global MC_TYPE, MC_VERSION, MC_PROTOCOL, MC_IMPLEMENTATION
    global MC_STATUS_NAME_CONTRACT, VANILLA263, CATALOG_PROFILES
    from admit_vanilla263_native_t6_control import (
        APP as NATIVE_APP, APPS_REF, OCI, OWNER, TARGET,
        MIDDLEWARE, PROFILE_BLOB, WORLD as NATIVE_DATASET,
    )
    SCHEMA = "semper-supra.minecraft-vanilla-263-truenas-t6-control/1"
    EXPECTED_TARGET = TARGET
    EXPECTED_PROFILE = PROFILE_BLOB
    EXPECTED_APPS_COMMIT = APPS_REF
    EXPECTED_IMAGE_FRAGMENT = OCI
    EXPECTED_MIDDLEWARE = MIDDLEWARE
    APP = NATIVE_APP
    DATASET = NATIVE_DATASET
    WORLD = "/mnt/" + NATIVE_DATASET
    PORT = 25580
    WORLD_LEVEL = WORLD + "/level.dat"
    SENTINEL_PATH = WORLD + "/.supracraft-vanilla263-t6-sentinel"
    REQUIRED_OWNER = OWNER
    MC_TYPE, MC_VERSION, MC_PROTOCOL = "VANILLA", "26.3", 777
    MC_IMPLEMENTATION, MC_STATUS_NAME_CONTRACT = "vanilla", "vanilla_exact"
    VANILLA263 = True
    CATALOG_PROFILES = dict(CATALOG_PROFILES)
    CATALOG_PROFILES["1.15.30"] = {"apps_commit": APPS_REF, "image": OCI}


class MinecraftT6Error(RuntimeError):
    pass


def qualified_native_image(app: dict, image_fragment: str = EXPECTED_IMAGE_FRAGMENT) -> str | None:
    """Accept only the digest-pinned OCI reference, with optional tag normalization."""
    work = app.get("active_workloads") or {}
    candidates = list(work.get("images") or [])
    for item in work.get("container_details") or []:
        if isinstance(item, dict) and isinstance(item.get("image"), str):
            candidates.append(item["image"])
    repository_tag, digest = image_fragment.split("@sha256:", 1)
    repository = repository_tag.rsplit(":", 1)[0]
    valid = {image_fragment, repository + "@sha256:" + digest}
    return next((v for v in candidates if isinstance(v, str) and v in valid), None)


def safe_job_error(state: dict, password: str) -> dict:
    """Bounded public-safe error evidence. Never emit traceback or unredacted secrets."""
    raw = state.get("error")
    raw = raw if isinstance(raw, str) else ""
    if password:
        raw = raw.replace(password, "[redacted]")
    raw = re.sub(
        r"(?i)(password|passphrase|token|secret|authorization|credential|api[_-]?key)\s*[:=]\s*[^,;\s]+",
        r"\1=[redacted]", raw,
    )
    raw = re.sub(r"[A-Za-z0-9_+/=-]{48,}", "[opaque]", raw)
    raw = "".join(c if 32 <= ord(c) <= 126 else " " for c in raw)
    info = state.get("exc_info") or {}
    kind = info.get("type") if isinstance(info, dict) else None
    return {
        "job_state": state.get("state") if state.get("state") in ("FAILED", "ABORTED") else "UNKNOWN",
        "error_excerpt": raw[:480],
        "error_present": bool(raw),
        "exception_kind": str(kind)[:100] if isinstance(kind, str) else None,
        "truncated": len(raw) > 480,
    }


def canonical_sha256(doc: dict) -> str:
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_control(path: pathlib.Path, expected_commit: str, catalog_version: str = "1.15.29") -> dict:
    if VANILLA263:
        from admit_vanilla263_native_t6_control import verify
        if catalog_version != "1.15.30":
            raise MinecraftT6Error("vanilla263 exact native catalog version refused")
        try:
            control = json.loads((path / "control.json").read_text(encoding="utf-8"))
            verify(control, expected_producer=expected_commit)
            return control
        except (OSError, ValueError, TypeError) as exc:
            raise MinecraftT6Error("exact vanilla263 signed source control refused") from None
    if catalog_version not in CATALOG_PROFILES:
        raise MinecraftT6Error("unadmitted native catalog version profile")
    profile = CATALOG_PROFILES[catalog_version]
    control = json.loads((path / "control.json").read_text(encoding="utf-8"))
    if not isinstance(control, dict) or control.get("schema") != SCHEMA:
        raise MinecraftT6Error("Minecraft Foundry control schema drift")
    if not re.fullmatch("[0-9a-f]{40}", expected_commit):
        raise MinecraftT6Error("producer SHA is not immutable")
    if control.get("foundry_ref") != expected_commit:
        raise MinecraftT6Error("Foundry producer identity drift")
    signed = control.copy()
    claimed = signed.pop("control_sha256", None)
    if claimed != canonical_sha256(signed):
        raise MinecraftT6Error("Foundry control canonical digest drift")
    target = control.get("target") or {}
    if (target.get("truenas_version") != EXPECTED_TARGET or
        target.get("expected_system_version") != "TrueNAS-" + EXPECTED_TARGET or
        target.get("profile_git_blob_sha") != EXPECTED_PROFILE or
        target.get("middleware_commit") != EXPECTED_MIDDLEWARE):
        raise MinecraftT6Error("exact TrueNAS target/profile drift")
    source = control.get("source") or {}
    if (source.get("apps_commit") != profile["apps_commit"] or
        source.get("app") != "community/minecraft" or
        source.get("image_reference") != profile["image"] or
        source.get("library_version") != "2.3.4" or
        not re.fullmatch("[0-9a-f]{64}", str(source.get("source_compose_sha256", ""))) or
        not re.fullmatch("[0-9a-f]{64}", str(source.get("values_raw_sha256", "")))):
        raise MinecraftT6Error("pinned native Minecraft catalog source drift")
    runtime = control.get("runtime") or {}
    if (runtime.get("app_name") != APP or runtime.get("catalog_app") != "minecraft" or
        runtime.get("train") != "community" or runtime.get("catalog_version_candidate") != catalog_version or
        runtime.get("paper_version") != "1.21.11" or
        runtime.get("required_owned_world_dataset") != DATASET or
        runtime.get("status_oracle") != "minecraft-java-status-oracle/v1"):
        raise MinecraftT6Error("Minecraft product/source identity drift")
    values = runtime.get("values_template")
    if not isinstance(values, dict):
        raise MinecraftT6Error("missing native values template")
    minecraft = values.get("minecraft") or {}
    if (minecraft.get("type") != "PAPER" or minecraft.get("version") != "1.21.11" or
        minecraft.get("eula") is not True or minecraft.get("online_mode") is not True or
        minecraft.get("enable_rcon") is not False):
        raise MinecraftT6Error("Paper/EULA/network mode contract drift")
    owner = minecraft.get("additional_envs") or []
    if len(owner) != len(REQUIRED_OWNER) or {
        i.get("name"): i.get("value") for i in owner if isinstance(i, dict)
    } != REQUIRED_OWNER:
        raise MinecraftT6Error("exact owner metadata drift")
    storage = values.get("storage") or {}
    if (storage.get("data") or {}).get("type") != "ix_volume":
        raise MinecraftT6Error("base data must use independent App ixVolume")
    mounts = storage.get("additional_storage") or []
    if (len(mounts) != 1 or mounts[0].get("type") != "host_path" or
        mounts[0].get("mount_path") != "/data/world" or
        mounts[0].get("read_only") is not False):
        raise MinecraftT6Error("independent writable world mount contract drift")
    if ((mounts[0].get("host_path_config") or {}).get("path") != "/opt/tests/collage-world-only"):
        raise MinecraftT6Error("source host-path identity drift")
    network = values.get("network") or {}
    if (network.get("host_network") is not False or
        (network.get("server_port") or {}).get("port_number") != 25565 or
        (network.get("server_port") or {}).get("bind_mode") != "published"):
        raise MinecraftT6Error("source published ingress contract drift")
    if (not isinstance(control.get("evidence"), dict) or
        control["evidence"].get("source_render_pass") is not True or
        any(control["evidence"].get(flag) is not False for flag in (
            "live_catalog_version_verified", "live_minecraft_server_qualified",
            "world_retention_qualified", "physical_truenas_qualified")) or
        control.get("secrets_captured") is not False):
        raise MinecraftT6Error("source candidate incorrectly promotes runtime or secrets")
    return control


def runtime_values(control: dict) -> dict:
    """Lower exact site bindings and remove only an absent optional native seed.

    Foundry source-render accepts seed: null; middleware app.create on
    TrueNAS 25.04.1 rejects that field with [EINVAL] ...seed: null not allowed.
    Omission means catalog default, not a synthesized world seed.
    """
    values = copy.deepcopy(control["runtime"]["values_template"])
    values["storage"]["additional_storage"][0]["host_path_config"]["path"] = WORLD
    values["network"]["server_port"]["port_number"] = PORT
    if "seed" in values["minecraft"] and values["minecraft"]["seed"] is None:
        del values["minecraft"]["seed"]
    return values


def safe_status_oracle(script: pathlib.Path, port: int, out: pathlib.Path,
                       expected_version: str = "1.21.11", *,
                       implementation: str = "paper",
                       expected_protocol: int = 774) -> dict:
    if implementation not in {"paper", "vanilla"} or (
            implementation == "paper" and expected_protocol != 774) or (
            implementation == "vanilla" and expected_protocol != 777):
        raise MinecraftT6Error("exact product protocol/implementation profile refused")
    if not script.is_file() or script.name != "minecraft_java_status_oracle.py":
        raise MinecraftT6Error("exact Minecraft product oracle file absent")
    cmd = [sys.executable, str(script), "--port", str(port),
           "--expected-version", expected_version,
           "--implementation", implementation, "--expected-protocol", str(expected_protocol),
           "--timeout", "5", "--out", str(out)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
    if result.returncode != 0 or not out.is_file():
        raise MinecraftT6Error("Minecraft Java status oracle did not pass")
    verdict = json.loads(out.read_text(encoding="utf-8"))
    if (verdict.get("schema") != "minecraft-java-status-oracle/v1" or
        verdict.get("classification") != "SUPPORTED" or
        verdict.get("oracleSatisfied") is not True or
        verdict.get("java_version") != expected_version or
        verdict.get("server_implementation") != implementation or
        verdict.get("status_name_contract") != (
            "paper_brand_exact" if implementation == "paper" else "vanilla_exact") or
        verdict.get("server_protocol") != expected_protocol or
        verdict.get("status_packet_valid") is not True):
        raise MinecraftT6Error("Minecraft Java status receipt invalid")
    return verdict


def classify_java_status_receipt(path: pathlib.Path) -> str:
    """Map the trusted, bounded *local oracle result* to an allowlisted cause.

    Do not propagate raw Minecraft status payloads, MOTD, IPs, user names,
    private paths or arbitrary exception strings into public receipts.
    """
    try:
        if not path.is_file() or path.stat().st_size > 4096:
            return "missing_or_oversized_receipt"
        row = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "unreadable_receipt"
    if not isinstance(row, dict) or row.get("schema") != "minecraft-java-status-oracle/v1":
        return "invalid_receipt"
    if row.get("classification") == "SUPPORTED" and row.get("oracleSatisfied") is True:
        return "status_supported"
    if row.get("classification") != "ORACLE_FAILURE" or row.get("oracleSatisfied") is not False:
        return "invalid_receipt"
    reason = row.get("failure_reason")
    if reason == "transport failure":
        return "transport_failure"
    if reason == "server version mismatch":
        return "version_mismatch"
    if reason == "server protocol is absent or invalid":
        return "protocol_version_invalid"
    if reason == "server protocol mismatch":
        return "protocol_mismatch"
    if reason in {
        "truncated VarInt", "VarInt overflow", "VarInt too long",
        "packet exceeds bound", "outbound packet exceeds bound",
        "truncated packet", "status frame length invalid",
        "wrong status packet id", "status JSON length mismatch",
        "malformed status JSON", "status payload not an object",
        "players status absent", "players counters invalid",
        "player counter bounds invalid",
    }:
        return "invalid_or_truncated_status"
    return "other_oracle_failure"


def native_server_port_matches(actual: object, desired: object) -> bool:
    """Allow only the upstream 1.15.29 catalog's default empty host_ips addition."""
    if not isinstance(actual, dict) or not isinstance(desired, dict):
        return False
    if actual == desired:
        return True
    if "host_ips" in desired or set(actual) != set(desired) | {"host_ips"}:
        return False
    return actual.get("host_ips") == [] and all(
        actual.get(key) == value for key, value in desired.items()
    )


def port_readback_diagnostics(actual: object, desired: object) -> dict[str, bool]:
    """Only boolean comparison; no site network data or secrets in public receipts."""
    if not isinstance(actual, dict) or not isinstance(desired, dict):
        return {"port_number": False, "bind_mode": False,
                "host_ips_empty_or_absent": False, "only_expected_keys": False}
    return {
        "port_number": "port_number" in actual and actual.get("port_number") == desired.get("port_number"),
        "bind_mode": "bind_mode" in actual and actual.get("bind_mode") == desired.get("bind_mode"),
        "host_ips_empty_or_absent": "host_ips" not in actual or actual["host_ips"] == [],
        "only_expected_keys": set(actual) <= set(desired) | {"host_ips"},
    }


def owner_readback_vector(config: dict, wanted: dict) -> dict[str, bool]:
    """Only boolean equality witnesses. Never emit app.config values or owner envs."""
    minecraft = (config.get("minecraft") or {}) if isinstance(config, dict) else {}
    env = minecraft.get("additional_envs") or [] if isinstance(minecraft, dict) else []
    found_owner = {v.get("name"): v.get("value") for v in env if isinstance(v, dict)} if isinstance(env, list) else {}
    return {
        "minecraft_type": minecraft.get("type") == MC_TYPE if isinstance(minecraft, dict) else False,
        "minecraft_version": minecraft.get("version") == MC_VERSION if isinstance(minecraft, dict) else False,
        "owner_environment": found_owner == REQUIRED_OWNER,
        "additional_storage": (config.get("storage") or {}).get("additional_storage") == wanted["storage"]["additional_storage"] if isinstance(config, dict) and isinstance(config.get("storage") or {}, dict) else False,
        "server_port": native_server_port_matches((config.get("network") or {}).get("server_port"), wanted["network"]["server_port"]) if isinstance(config, dict) and isinstance(config.get("network") or {}, dict) else False,
    }


def owned_config(config: dict, wanted: dict) -> bool:
    return all(owner_readback_vector(config, wanted).values())


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", required=True, type=int)
    p.add_argument("--status-port", required=True, type=int)
    p.add_argument("--status-oracle", required=True, type=pathlib.Path)
    p.add_argument("--password-file", required=True, type=pathlib.Path)
    p.add_argument("--control-dir", required=True, type=pathlib.Path)
    p.add_argument("--foundry-commit", required=True)
    p.add_argument("--expected-system-version", required=True)
    p.add_argument("--out", required=True, type=pathlib.Path)
    p.add_argument("--collage-source-dir", type=pathlib.Path)
    p.add_argument("--collage-https-port", type=int)
    p.add_argument("--collage-source-ref")
    p.add_argument("--lantern-zip", type=pathlib.Path)
    p.add_argument("--lantern-manifest", type=pathlib.Path)
    p.add_argument("--native-world-rollback", action="store_true")
    p.add_argument("--native-offline-player", action="store_true")
    p.add_argument("--native-player-forward")
    p.add_argument("--native-player-node-path", type=pathlib.Path)
    p.add_argument("--native-catalog-profile", choices=sorted(CATALOG_PROFILES),
                   default="1.15.29")
    p.add_argument("--product-profile", choices=("legacy-paper", "vanilla263"),
                   default="legacy-paper")
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8)
    p.add_argument("--job-timeout", type=float, default=600)
    p.add_argument("--state-timeout", type=float, default=480)
    a = p.parse_args()
    if a.product_profile == "vanilla263":
        configure_exact_vanilla263()
    started = time.monotonic()
    payload = {
        "schema": "truenas-minecraft-vanilla263-t6/v1" if VANILLA263 else "truenas-minecraft-paper-t6/v1",
        "classification": "ORACLE_FAILURE", "oracleSatisfied": False,
        "product": "vanilla-26.3" if VANILLA263 else "paper-upstream-1.21.11", "target": EXPECTED_TARGET,
        "cleanup": {"attempted": False, "zero_residue": False},
        "secret_values_captured": False,
    }
    ws = None
    dataset_created = False
    app_created = False
    try:
        if (not VANILLA263 and a.native_catalog_profile == "1.15.30" and
                a.collage_source_dir is None):
            raise MinecraftT6Error("1.15.30 catalog profile is COLLAGE P2 opt-in only")
        if (a.lantern_zip is None) != (a.lantern_manifest is None):
            raise MinecraftT6Error("native Lantern source ZIP and manifest required as pair")
        if a.lantern_zip is not None and (not VANILLA263 or
                                           a.collage_source_dir is None):
            raise MinecraftT6Error("native Lantern staging needs exact vanilla263 and read-only COLLAGE source")
        if a.native_world_rollback and (not VANILLA263 or
            a.lantern_zip is None or a.collage_source_dir is None):
            raise MinecraftT6Error("G3 native rollback requires exact vanilla263 G2 and signed Lantern ZIP")
        if a.native_offline_player and (not a.native_world_rollback or
            not a.native_player_forward or a.native_player_node_path is None):
            raise MinecraftT6Error("G4 client requires exact G3 rollback and owned loopback")
        if not a.native_offline_player and (a.native_player_forward or
            a.native_player_node_path is not None):
            raise MinecraftT6Error("G4 client arguments without explicit admission")
        lantern_blob = None
        lantern_evidence = None
        if a.lantern_zip is not None:
            from qualify_vanilla263_native_lantern_stage import (
                verify_exact_candidate,
            )
            lantern_blob, lantern_evidence = verify_exact_candidate(
                a.lantern_zip, a.lantern_manifest)
        control = load_control(a.control_dir, a.foundry_commit,
                               catalog_version=a.native_catalog_profile)
        if a.expected_system_version != "TrueNAS-" + EXPECTED_TARGET:
            raise MinecraftT6Error("requested exact system version drift")
        desired = runtime_values(control)
        if a.native_offline_player:
            from qualify_native_vanilla263_loopback_player_overlay import (
                BOT_NAME, PROFILE, derive,
            )
            admission = {
                "schema": PROFILE, "rdte_disposable": True,
                "experiment": "offline-mineflayer-player-causal",
                "physical_truenas_apply": "HOLD",
                "operational_selection": False, "external_ingress": False,
                "qemu_network": "user", "host_forward": a.native_player_forward,
                "guest_target": "TrueNAS-" + EXPECTED_TARGET,
                "authorized_bot": BOT_NAME,
            }
            overlay = derive(control, admission)
            if overlay["host_port"] != a.status_port:
                raise MinecraftT6Error("G4 client and actual native QEMU port differ")
            desired = overlay["values"]
            payload["native_player_profile"] = {
                "schema": PROFILE, "classification": "DISPOSABLE_OVERLAY_BOUND",
                "operational_selection": False,
                "physical_truenas_apply": "HOLD",
                "client_online_account_qualified": False,
                "rcon_enabled": False,
            }
        sentinel_bytes = (("SUPRACRAFT-VANILLA263-T6:" if VANILLA263 else "SUPRACRAFT-PAPER-T6:") + control["control_sha256"] + "\n").encode("ascii")
        payload["foundry_ref"] = a.foundry_commit
        payload["control_sha256"] = control["control_sha256"]
        if not a.status_oracle.is_file():
            raise MinecraftT6Error("qualified status oracle source absent")
        password = a.password_file.read_text(encoding="utf-8").strip()
        ws = WebSocket(a.host, a.port, timeout=a.timeout, tls=a.tls)
        ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        if wait_for(ws, lambda m: m.get("msg") in {"connected", "failed"}).get("msg") != "connected":
            raise MinecraftT6Error("DDP connection failed")
        call = sequenced_guest_ddp_call(ws)
        def one(method, filters):
            rows = call(method, [filters])
            if not isinstance(rows, list) or len(rows) > 1:
                raise MinecraftT6Error(method + " returned ambiguous query")
            return rows[0] if rows else None
        def wait_job(job, label):
            if not isinstance(job, int):
                raise MinecraftT6Error(label + " did not return job ID")
            deadline = time.monotonic() + a.job_timeout
            while time.monotonic() < deadline:
                state = call("core.get_jobs", [[["id", "=", job]], {"get": True}])
                if isinstance(state, dict) and state.get("state") == "SUCCESS":
                    return
                if isinstance(state, dict) and state.get("state") in {"FAILED", "ABORTED"}:
                    payload["failed_job"] = {
                        "phase": label, "job_id": job, **safe_job_error(state, password)
                    }
                    raise MinecraftT6Error(label + " returned terminal failed job")
                time.sleep(2)
            raise MinecraftT6Error(label + " job timeout")
        def getapp():
            return one("app.query", [["id", "=", APP]])
        def wait_app():
            deadline = time.monotonic() + a.state_timeout
            while time.monotonic() < deadline:
                app = getapp()
                if isinstance(app, dict) and app.get("state") == "RUNNING":
                    matching_image = qualified_native_image(app,
                         image_fragment=CATALOG_PROFILES[a.native_catalog_profile]["image"])
                    if matching_image is None:
                        raise MinecraftT6Error("native Minecraft App runtime image differs from digest-pinned source")
                    payload["observed_image_reference"] = matching_image
                    payload["image_digest_qualification"] = "SOURCE_AND_GUEST_REF_MATCH"
                    cfg = call("app.config", [APP])
                    if a.native_offline_player:
                        # Never grant OP or disable online account auth in an
                        # unconfirmed App. Read exact isolated source overlay,
                        # no raw config/provider fields in public receipts.
                        cm = cfg.get("minecraft") if isinstance(cfg, dict) else None
                        if (not isinstance(cm, dict) or
                            cm.get("online_mode") is not False or
                            cm.get("ops") != ["SupraCraftProbe"] or
                            cm.get("enable_rcon") is not False or
                            cm.get("rcon_password") != "" or
                            cm.get("whitelist") != []):
                            raise MinecraftT6Error(
                                "disposable native player auth/OP profile mismatch")
                    match_vector = owner_readback_vector(cfg, desired)
                    if all(match_vector.values()):
                        return app
                    # Emit only field-level match booleans; no actual user values,
                    # storage paths, environment variables or credentials.
                    payload["owner_readback_match"] = match_vector
                    network = (cfg.get("network") or {}) if isinstance(cfg, dict) else {}
                    payload["server_port_readback_match"] = port_readback_diagnostics(
                        network.get("server_port") if isinstance(network, dict) else None,
                        desired["network"]["server_port"],
                    )
                    raise MinecraftT6Error("RUNNING App read-back did not match owner")
                if isinstance(app, dict) and app.get("state") in {"CRASHED", "ERROR"}:
                    raise MinecraftT6Error("Minecraft App reported terminal runtime failure")
                time.sleep(3)
            raise MinecraftT6Error("Minecraft App never reached verified RUNNING")
        def read_sentinel():
            row = call("core.download", ["filesystem.get", [SENTINEL_PATH], "paper-t6-sentinel.txt", True])
            if not isinstance(row, list) or len(row) != 2 or not isinstance(row[0], int):
                raise MinecraftT6Error("sentinel download response invalid")
            if not isinstance(row[1], str) or not row[1].startswith("/_download/") or ".." in row[1]:
                raise MinecraftT6Error("sentinel download path is outside middleware")
            wait_job(row[0], "world sentinel download")
            content = middleware_http_bytes(a.host, a.port, a.tls, row[1], timeout=a.timeout)
            if content != sentinel_bytes:
                raise MinecraftT6Error("world sentinel bytes changed or disappeared")
            return hashlib.sha256(content).hexdigest()
        def stat_level():
            try:
                item = call("filesystem.stat", [WORLD_LEVEL])
            except Exception:
                return None
            if isinstance(item, dict) and isinstance(item.get("size"), int) and item["size"] > 0:
                return {"size": item["size"], "type": item.get("type")}
            return None
        def wait_status(label):
            deadline = time.monotonic() + a.state_timeout
            last = None
            attempts = 0
            level_stat_attempted = False
            level_ever_observed = False
            status_ever_satisfied = False
            status_cause = "not_probed"
            while time.monotonic() < deadline:
                attempts += 1
                receipt = a.out.with_name(a.out.stem + "-status-" + label + ".json")
                try:
                    verdict = safe_status_oracle(a.status_oracle, a.status_port, receipt,
                                                 expected_version=MC_VERSION,
                                                 implementation=MC_IMPLEMENTATION,
                                                 expected_protocol=MC_PROTOCOL)
                    status_ever_satisfied = True
                    status_cause = "status_supported"
                    level_stat_attempted = True
                    level = stat_level()
                    level_ever_observed = level_ever_observed or (level is not None)
                    if level is not None:
                        payload.setdefault("readiness", {})[label] = {"protocol": verdict, "level": level}
                        return
                except (OSError, ValueError, MinecraftT6Error, subprocess.TimeoutExpired) as exc:
                    last = type(exc).__name__
                    # The oracle writes a bounded local failure receipt even on a
                    # failed connection. Only copy an allowlisted category.
                    status_cause = classify_java_status_receipt(receipt)
                # Sample world independently of protocol success; a server may
                # create level.dat while no TCP status listener is accessible.
                # A negative stat is not a proof that the world is absent.
                if attempts == 1 or attempts % 8 == 0:
                    level_stat_attempted = True
                    level_ever_observed = level_ever_observed or (stat_level() is not None)
                time.sleep(4)
            snapshot = {
                "attempts": attempts,
                "status_oracle_ever_satisfied": status_ever_satisfied,
                "level_stat_attempted": level_stat_attempted,
                "level_dat_ever_observed": level_ever_observed,
                "last_status_cause": status_cause,
                "last_exception_kind": last if last in {
                    "OSError", "ValueError", "MinecraftT6Error", "TimeoutExpired"
                } else "none_or_other",
            }
            # Middleware reachability and App lifecycle state are separate
            # evidence, never substitutes for the Java/status+level.dat oracle.
            try:
                app = getapp()
                state = app.get("state") if isinstance(app, dict) else None
                snapshot["middleware_app_query_succeeded"] = True
                snapshot["app_state"] = state if state in {
                    "RUNNING", "DEPLOYING", "CRASHED", "STOPPED", "UNKNOWN"
                } else "other_or_absent"
            except Exception:
                snapshot["middleware_app_query_succeeded"] = False
                snapshot["app_state"] = "query_failed"
            payload.setdefault("readiness_diagnostics", {})[label] = snapshot
            raise MinecraftT6Error("Minecraft runtime status+world did not converge")
        def delete_app(label):
            nonlocal app_created
            wait_job(call("app.delete", [APP, {
                "remove_images": False,
                "remove_ix_volumes": True,
                "force_remove_custom_app": False,
            }]), label)
            app_created = False
            if getapp() is not None:
                raise MinecraftT6Error("App survived " + label)

        auth = call("auth.login_ex", [{"mechanism": "PASSWORD_PLAIN",
                  "username": "truenas_admin", "password": password}])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise MinecraftT6Error("middleware authentication failed")
        if call("system.version", []) != a.expected_system_version:
            raise MinecraftT6Error("installed TrueNAS exact identity mismatch")
        methods = call("core.get_methods", [])
        required = {"app.query", "app.config", "app.create", "app.delete", "app.start",
                    "app.stop", "app.redeploy", "pool.dataset.query", "pool.dataset.create",
                    "pool.dataset.delete", "filesystem.stat", "filesystem.setperm"}
        if a.native_world_rollback:
            required.update({"zfs.snapshot.create", "zfs.snapshot.query",
                             "zfs.snapshot.rollback", "filesystem.listdir"})
        if not isinstance(methods, dict) or not required.issubset(methods):
            raise MinecraftT6Error("required native TrueNAS methods missing")
        if getapp() is not None or one("pool.dataset.query", [["id", "=", DATASET]]) is not None:
            raise MinecraftT6Error("refusing to adopt pre-existing app or ZFS world dataset")
        catalog = call("catalog.get_app_details", ["minecraft", {"train": "community"}])
        versions = (catalog or {}).get("versions") or {}
        expected_catalog = control["runtime"]["catalog_version_candidate"]
        # Record bounded public-safe discovered revision identities, not catalog secrets.
        payload["catalog_discovery"] = {
            "catalog_app": (catalog or {}).get("name"),
            "latest_version": (catalog or {}).get("latest_version"),
            "healthy": (catalog or {}).get("healthy"),
            "visible_versions": sorted(str(v) for v in versions)[:32] if isinstance(versions, dict) else [],
            "requested_version": expected_catalog,
            "upstream_apps_commit": CATALOG_PROFILES[a.native_catalog_profile]["apps_commit"],
        }
        if not isinstance(versions, dict) or expected_catalog not in versions:
            raise MinecraftT6Error("exact native Minecraft catalog version unavailable")
        payload["catalog_version_verified"] = True

        dataset = call("pool.dataset.create", [{"name": DATASET, "type": "FILESYSTEM",
                      "share_type": "GENERIC", "comments": "disposable Minecraft Paper T6"}])
        if not isinstance(dataset, dict) or dataset.get("id") != DATASET:
            raise MinecraftT6Error("created dataset identity mismatch")
        dataset_created = True
        perms = call("filesystem.setperm", [{"path": WORLD, "uid": 568, "gid": 568,
            "mode": "775", "options": {"stripacl": True, "recursive": False, "traverse": False}}])
        if isinstance(perms, int) and not isinstance(perms, bool):
            wait_job(perms, "world directory owner")
        elif perms not in (None, True):
            raise MinecraftT6Error("unexpected world permission result")
        observed_perms = call("filesystem.stat", [WORLD])
        if (not isinstance(observed_perms, dict) or observed_perms.get("uid") != 568
                or observed_perms.get("gid") != 568):
            raise MinecraftT6Error("writable world ownership readback mismatch")
        upload = multipart_upload(a.host, a.port, a.tls, "truenas_admin", password,
                                  SENTINEL_PATH, sentinel_bytes, 0o644, a.timeout)
        wait_job(upload, "world sentinel write")
        payload["sentinel_sha256"] = read_sentinel()
        create_payload = {"app_name": APP, "catalog_app": "minecraft", "train": "community",
                          "version": control["runtime"]["catalog_version_candidate"],
                          "values": desired}
        app_created = True  # ownership was clean immediately before mutating request
        wait_job(call("app.create", [create_payload]), "Minecraft first create")
        wait_app()
        wait_status("first")
        read_sentinel()
        def observe_collage_after_native_readiness():
            if (a.collage_https_port is None or a.collage_source_ref is None
                    or a.collage_https_port <= 0):
                raise MinecraftT6Error("COLLAGE P2 readback admission incomplete")
            from truenas_middleware_collage_readback_p2 import (
                ObservationError, run_real_readback,
            )
            try:
                payload["collage_readback"] = run_real_readback(
                    call,
                    collage=a.collage_source_dir,
                    https_port=a.collage_https_port,
                    state_dir=a.out.parent,
                    expected_source_sha=a.collage_source_ref,
                    profile="vanilla263" if VANILLA263 else "paper",
                )
            except ObservationError as err:
                # The helper emits only a fixed reason code, no raw auth,
                # certificate, network or client traces.
                raise MinecraftT6Error("COLLAGE P2: " + str(err)) from None
            read_sentinel()

        # The exact Lantern ZIP stage/persistence was independently accepted
        # in 006/007/008 despite terminal scoped-key failures. Do not repay
        # three App restarts before attempting the still-unqualified G1/G2
        # read-only Go observer. Observe the verified first native App here;
        # on success, retain this same App/world for real ZIP stage/reinstall.
        # Legacy native-only and Paper P2 default paths remain unchanged.
        if a.collage_source_dir is not None:
            observe_collage_after_native_readiness()

        first_level = payload["readiness"]["first"]["level"]["size"]

        wait_job(call("app.stop", [APP]), "Minecraft stop")
        if a.native_world_rollback:
            from qualify_vanilla263_native_world_rollback import take_owned_pre_stage_snapshot
            try:
                payload["native_world_rollback"] = take_owned_pre_stage_snapshot(call)
            except Exception as exc:
                from qualify_vanilla263_native_world_rollback import Refused
                if isinstance(exc, Refused):
                    raise MinecraftT6Error("G3 snapshot: " + str(exc)) from None
                raise MinecraftT6Error("G3 snapshot: FIXED_NATIVE_SNAPSHOT_UNAVAILABLE") from None
        if lantern_blob is not None:
            from qualify_vanilla263_native_lantern_stage import stage
            try:
                payload["lantern_artifact_stage"] = stage(
                    call, wait_job, multipart_upload, middleware_http_bytes,
                    host=a.host, port=a.port, tls=a.tls,
                    username="truenas_admin", password=password,
                    timeout=a.timeout, blob=lantern_blob, evidence=lantern_evidence)
            except Exception as exc:
                # Report only the bounded code. Never emit credentials,
                # middleware errors or raw artifacts into public GHA logs.
                from qualify_vanilla263_native_lantern_stage import Refused
                if isinstance(exc, Refused):
                    raise MinecraftT6Error("native Lantern stage: " + str(exc)) from None
                raise MinecraftT6Error("native Lantern stage: GUEST_STAGE_UNAVAILABLE") from None
        wait_job(call("app.start", [APP]), "Minecraft start")
        wait_app()
        wait_status("restart")
        if lantern_blob is not None:
            from qualify_vanilla263_native_lantern_stage import readback, SHA
            require_stage = readback(call,wait_job,middleware_http_bytes,
                         host=a.host,port=a.port,tls=a.tls,timeout=a.timeout)
            if require_stage != SHA:
                raise MinecraftT6Error("native Lantern staged file lost during restart")
            payload["lantern_artifact_stage"]["persisted_on_restart"] = True
        wait_job(call("app.redeploy", [APP]), "Minecraft redeploy")
        wait_app()
        wait_status("redeploy")
        delete_app("Minecraft retain-world delete")
        if one("pool.dataset.query", [["id", "=", DATASET]]) is None:
            raise MinecraftT6Error("world dataset destroyed by App delete")
        if stat_level() is None:
            raise MinecraftT6Error("world level.dat absent after App deletion")
        read_sentinel()
        payload["world_retained_on_delete"] = True
        app_created = True
        wait_job(call("app.create", [create_payload]), "Minecraft reinstall")
        wait_app()
        wait_status("reinstall")
        if lantern_blob is not None:
            from qualify_vanilla263_native_lantern_stage import readback, SHA
            actual = readback(call,wait_job,middleware_http_bytes,
                     host=a.host,port=a.port,tls=a.tls,timeout=a.timeout)
            if actual != SHA:
                raise MinecraftT6Error("native Lantern staged file lost across reinstall")
            payload["lantern_artifact_stage"]["persisted_on_reinstall"] = True
            # The same exact App owner is rechecked by wait_app() above;
            # pre-stage TLS Go observation remains a separate G2 receipt.
        if a.native_offline_player:
            from qualify_native_vanilla263_mineflayer_causal import run as run_player
            payload["native_player_gameplay"] = {
                "candidate": run_player(stage="candidate",
                    forward=a.native_player_forward, state_dir=a.out.parent,
                    node_path=a.native_player_node_path),
                "same_native_guest_client_causal_visibility": False,
                "backend_independent_world_oracle_pass": False,
                "collage_managed_deployment": False,
                "physical_true_nas_apply": "HOLD",
            }
        if a.native_world_rollback:
            from qualify_vanilla263_native_world_rollback import restore_owned_baseline_after_injected_fault
            try:
                restored = restore_owned_baseline_after_injected_fault(
                    call, wait_job, wait_app, wait_status)
            except Exception as exc:
                from qualify_vanilla263_native_world_rollback import Refused
                if isinstance(exc, Refused):
                    raise MinecraftT6Error("G3 rollback: " + str(exc)) from None
                raise MinecraftT6Error("G3 rollback: FIXED_NATIVE_RESTORE_UNAVAILABLE") from None
            payload["native_world_rollback"].update(restored)
        if a.native_offline_player:
            from qualify_native_vanilla263_mineflayer_causal import run as run_player
            payload["native_player_gameplay"]["rollback"] = run_player(
                stage="rollback", forward=a.native_player_forward,
                state_dir=a.out.parent, node_path=a.native_player_node_path)
            payload["native_player_gameplay"]["same_native_guest_client_causal_visibility"] = True
        read_sentinel()
        if first_level <= 0:
            raise MinecraftT6Error("world level.dat size invalid")
        payload["world_rebound_after_reinstall"] = True
        delete_app("Minecraft final delete")
        if stat_level() is None:
            raise MinecraftT6Error("world not retained before explicit owned cleanup")
        read_sentinel()
        result = call("pool.dataset.delete", [DATASET, {"recursive": True, "force": False}])
        if result is not True:
            raise MinecraftT6Error("owned ZFS dataset delete was not confirmed")
        dataset_created = False
        if one("pool.dataset.query", [["id", "=", DATASET]]) is not None:
            raise MinecraftT6Error("world dataset cleanup left residue")
        payload["cleanup"] = {"attempted": True, "zero_residue": True, "app_absent": True,
                              "owned_world_dataset_absent": True}
        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["detail"] = ("native vanilla 26.3 status/world lifecycle verified in disposable TrueNAS; not physical site or managed COLLAGE" if VANILLA263 else "native Paper Minecraft status/world lifecycle verified in disposable TrueNAS; not vanilla 26.3 or physical site")
    except Exception as exc:
        payload["failure_type"] = type(exc).__name__
        payload["detail"] = str(exc) if isinstance(exc, MinecraftT6Error) else "runtime exception; inspect bounded guest diagnostics"
        if ws is not None and (app_created or dataset_created):
            cleanup = {"attempted": True, "zero_residue": False}
            try:
                if app_created and getapp() is not None:
                    delete_app("failure cleanup App")
                cleanup["app_absent"] = getapp() is None
                if dataset_created and cleanup["app_absent"] and one("pool.dataset.query", [["id", "=", DATASET]]) is not None:
                    # Destroy only own dataset, never any unknown/foreign dataset.
                    removed = call("pool.dataset.delete", [DATASET, {"recursive": True, "force": False}])
                    if removed is not True:
                        raise MinecraftT6Error("failure cleanup dataset refused")
                cleanup["owned_world_dataset_absent"] = one("pool.dataset.query", [["id", "=", DATASET]]) is None
                cleanup["zero_residue"] = cleanup["app_absent"] and cleanup["owned_world_dataset_absent"]
            except Exception as cexc:
                cleanup["cleanup_error_type"] = type(cexc).__name__
            payload["cleanup"] = cleanup
        # A failed product oracle need not mean contaminated guest or failed cleanup.
        # Prove the guest middleware is still coherent using read-only endpoints.
        if ws is not None and payload["cleanup"].get("zero_residue") is True:
            try:
                system_ok = call("system.version", []) == a.expected_system_version
                docker = call("docker.config", [])
                payload["post_failure_platform_healthy"] = bool(
                    system_ok and isinstance(docker, dict)
                    and getapp() is None
                    and one("pool.dataset.query", [["id", "=", DATASET]]) is None
                )
            except Exception:
                payload["post_failure_platform_healthy"] = False
    finally:
        if ws is not None:
            ws.close()
    payload["elapsed_seconds"] = round(time.monotonic() - started, 2)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["oracleSatisfied"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
