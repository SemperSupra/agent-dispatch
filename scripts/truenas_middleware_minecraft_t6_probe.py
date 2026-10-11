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

SCHEMA = "semper-supra.minecraft-paper-truenas-t6-control/1"
EXPECTED_TARGET = "25.04.1"
EXPECTED_PROFILE = "800aca038ded29e6a91bfc4c1b1fe2d2199182e8"
EXPECTED_APPS_COMMIT = "bb96ef6fd8c2708765012a4a3ca3739370a4f92c"
EXPECTED_IMAGE_FRAGMENT = "ghcr.io/itzg/minecraft-server:2026.9.2-java21@sha256:edf50d431ddc6f73929368e82f4334a405796874f7b0ae11f1edcbb267d670aa"
EXPECTED_MIDDLEWARE = "74ab5a2d373be4097dece257d00e1086376333ba"
APP = "rdte-t6-minecraft-paper"
DATASET = "rdtepool/minecraft-paper-t6-world"
WORLD = "/mnt/rdtepool/minecraft-paper-t6-world"
PORT = 25580
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


class MinecraftT6Error(RuntimeError):
    pass


def qualified_native_image(app: dict) -> str | None:
    """Accept only the digest-pinned OCI reference, with optional tag normalization."""
    work = app.get("active_workloads") or {}
    candidates = list(work.get("images") or [])
    for item in work.get("container_details") or []:
        if isinstance(item, dict) and isinstance(item.get("image"), str):
            candidates.append(item["image"])
    repository_tag, digest = EXPECTED_IMAGE_FRAGMENT.split("@sha256:", 1)
    repository = repository_tag.rsplit(":", 1)[0]
    valid = {EXPECTED_IMAGE_FRAGMENT, repository + "@sha256:" + digest}
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


def load_control(path: pathlib.Path, expected_commit: str) -> dict:
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
    if (source.get("apps_commit") != EXPECTED_APPS_COMMIT or
        source.get("app") != "community/minecraft" or
        source.get("image_reference") != EXPECTED_IMAGE_FRAGMENT or
        source.get("library_version") != "2.3.4" or
        not re.fullmatch("[0-9a-f]{64}", str(source.get("source_compose_sha256", ""))) or
        not re.fullmatch("[0-9a-f]{64}", str(source.get("values_raw_sha256", "")))):
        raise MinecraftT6Error("pinned native Minecraft catalog source drift")
    runtime = control.get("runtime") or {}
    if (runtime.get("app_name") != APP or runtime.get("catalog_app") != "minecraft" or
        runtime.get("train") != "community" or runtime.get("catalog_version_candidate") != "1.15.29" or
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
                       expected_version: str = "1.21.11") -> dict:
    if not script.is_file() or script.name != "minecraft_java_status_oracle.py":
        raise MinecraftT6Error("exact Minecraft product oracle file absent")
    cmd = [sys.executable, str(script), "--port", str(port),
           "--expected-version", expected_version, "--timeout", "5",
           "--out", str(out)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
    if result.returncode != 0 or not out.is_file():
        raise MinecraftT6Error("Minecraft Java status oracle did not pass")
    verdict = json.loads(out.read_text(encoding="utf-8"))
    if (verdict.get("schema") != "minecraft-java-status-oracle/v1" or
        verdict.get("classification") != "SUPPORTED" or
        verdict.get("oracleSatisfied") is not True or
        verdict.get("java_version") != expected_version or
        verdict.get("status_packet_valid") is not True):
        raise MinecraftT6Error("Minecraft Java status receipt invalid")
    return verdict


def owner_readback_vector(config: dict, wanted: dict) -> dict[str, bool]:
    """Only boolean equality witnesses. Never emit app.config values or owner envs."""
    minecraft = (config.get("minecraft") or {}) if isinstance(config, dict) else {}
    env = minecraft.get("additional_envs") or [] if isinstance(minecraft, dict) else []
    found_owner = {v.get("name"): v.get("value") for v in env if isinstance(v, dict)} if isinstance(env, list) else {}
    return {
        "minecraft_type": minecraft.get("type") == "PAPER" if isinstance(minecraft, dict) else False,
        "minecraft_version": minecraft.get("version") == "1.21.11" if isinstance(minecraft, dict) else False,
        "owner_environment": found_owner == REQUIRED_OWNER,
        "additional_storage": (config.get("storage") or {}).get("additional_storage") == wanted["storage"]["additional_storage"] if isinstance(config, dict) and isinstance(config.get("storage") or {}, dict) else False,
        "server_port": (config.get("network") or {}).get("server_port") == wanted["network"]["server_port"] if isinstance(config, dict) and isinstance(config.get("network") or {}, dict) else False,
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
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8)
    p.add_argument("--job-timeout", type=float, default=600)
    p.add_argument("--state-timeout", type=float, default=480)
    a = p.parse_args()
    started = time.monotonic()
    payload = {
        "schema": "truenas-minecraft-paper-t6/v1",
        "classification": "ORACLE_FAILURE", "oracleSatisfied": False,
        "product": "paper-upstream-1.21.11", "target": EXPECTED_TARGET,
        "cleanup": {"attempted": False, "zero_residue": False},
        "secret_values_captured": False,
    }
    ws = None
    dataset_created = False
    app_created = False
    try:
        control = load_control(a.control_dir, a.foundry_commit)
        if a.expected_system_version != "TrueNAS-" + EXPECTED_TARGET:
            raise MinecraftT6Error("requested exact system version drift")
        desired = runtime_values(control)
        sentinel_bytes = ("SUPRACRAFT-PAPER-T6:" + control["control_sha256"] + "\n").encode("ascii")
        payload["foundry_ref"] = a.foundry_commit
        payload["control_sha256"] = control["control_sha256"]
        if not a.status_oracle.is_file():
            raise MinecraftT6Error("qualified status oracle source absent")
        password = a.password_file.read_text(encoding="utf-8").strip()
        ws = WebSocket(a.host, a.port, timeout=a.timeout, tls=a.tls)
        ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        if wait_for(ws, lambda m: m.get("msg") in {"connected", "failed"}).get("msg") != "connected":
            raise MinecraftT6Error("DDP connection failed")
        ident = 1
        def call(method, params):
            nonlocal ident
            result = ddp_call(ws, str(ident), method, params)
            ident += 1
            return result
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
                    matching_image = qualified_native_image(app)
                    if matching_image is None:
                        raise MinecraftT6Error("native Minecraft App runtime image differs from digest-pinned source")
                    payload["observed_image_reference"] = matching_image
                    payload["image_digest_qualification"] = "SOURCE_AND_GUEST_REF_MATCH"
                    cfg = call("app.config", [APP])
                    match_vector = owner_readback_vector(cfg, desired)
                    if all(match_vector.values()):
                        return app
                    # Emit only field-level match booleans; no actual user values,
                    # storage paths, environment variables or credentials.
                    payload["owner_readback_match"] = match_vector
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
            while time.monotonic() < deadline:
                receipt = a.out.with_name(a.out.stem + "-status-" + label + ".json")
                try:
                    verdict = safe_status_oracle(a.status_oracle, a.status_port, receipt)
                    level = stat_level()
                    if level is not None:
                        payload.setdefault("readiness", {})[label] = {"protocol": verdict, "level": level}
                        return
                except (OSError, ValueError, MinecraftT6Error, subprocess.TimeoutExpired) as exc:
                    last = type(exc).__name__
                time.sleep(4)
            raise MinecraftT6Error("Minecraft runtime status+world did not converge: " + str(last))
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
            "upstream_apps_commit": EXPECTED_APPS_COMMIT,
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
        first_level = payload["readiness"]["first"]["level"]["size"]

        wait_job(call("app.stop", [APP]), "Minecraft stop")
        wait_job(call("app.start", [APP]), "Minecraft start")
        wait_app()
        wait_status("restart")
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
        payload["detail"] = "native Paper Minecraft status/world lifecycle verified in disposable TrueNAS; not vanilla 26.3 or physical site"
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
