#!/usr/bin/env python3
"""Bounded WOW Sidecar Foundry T6 oracle on disposable TrueNAS."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import time

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for

SCHEMA = "semper-supra.wow-sidecar-truenas-t6-control/1"
EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"
EXPECTED_APP_NAME = "rdte-t6-wow-sidecar"
EXPECTED_IMAGE = "ghcr.io/sempersupra/wow-sidecar@sha256:6b700ce7ba5ae44116b240ccbb54fb3b60dc952a9b4072ca1314b6f311bc5376"
EXPECTED_HELPER = "ixsystems/container-utils@sha256:46eba20714c1cc6784f60e245c32c33a2d9f616e47d804694a9854248c89a992"
EXPECTED_FIXTURE_DATASET = "rdtepool/wow-sidecar-t6"
EXPECTED_FIXTURE_ROOT = "/mnt/rdtepool/wow-sidecar-t6"
EXPECTED_CONFIG_DIR = EXPECTED_FIXTURE_ROOT + "/config"
EXPECTED_STATE_DIR = EXPECTED_FIXTURE_ROOT + "/state"
EXPECTED_KEY_PATH = EXPECTED_CONFIG_DIR + "/github-app.pem"
EXPECTED_PROFILE_PATH = EXPECTED_CONFIG_DIR + "/profiles/operator.json"
EXPECTED_MARKER_PATH = EXPECTED_CONFIG_DIR + "/.initialized-v1"
FIXTURE_MARKER = "PUBLIC-QUALIFICATION-FIXTURE"
PRIVATE_REPO_RE = re.compile(r"(?:https://github\\.com/)?SemperSupra/[A-Za-z0-9_.-]+-private(?![A-Za-z0-9_.-])", re.IGNORECASE)
PEM_RE = re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL)


def sanitize_diagnostic_text(value: object, limit: int = 6000) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = PEM_RE.sub("<redacted-pem>", text)
    text = PRIVATE_REPO_RE.sub("<redacted-private-repository>", text)
    text = re.sub(r"\\b(?:ghp_|github_pat_|sk-)[A-Za-z0-9_-]+", "<redacted-token>", text)
    if len(text) > limit:
        text = text[:limit] + "<truncated>"
    return text


def canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def load_json(path: pathlib.Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain an object")
    return value


def load_control(directory: pathlib.Path, foundry_commit: str) -> tuple[dict, dict]:
    control = load_json(directory / "control.json")
    compose = load_json(directory / "compose.json")
    if control.get("schema") != SCHEMA:
        raise RuntimeError("unexpected WOW T6 control schema")
    if control.get("foundry_ref") != foundry_commit:
        raise RuntimeError("Foundry source ref drifted")
    if control.get("secrets_captured") is not False:
        raise RuntimeError("control bundle does not assert secrets_captured=false")

    candidate = control.get("candidate") or {}
    if candidate.get("wow_image") != EXPECTED_IMAGE:
        raise RuntimeError("WOW image identity drifted")
    if candidate.get("permissions_helper") != EXPECTED_HELPER:
        raise RuntimeError("permissions helper identity drifted")
    runtime = control.get("runtime") or {}
    if runtime.get("app_name") != EXPECTED_APP_NAME:
        raise RuntimeError("WOW T6 app name drifted")
    if runtime.get("production_credentials_present") is not False:
        raise RuntimeError("public T6 control claims production credentials")
    if runtime.get("fixture_key_marker") != FIXTURE_MARKER:
        raise RuntimeError("public fixture key marker drifted")
    if runtime.get("fixture_config_dir") != EXPECTED_CONFIG_DIR:
        raise RuntimeError("fixture config directory drifted")
    if runtime.get("fixture_state_dir") != EXPECTED_STATE_DIR:
        raise RuntimeError("fixture state directory drifted")

    if control.get("artifacts", {}).get("compose_canonical_sha256") != canonical_sha256(compose):
        raise RuntimeError("rendered Compose identity does not match control")

    services = compose.get("services") or {}
    if set(services) != {"permissions", "wow-sidecar", "wow-sidecar-config-seed"}:
        raise RuntimeError("unexpected WOW T6 service inventory")
    if services["wow-sidecar"].get("image") != EXPECTED_IMAGE:
        raise RuntimeError("worker image drifted")
    if services["wow-sidecar-config-seed"].get("image") != EXPECTED_IMAGE:
        raise RuntimeError("seed image drifted")
    if services["permissions"].get("image") != EXPECTED_HELPER:
        raise RuntimeError("permissions image drifted")

    serialized = json.dumps(compose, sort_keys=True)
    if FIXTURE_MARKER not in serialized:
        raise RuntimeError("public fixture marker is absent from exact control")
    if PRIVATE_REPO_RE.search(serialized):
        raise RuntimeError("private repository identity leaked into public control")
    for forbidden in ("ghp_", "sk-"):
        if forbidden in serialized:
            raise RuntimeError(f"private credential-like content leaked into public control: {forbidden}")
    return control, compose


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--control-dir", type=pathlib.Path, required=True)
    p.add_argument("--foundry-commit", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    p.add_argument("--state-timeout", type=float, default=240.0)
    a = p.parse_args()

    started = time.time()
    payload = {
        "schema": "truenas-wow-sidecar-foundry-t6/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "expected_version": EXPECTED_VERSION,
        "foundry_commit": a.foundry_commit,
        "app_name": EXPECTED_APP_NAME,
        "wow_image": EXPECTED_IMAGE,
        "permissions_helper": EXPECTED_HELPER,
        "production_credentials_present": False,
        "execution_control_mutation_authorized": False,
        "credential_boundary": "public-fixture-only",
    }
    ws = None
    request_id = 1
    created_app = False
    created_dataset = False

    try:
        control, compose = load_control(a.control_dir, a.foundry_commit)
        compose_sha = canonical_sha256(compose)
        payload["materialization"] = {
            "schema": control["schema"],
            "foundry_ref": control["foundry_ref"],
            "compose_canonical_sha256": compose_sha,
            "production_credentials_present": False,
        }

        password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()
        ws = WebSocket(a.host, a.port, timeout=a.timeout, tls=a.tls)
        ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(ws, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise RuntimeError("DDP connection failed")

        def call(method, params):
            nonlocal request_id
            result = ddp_call(ws, str(request_id), method, params)
            request_id += 1
            return result

        def wait_job(job_id, label):
            deadline = time.monotonic() + a.job_timeout
            last = None
            while time.monotonic() < deadline:
                last = call("core.get_jobs", [[["id", "=", job_id]], {"get": True}])
                if last and last.get("state") == "SUCCESS":
                    return last
                if last and last.get("state") in {"FAILED", "ABORTED"}:
                    exc_info = last.get("exc_info") if isinstance(last.get("exc_info"), dict) else {}
                    payload["job_failure"] = {
                        "label": label,
                        "job_id": job_id,
                        "method": last.get("method"),
                        "state": last.get("state"),
                        "progress": last.get("progress"),
                        "error": sanitize_diagnostic_text(last.get("error")),
                        "exception": sanitize_diagnostic_text(last.get("exception")),
                        "logs_excerpt": sanitize_diagnostic_text(last.get("logs_excerpt")),
                        "exc_info": {
                            "type": exc_info.get("type"),
                            "errno": exc_info.get("errno"),
                            "errname": exc_info.get("errname"),
                            "repr": sanitize_diagnostic_text(exc_info.get("repr")),
                            "extra": sanitize_diagnostic_text(exc_info.get("extra"), 3000),
                        },
                        "arguments_recorded": False,
                        "credentials_recorded": False,
                    }
                    raise RuntimeError(f"{label} job {last.get('state')}")
                time.sleep(1)
            raise RuntimeError(f"{label} job did not reach SUCCESS")

        def app_query(get=True):
            params = [[["id", "=", EXPECTED_APP_NAME]]]
            if get:
                params.append({"get": True})
            return call("app.query", params)

        def wait_running():
            deadline = time.monotonic() + a.state_timeout
            last = None
            while time.monotonic() < deadline:
                last = app_query()
                if last:
                    if last.get("state") in {"CRASHED", "ERROR"}:
                        raise RuntimeError(f"WOW app entered {last.get('state')}")
                    details = (last.get("active_workloads") or {}).get("container_details") or []
                    workers = [
                        item for item in details
                        if item.get("service_name") == "wow-sidecar"
                        and item.get("image") == EXPECTED_IMAGE
                        and item.get("state") == "running"
                    ]
                    if last.get("state") == "RUNNING" and len(workers) == 1:
                        return last
                time.sleep(1)
            raise RuntimeError(f"WOW worker did not reach RUNNING: {last!r}")

        auth = call("auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": "truenas_admin",
            "password": password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise RuntimeError("authentication did not return SUCCESS")

        payload["system_version"] = call("system.version", [])
        if payload["system_version"] != EXPECTED_VERSION:
            raise RuntimeError("target version drifted")

        if call("app.query", [[["id", "=", EXPECTED_APP_NAME]]]):
            raise RuntimeError("refusing adopted WOW app state")
        if call("pool.dataset.query", [[["id", "=", EXPECTED_FIXTURE_DATASET]]]):
            raise RuntimeError("refusing adopted WOW fixture dataset")

        dataset = call("pool.dataset.create", [{
            "name": EXPECTED_FIXTURE_DATASET,
            "type": "FILESYSTEM",
            "share_type": "GENERIC",
            "comments": "SemperSupra disposable WOW Sidecar T6 fixture",
        }])
        if not isinstance(dataset, dict) or dataset.get("id") != EXPECTED_FIXTURE_DATASET:
            raise RuntimeError("pool.dataset.create did not return exact WOW fixture dataset")
        created_dataset = True

        created_dirs = []
        for path in (EXPECTED_CONFIG_DIR, EXPECTED_STATE_DIR):
            result = call("filesystem.mkdir", [{
                "path": path,
                "options": {"mode": "750", "raise_chmod_error": True},
            }])
            if not isinstance(result, dict) or result.get("path") != path:
                raise RuntimeError(f"filesystem.mkdir did not create exact path {path}")
            created_dirs.append(path)
        payload["fixture_storage"] = {
            "dataset": EXPECTED_FIXTURE_DATASET,
            "directories": created_dirs,
            "content_recorded": False,
        }

        create_id = call("app.create", [{
            "app_name": EXPECTED_APP_NAME,
            "custom_app": True,
            "custom_compose_config": compose,
        }])
        if not isinstance(create_id, int):
            raise RuntimeError("app.create did not return a job id")
        wait_job(create_id, "app.create")
        created_app = True

        app = wait_running()
        details = (app.get("active_workloads") or {}).get("container_details") or []
        payload["runtime"] = {
            "state": app.get("state"),
            "custom_app": app.get("custom_app"),
            "worker_running_exact_image": any(
                item.get("service_name") == "wow-sidecar"
                and item.get("image") == EXPECTED_IMAGE
                and item.get("state") == "running"
                for item in details
            ),
            "container_states": sorted({
                f"{item.get('service_name')}:{item.get('state')}"
                for item in details
                if isinstance(item, dict)
            }),
        }
        if app.get("custom_app") is not True:
            raise RuntimeError("WOW runtime did not materialize as a custom app")

        config_sha = canonical_sha256(call("app.config", [EXPECTED_APP_NAME]))
        if config_sha != compose_sha:
            raise RuntimeError("app.config read-back does not match exact Foundry Compose")
        payload["runtime"]["compose_readback_sha256"] = config_sha

        stat_paths = {
            "config_root": EXPECTED_CONFIG_DIR,
            "state_root": EXPECTED_STATE_DIR,
            "seed_marker": EXPECTED_MARKER_PATH,
            "github_app_key": EXPECTED_KEY_PATH,
            "operator_profile": EXPECTED_PROFILE_PATH,
        }
        metadata = {}
        for label, path in stat_paths.items():
            st = call("filesystem.stat", [path])
            metadata[label] = {
                "path": path,
                "mode": oct(int(st.get("mode", 0)) & 0o777),
                "uid": st.get("uid"),
                "gid": st.get("gid"),
                "type": st.get("type"),
            }
        if metadata["config_root"]["uid"] != 10001 or metadata["config_root"]["gid"] != 10001:
            raise RuntimeError("config root ownership does not match WOW runtime identity")
        if metadata["state_root"]["uid"] != 10001 or metadata["state_root"]["gid"] != 10001:
            raise RuntimeError("state root ownership does not match WOW runtime identity")
        if metadata["github_app_key"]["mode"] != "0o400":
            raise RuntimeError("fixture GitHub App key mode is not 0400")
        if metadata["operator_profile"]["mode"] != "0o400":
            raise RuntimeError("fixture operator profile mode is not 0400")
        if metadata["seed_marker"]["mode"] != "0o444":
            raise RuntimeError("seed marker mode is not 0444")
        payload["seed_metadata"] = metadata
        payload["seed_metadata"]["raw_content_recorded"] = False

        stop_id = call("app.stop", [EXPECTED_APP_NAME])
        wait_job(stop_id, "app.stop")
        stopped = app_query()
        if not stopped or stopped.get("state") != "STOPPED":
            raise RuntimeError("WOW app did not reach STOPPED")

        start_id = call("app.start", [EXPECTED_APP_NAME])
        wait_job(start_id, "app.start")
        wait_running()
        restart_sha = canonical_sha256(call("app.config", [EXPECTED_APP_NAME]))
        if restart_sha != compose_sha:
            raise RuntimeError("Foundry Compose identity drifted after restart")
        payload["runtime"]["restart_compose_identity_preserved"] = True

        delete_id = call("app.delete", [EXPECTED_APP_NAME, {
            "remove_images": False,
            "remove_ix_volumes": False,
            "force_remove_custom_app": False,
        }])
        wait_job(delete_id, "app.delete")
        created_app = False
        if call("app.query", [[["id", "=", EXPECTED_APP_NAME]]]):
            raise RuntimeError("WOW app remains after delete")

        deleted = call("pool.dataset.delete", [
            EXPECTED_FIXTURE_DATASET,
            {"recursive": True, "force": False},
        ])
        if deleted is not True:
            raise RuntimeError("pool.dataset.delete did not return true")
        created_dataset = False
        if call("pool.dataset.query", [[["id", "=", EXPECTED_FIXTURE_DATASET]]]):
            raise RuntimeError("WOW fixture dataset remains after delete")

        mountpoint_absent = False
        try:
            call("filesystem.stat", [EXPECTED_FIXTURE_ROOT])
        except RuntimeError:
            mountpoint_absent = True
        if not mountpoint_absent:
            raise RuntimeError("WOW fixture mountpoint remains after dataset delete")

        payload["cleanup"] = {
            "app_absent": True,
            "fixture_dataset_absent": True,
            "fixture_mountpoint_absent": True,
            "zero_residue": True,
        }
        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["detail"] = (
            "exact Foundry-exported WOW App realized on real disposable TrueNAS; "
            "immutable image/config read-back, permissions, create-once seed metadata, "
            "worker RUNNING under public fixture credential, restart persistence, "
            "and delete/zero-residue all passed"
        )
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
        payload["cleanup_needed"] = {
            "app": created_app,
            "fixture_dataset": created_dataset,
        }
    finally:
        if ws is not None:
            ws.close()

    payload["elapsed_seconds"] = round(time.time() - started, 3)
    pathlib.Path(a.out).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
