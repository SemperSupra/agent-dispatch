#!/usr/bin/env python3
"""Read-only TrueNAS app/ZFS *observation* for synthetic Takeout T6.

Consumes an injected, already-admitted DDP call function and pinned candidate.
Cannot create/delete, login, acquire elevated permissions or attest archive
bytes. This is a reusable observer, not a ready guest execution provider.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable


class ObservationBlocked(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise ObservationBlocked(code)


def canonical_digest(value):
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def observe(call: Callable, control: dict, *, stage: str,
            exact_compose: dict | None = None) -> dict:
    require(stage in {"BEFORE_NATIVE_APP_DELETE", "AFTER_NATIVE_APP_DELETE"},
            "UNSUPPORTED_STAGE")
    require(isinstance(control, dict) and
            control.get("schema") == "takeout-synthetic-guest-control-candidate/v1" and
            control.get("decision") == "HOLD" and
            control.get("target", {}).get("guest_only") is True,
            "UNTRUSTED_GUEST_CONTROL")
    profile = control["data"]
    app_name = profile["app_name"]
    datasets = (
        (profile["archive_dataset"], profile["archive_host_path"]),
        (profile["state_dataset"], profile["state_host_path"]),
    )
    require(profile["network_mode"] == "none" and profile["restart"] == "no" and
            profile["worker_user"] == "10001:10001" and
            profile["archive_dataset"] != profile["state_dataset"],
            "SOURCE_SECURITY_PROFILE_DRIFT")
    try:
        version = call("system.version", [])
    except Exception:
        raise ObservationBlocked("NATIVE_VERSION_UNAVAILABLE") from None
    require(version == "TrueNAS-25.04.2.6", "NATIVE_SYSTEM_VERSION_MISMATCH")
    try:
        app = call("app.query", [[["id", "=", app_name]], {"get": True}])
        ds_data = []
        for name, path in datasets:
            found = call("pool.dataset.query", [[["id", "=", name]]])
            require(isinstance(found, list) and len(found) == 1 and
                    isinstance(found[0], dict) and
                    found[0].get("id") == name,
                    "OWNED_DATASET_NOT_PRESENT")
            ds_data.append((name, path, found[0]))
    except ObservationBlocked:
        raise
    except Exception:
        raise ObservationBlocked("NATIVE_INVENTORY_UNAVAILABLE") from None
    stat_data = []
    for name, path, dataset in ds_data:
        require(dataset.get("mountpoint") == path,
                "DATASET_MOUNTPOINT_DRIFT")
        try:
            st = call("filesystem.stat", [path])
        except Exception:
            raise ObservationBlocked("OWNED_HOSTPATH_UNOBSERVABLE") from None
        require(isinstance(st, dict) and st.get("type") == "DIRECTORY" and
                st.get("uid") == 10001 and st.get("gid") == 10001,
                "HOSTPATH_OWNERSHIP_MISMATCH")
        stat_data.append({"dataset": name, "mountpoint": path,
                          "owner_uid": 10001, "owner_gid": 10001})
    if stage == "BEFORE_NATIVE_APP_DELETE":
        require(isinstance(app, dict) and app.get("id") == app_name and
                app.get("custom_app") is True and app.get("state") == "STOPPED",
                "NATIVE_APP_NOT_STOPPED")
        require(exact_compose is not None and
                isinstance(exact_compose, dict) and
                set(exact_compose.get("services", {})) == {"takeoutsynthetic"},
                "EXPECTED_COMPOSE_UNBOUND")
        try:
            actual = call("app.config", [app_name])
        except Exception:
            raise ObservationBlocked("NATIVE_APP_CONFIG_UNAVAILABLE") from None
        require(isinstance(actual, dict) and actual == exact_compose,
                "NATIVE_COMPOSE_READBACK_DRIFT")
        worker = actual["services"]["takeoutsynthetic"]
        require(worker.get("image") == control["image"]["tag"] and
                worker.get("restart") == "no" and
                worker.get("network_mode") == "none" and
                worker.get("read_only") is True and
                str(worker.get("user")) in ("10001", "10001:10001") and
                not worker.get("ports") and not worker.get("privileged"),
                "NATIVE_WORKER_SECURITY_DRIFT")
        require(any(profile["archive_host_path"] in str(v) and "/archive" in str(v)
                    for v in worker.get("volumes", [])) and
                any(profile["state_host_path"] in str(v) and "/state" in str(v)
                    for v in worker.get("volumes", [])),
                "NATIVE_DATA_MOUNT_MISMATCH")
        return {"classification": "NATIVE_APP_READBACK_SHAPE_ONLY",
                "stage": stage, "app": app_name,
                "compose_sha256": canonical_digest(actual),
                "hostpath_observations": stat_data,
                "native_credential_origin_attested": False,
                "native_guest_execution_attested": False,
                "independent_file_bytes_verified": False,
                "docker_read_required": False, "physical_apply": "HOLD"}
    else:
        require(app is None or app == [] or app == {},
                "NATIVE_APP_STILL_PRESENT_AFTER_DELETE")
        require(exact_compose is None, "POST_DELETE_COMPOSE_NOT_ALLOWED")
        return {"classification": "NATIVE_APP_ABSENCE_SHAPE_ONLY",
                "stage": stage, "app": app_name,
                "hostpath_observations": stat_data,
                "retained_datasets_observed": True,
                "native_guest_execution_attested": False,
                "independent_file_bytes_verified": False,
                "docker_read_required": False, "physical_apply": "HOLD"}
