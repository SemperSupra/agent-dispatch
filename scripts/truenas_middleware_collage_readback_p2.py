#!/usr/bin/env python3
"""COLLAGE P2: independent native TrueNAS App readback in one disposable guest.

This helper only runs after the existing Paper T6 proof has installed a native
App. Credential/certificate setup mutates the *disposable guest* before the
observation phase. Only the Go observer reads provider state. Never use on a
physical TrueNAS host, with an existing site's credentials, or in operations.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import ssl
import subprocess
import sys
import tempfile

SCHEMA = "semper-supra.collage-native-readback-p2/1"
REALM = "d68a14b9-2a1c-4e83-a452-e3b569cdf93e"
SERVICE_UUID = "11111111-1111-4111-8111-111111111111"
NAME = "collage_p2_observer"
ROLE_NAME = "collage-p2-apps-read"
OWNER = "rdte-t6-minecraft-paper"
WORLD_ID = "world-rdte-001"
DEFAULT_SOURCE_SHA = "fbda94f3fea0a216ddd9c35b38a09d325bed3640"
NATIVE_VANILLA263_SOURCE = "17dfacc4351053fa06f8bdbaed7d931c97c1707e"
NATIVE_VANILLA263_ARTIFACT_SHA = "da25005e8729e6f013f7108ac5b8869dd46323befc78efdae18221b26cafe5f8"
NATIVE_VANILLA263_APP = "rdte-t6-minecraft-vanilla-263"
NATIVE_VANILLA263_WORLD = "lantern-rdte"


class ObservationError(RuntimeError):
    pass


def require(value: bool, code: str) -> None:
    if not value:
        raise ObservationError(code)


def available_role_names(roles: object) -> set[str]:
    """TrueNAS 25.04 privilege.roles -> list of role descriptors, not a map.

    Reject malformed or ambiguous inventories before any guest mutation. Only
    report whether the exact role is offered; never infer broader privilege.
    """
    require(isinstance(roles, list), "PRIVILEGE_ROLES_SHAPE_DRIFT")
    names: set[str] = set()
    for item in roles:
        require(isinstance(item, dict) and isinstance(item.get("name"), str)
                and isinstance(item.get("includes"), list)
                and all(isinstance(x, str) for x in item["includes"]),
                "PRIVILEGE_ROLES_SHAPE_DRIFT")
        name = item["name"]
        require(name not in names, "DUPLICATE_PRIVILEGE_ROLE")
        names.add(name)
    return names


def provision_guest_readonly(call) -> str:
    """Called on *already isolated* disposable TrueNAS 25.04.1 via admin DDP.

    Explicit provisioning is *outside* the zero-mutation observation phase.
    No API keys, returned user/group/privilege records, or raw errors in logs.
    """
    require(call("user.query", [[["username", "=", NAME]]]) == [],
            "PREEXISTING_READONLY_USER_REFUSED")
    require(call("privilege.query", [[["name", "=", ROLE_NAME]]]) == [],
            "PREEXISTING_PRIVILEGE_REFUSED")
    roles = available_role_names(call("privilege.roles", []))
    require("APPS_READ" in roles, "APPS_READ_ROLE_NOT_AVAILABLE")
    user = call("user.create", [{
        "username": NAME, "full_name": "Disposable COLLAGE P2 observer",
        "group_create": True, "password_disabled": True,
        "ssh_password_enabled": False, "smb": False,
    }])
    require(isinstance(user, dict) and user.get("username") == NAME,
            "READONLY_ACCOUNT_CREATION_REFUSED")
    group = user.get("group")
    require(isinstance(group, dict) and type(group.get("id")) is int
            and type(group.get("gid")) is int,
            "READONLY_ACCOUNT_GROUP_UNAVAILABLE")
    # Exact TrueNAS 25.04.2.6 middleware privilege.create.local_groups
    # requires POSIX GIDs, NOT middleware account.group datastore IDs.
    # group.query(id=...) and user.query(group.id) still use datastore IDs.
    privilege = call("privilege.create", [{
        "name": ROLE_NAME, "local_groups": [group["gid"]],
        "roles": ["APPS_READ"], "web_shell": False,
    }])
    require(isinstance(privilege, dict) and privilege.get("name") == ROLE_NAME,
            "APPS_READ_ASSIGNMENT_UNVERIFIED")
    require(privilege.get("roles") == ["APPS_READ"],
            "CREATED_PRIVILEGE_ROLES_NOT_EXACT")
    members = privilege.get("local_groups")
    require(type(members) is list and len(members) == 1
            and type(members[0]) is dict
            and members[0].get("gid") == group["gid"],
            "CREATED_PRIVILEGE_GID_LINK_NOT_EXACT")
    # Distinguish role/primary-group propagation problems from extra authority,
    # without emitting public role names, user metadata or sensitive API fields.
    primary = call("group.query", [[["id", "=", group["id"]]], {"get": True}])
    require(isinstance(primary, dict) and primary.get("id") == group["id"],
            "OBSERVER_PRIMARY_GROUP_NOT_FOUND")
    require(primary.get("roles") == ["APPS_READ"],
            "OBSERVER_PRIMARY_GROUP_ROLE_NOT_EXACT")
    user_roles = call("user.query", [[["username", "=", NAME]], {"get": True}])
    require(isinstance(user_roles, dict) and user_roles.get("username") == NAME,
            "OBSERVER_USER_READBACK_NOT_FOUND")
    user_primary = user_roles.get("group")
    require(isinstance(user_primary, dict)
            and user_primary.get("id") == group["id"],
            "OBSERVER_USER_PRIMARY_GROUP_DRIFT")
    effective = user_roles.get("roles")
    require(isinstance(effective, list)
            and all(isinstance(role, str) for role in effective),
            "OBSERVER_USER_ROLES_SHAPE_DRIFT")
    require("APPS_READ" in effective, "OBSERVER_USER_REQUIRED_ROLE_ABSENT")
    require(effective == ["APPS_READ"], "OBSERVER_USER_EXTRA_ROLES_REFUSED")
    expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
    key = call("api_key.create", [{
        "name": "disposable-collage-p2", "username": NAME,
        "expires_at": expiry,
    }])
    require(isinstance(key, dict) and isinstance(key.get("key"), str)
            and len(key["key"]) > 20,
            "DISPOSABLE_READONLY_KEY_NOT_ISSUED")
    return key["key"]


def discover_tls_anchor(port: int, out: pathlib.Path) -> tuple[str, str]:
    """Pin self-signed guest HTTPS cert for private ephemeral RDTE loopback.

    TOFU is limited to the fresh, runner-owned, 127.0.0.1 QEMU forwarded port.
    The subsequent Go client MUST verify this pinned cert. No insecure Go TLS.
    Operational deployments must instead pin their explicit trusted CA.
    """
    require(0 < port < 65536, "INVALID_GUEST_HTTPS_PORT")
    try:
        pem = ssl.get_server_certificate(("127.0.0.1", port), timeout=12)
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (OSError, ssl.SSLError):
        raise ObservationError("DISPOSABLE_GUEST_TLS_UNAVAILABLE") from None
    out.write_text(pem, encoding="ascii")
    p = subprocess.run(["openssl", "x509", "-in", str(out), "-noout",
                        "-ext", "subjectAltName"], text=True,
                       capture_output=True, timeout=12, check=False)
    require(p.returncode == 0, "TLS_CERTIFICATE_SAN_UNAVAILABLE")
    sans = p.stdout
    if "IP Address:127.0.0.1" in sans:
        hostname = "127.0.0.1"
    elif "DNS:localhost" in sans:
        hostname = "localhost"
    else:
        # Never override an arbitrary hostname in runner DNS.
        names = re.findall(r"DNS:(truenas(?:\.[a-z0-9.-]+)?)", sans, re.I)
        require(bool(names), "TLS_CERTIFICATE_HOST_IDENTITY_UNSUPPORTED")
        hostname = names[0].lower()
        add = subprocess.run(["sudo", "-n", "sh", "-c",
                              "printf '127.0.0.1 %s\\n' \"$1\" >> /etc/hosts",
                              "sh", hostname], capture_output=True, timeout=8)
        require(add.returncode == 0, "EPHEMERAL_GUEST_HOSTNAME_BINDING_FAILED")
    return hostname, hashlib.sha256(der).hexdigest()


def run_real_readback(call, *, collage: pathlib.Path, https_port: int,
                      state_dir: pathlib.Path, expected_source_sha: str
                      = DEFAULT_SOURCE_SHA, native_vanilla263: bool = False,
                      real_artifact_dir: pathlib.Path | None = None) -> dict:
    """Return ONLY allowlisted, non-secret independent readback evidence."""
    require(collage.is_dir(), "PINNED_COLLAGE_CHECKOUT_MISSING")
    git = subprocess.run(["git", "-C", str(collage), "rev-parse", "HEAD"],
                         text=True, capture_output=True, timeout=5)
    require(git.returncode == 0 and git.stdout.strip() == expected_source_sha,
            "PINNED_COLLAGE_COMMIT_DRIFT")
    if native_vanilla263:
        require(expected_source_sha == NATIVE_VANILLA263_SOURCE,
                "VANILLA_READBACK_SOURCE_REF_DRIFT")
        require(real_artifact_dir is not None and real_artifact_dir.is_dir()
                and not real_artifact_dir.is_symlink(),
                "VANILLA_REAL_ARTIFACT_MISSING")
        real = real_artifact_dir.resolve()
        manifest_path = real / "lantern-restoration-26.3.json"
        zip_path = real / "lantern-restoration-26.3.zip"
        require(manifest_path.is_file() and zip_path.is_file() and
                not manifest_path.is_symlink() and not zip_path.is_symlink(),
                "VANILLA_REAL_ARTIFACT_MISSING")
        # Reuse COLLAGE's independent real-ZIP verifier and request generator;
        # test fixtures, raw client claims and foreign producers are refused.
        import importlib.util
        consumer_path = collage / "tools" / "consume_vanilla_datapack_source.py"
        require(consumer_path.is_file(), "VANILLA_CONSUMER_UNAVAILABLE")
        from collage_deploy_plan import Refused as _Refused
        from consume_vanilla_datapack_source import (
            audience_requests, consume, verify_candidate,
        )
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            source_evidence = consume(manifest, zip_path, real,
                                      native_vanilla263=True)
            candidate = verify_candidate(manifest, zip_path)
        except (OSError, UnicodeError, ValueError, _Refused):
            raise ObservationError("VANILLA_REAL_ARTIFACT_REFUSED") from None
        require(source_evidence.get("classification") ==
                "SOURCE_ARTIFACT_AND_INTENT_PARITY_VALIDATED" and
                source_evidence.get("candidate", {}).get("sha256") ==
                NATIVE_VANILLA263_ARTIFACT_SHA and
                source_evidence.get("real_provider_readback") is False and
                source_evidence.get("mutation_authorized") is False,
                "VANILLA_SOURCE_PARITY_NOT_ACCEPTED")
        requests = audience_requests(candidate, zip_path.name,
                                     native_vanilla263=True)
        require(len(requests) == 3 and
                [row["principal"]["kind"] for row in requests] ==
                ["human", "automation", "agent"],
                "VANILLA_THREE_AUDIENCE_CONTRACT_DRIFT")
        request = requests[1]  # unprivileged automation source-only actor
        require(request["target"]["deployment_id"] ==
                NATIVE_VANILLA263_APP and request["target"]["world_id"] ==
                NATIVE_VANILLA263_WORLD and
                request["target"]["service_id"] == SERVICE_UUID,
                "VANILLA_TARGET_OWNER_DRIFT")
        artifact_root = real
    else:
        source_plan = collage / "examples" / "source-only-rdte.json"
        fixture = collage / "examples" / "contract-only-world.fixture"
        require(source_plan.is_file() and fixture.is_file(),
                "SOURCE_ONLY_FIXTURE_UNAVAILABLE")
        request = json.loads(source_plan.read_text(encoding="utf-8"))
        request["request_id"] = "collage-p2-native-paper"
        request["target"].update({
            "deployment_id": OWNER, "service_id": SERVICE_UUID,
            "world_id": WORLD_ID, "minecraft_version": "1.21.11",
            "backend": "paper", "purpose": "generic",
        })
        request["artifact"].update({
            "world_id": WORLD_ID, "minecraft_version": "1.21.11",
        })
        artifact_root = collage
    source = state_dir / "collage-p2-request.json"
    source.write_text(json.dumps(request, indent=2, sort_keys=True) + "\n")
    key = provision_guest_readonly(call)
    trust = state_dir / "collage-p2-guest-cert.pem"
    hostname, cert_sha = discover_tls_anchor(https_port, trust)
    env = os.environ.copy()
    env["TRUENAS_API_KEY"] = key
    env["TRUENAS_PORT"] = str(https_port)
    env["SSL_CERT_FILE"] = str(trust)
    cmd = [sys.executable, str(collage / "tools" / "collage_native_readback.py"),
           "--request", str(source), "--artifact-root", str(artifact_root),
           "--host", hostname, "--username", NAME,
           "--trusted-realm-id", REALM,
           "--manager-id", "manager-rdte", "--fleet-id", "rdte"]
    try:
        p = subprocess.run(cmd, env=env, text=True, capture_output=True,
                           timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ObservationError("NATIVE_READONLY_CLIENT_UNAVAILABLE") from None
    # No raw stdout/stderr from clients or API; only extract declared schema.
    try:
        verdict = json.loads(p.stdout) if len(p.stdout) < 32768 else {}
    except ValueError:
        verdict = {}
    require(p.returncode == 0 and verdict.get("schema") == "collage.native-readback/1"
            and verdict.get("classification") == "PROVIDER_READBACK_MATCH"
            and verdict.get("mutation_authorized") is False
            and verdict.get("ownership_fields_matched") == 6
            and verdict.get("service_id") == SERVICE_UUID
            and verdict.get("native_app") ==
            (NATIVE_VANILLA263_APP if native_vanilla263 else OWNER) and
            verdict.get("truenas_version") ==
            ("25.04.2.6" if native_vanilla263 else "25.04.1") and
            verdict.get("world_id") ==
            (NATIVE_VANILLA263_WORLD if native_vanilla263 else WORLD_ID),
            "NATIVE_READONLY_GUEST_JOIN_FAILED")
    return {
        "schema": SCHEMA,
        "classification": "PROVIDER_READBACK_MATCH",
        "source_sha": expected_source_sha,
        "source_plan_sha256": verdict["source_plan_sha256"],
        "native_app": NATIVE_VANILLA263_APP if native_vanilla263 else OWNER,
        "truenas_version": verdict["truenas_version"],
        "service_id": SERVICE_UUID,
        "world_id": NATIVE_VANILLA263_WORLD if native_vanilla263 else WORLD_ID,
        "real_artifact_sha256_verified": (NATIVE_VANILLA263_ARTIFACT_SHA
                                           if native_vanilla263 else None),
        "native_vanilla263_source_profile": native_vanilla263,
        "ownership_fields_matched": 6,
        "tls_cert_sha256": cert_sha,
        "transport": "isolated_guest_tls_verified",
        "credential_scope": "APPS_READ",
        "credential_mutation_phase": "disposable_guest_setup_before_observation",
        "observation_mutation_count": 0,
        "world_artifact_format_verified": False,
        "two_rivers_gameplay_qualified": False,
        "world_activated": False,
        "cloudnet_adoption_executed": False,
        "physical_true_nas_mutated": False,
    }
