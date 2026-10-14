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
VANILLA263_OWNER = "rdte-t6-minecraft-vanilla-263"
VANILLA263_WORLD = "lantern-rdte"
VANILLA263_SOURCE_SHA = "2b6abe1141e65b8c6872eeba6c8ae39f5a9635f8"
DEFAULT_SOURCE_SHA = "fbda94f3fea0a216ddd9c35b38a09d325bed3640"


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



def scoped_key_expiry_ejson(now: dt.datetime | None = None) -> dict[str, int]:
    """One-hour UTC expiry in pinned TrueNAS legacy WebSocket EJSON format.

    TrueNAS api_client release/25.04.2.6/ejson.py serializes datetime as
    {"$date": UTC milliseconds}. The pinned middleware BaseModel has
    strict=True: a plain datetime.isoformat() string is rejected as type
    datetime by the 25.04.2.6 api_key.create input validator. Do not bypass
    expiration or change role/transport to avoid this type mismatch.
    """
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    require(type(now) is dt.datetime and now.tzinfo is not None and
            now.utcoffset() is not None,
            "SCOPED_KEY_EXPIRY_REQUIRES_AWARE_DATETIME")
    future = now.astimezone(dt.timezone.utc) + dt.timedelta(hours=1)
    # Exactly the UTC-second canonicalization in the frozen EJSON encoder.
    return {"$date": int(future.timestamp()) * 1000}


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
    # TrueNAS user.create returns a populated group reference (datastore ID)
    # but does not guarantee that it includes the Unix GID. Fetch the exact
    # group by its immutable internal ID before creating a privilege. Never
    # fall back to treating the database ID as POSIX GID.
    require(isinstance(group, dict) and type(group.get("id")) is int,
            "READONLY_ACCOUNT_PRIMARY_GROUP_ID_UNAVAILABLE")
    gid_record = call("group.query", [[["id", "=", group["id"]]], {"get": True}])
    require(type(gid_record) is dict and gid_record.get("id") == group["id"]
            and type(gid_record.get("gid")) is int and gid_record["gid"] >= 0
            and gid_record.get("local") is True,
            "READONLY_ACCOUNT_PRIMARY_GROUP_GID_UNAVAILABLE")
    group_gid = gid_record["gid"]
    # Exact TrueNAS 25.04.2.6 middleware privilege.create.local_groups
    # requires POSIX GIDs, NOT middleware account.group datastore IDs.
    # group.query(id=...) and user.query(group.id) still use datastore IDs.
    privilege = call("privilege.create", [{
        "name": ROLE_NAME, "local_groups": [group_gid],
        "roles": ["APPS_READ"], "web_shell": False,
    }])
    require(isinstance(privilege, dict) and privilege.get("name") == ROLE_NAME,
            "APPS_READ_ASSIGNMENT_UNVERIFIED")
    require(privilege.get("roles") == ["APPS_READ"],
            "CREATED_PRIVILEGE_ROLES_NOT_EXACT")
    members = privilege.get("local_groups")
    require(type(members) is list and len(members) == 1
            and type(members[0]) is dict
            and members[0].get("gid") == group_gid,
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
    # The 25.04.2.6 BaseModel is strict: a bare ISO string is NOT a
    # datetime in Python-mode validation. Legacy DDP uses extended JSON
    # {"$date": epoch_ms}; the pinned TrueNAS decoder turns it into a
    # timezone-aware datetime before API validation. Keep the one-hour TTL.
    expiry = scoped_key_expiry_ejson()
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


def exact_source_readback_request(plan: dict, *, profile: str) -> tuple[dict, str, str]:
    """Build only a read-only source intent; never establish artifact format.

    Use the already admitted COLLAGE source-only fixture for the provider
    ownership probe. This fixture is NOT a playable datapack and is never
    unpacked, applied or counted as real-world artifact deployment.
    """
    require(profile in {"paper", "vanilla263"}, "COLLAGE_READBACK_PROFILE_UNSUPPORTED")
    request = json.loads(json.dumps(plan))
    native = profile == "vanilla263"
    owner = VANILLA263_OWNER if native else OWNER
    world = VANILLA263_WORLD if native else WORLD_ID
    request["request_id"] = "collage-native-vanilla263-readonly" if native else "collage-p2-native-paper"
    request["target"].update({
        "deployment_id": owner, "service_id": SERVICE_UUID,
        "world_id": world, "minecraft_version": "26.3" if native else "1.21.11",
        "backend": "vanilla" if native else "paper", "purpose": "generic",
    })
    request["artifact"].update({
        "world_id": world, "minecraft_version": "26.3" if native else "1.21.11",
    })
    if native:
        # The source artifact remains an intentionally unplayable fixture.
        # This is permissible only for read-only provider observation, where
        # artifact_format_verified must remain false; not actual deployment.
        request["artifact"]["kind"] = "datapack"
    return request, owner, world


# Fixed, non-secret RPC names and call order. No untrusted exception message
# or credential ever crosses into public job evidence. The prior real 005 guest
# failed with generic RuntimeError, masking WHICH guest RBAC API rejected.
RBAC_CALL_SEQUENCE = (
    ("user.query", "precheck_user"),
    ("privilege.query", "precheck_privilege"),
    ("privilege.roles", "discover_roles"),
    ("user.create", "create_user"),
    ("group.query", "resolve_group_gid"),
    ("privilege.create", "grant_apps_read"),
    ("group.query", "check_group_roles"),
    ("user.query", "check_user_roles"),
    ("api_key.create", "issue_scoped_key"),
)



# Fixed allowlist only: TrueNAS 25.04 serializes ValidationErrors as
# errno 11 with type=VALIDATION and extra [attribute, message, errno] tuples.
# Attribute strings not explicitly listed here may never appear in receipts.
_VALIDATION_FIELDS = {
    "api_key_create": "GENERAL",
    "api_key_create.name": "NAME",
    "api_key_create.username": "USERNAME",
    "api_key_create.expires_at": "EXPIRES_AT",
}


def scoped_validation_field_suffix(obj: dict) -> str:
    """Classify only a recognized validation field, never its message/value."""
    if obj.get("type") != "VALIDATION":
        return ""
    extra = obj.get("extra")
    if type(extra) is not list or not (1 <= len(extra) <= 12):
        return "_VALIDATION_FIELD_UNKNOWN"
    categories = set()
    for item in extra:
        if type(item) is not list or len(item) != 3:
            return "_VALIDATION_FIELD_UNKNOWN"
        field = item[0]
        if type(field) is not str or field not in _VALIDATION_FIELDS:
            return "_VALIDATION_FIELD_UNKNOWN"
        categories.add(_VALIDATION_FIELDS[field])
    return ("_VALIDATION_" + next(iter(categories))) if len(categories) == 1 else "_VALIDATION_MULTI"


def scoped_key_record_count_suffix(call) -> str:
    """Read-only exact owned key count once; no listing, retries or disclosure."""
    try:
        count = call("api_key.query", [
            [["username", "=", NAME], ["name", "=", "disposable-collage-p2"]],
            {"count": True},
        ])
    except Exception:
        return "_KEY_COUNT_UNAVAILABLE"
    if type(count) is not int or count < 0:
        return "_KEY_COUNT_INVALID"
    if count == 0:
        return "_KEY_COUNT0"
    if count == 1:
        return "_KEY_COUNT1"
    return "_KEY_COUNT_MULTIPLE"


def classify_scoped_key_ddp_failure(exc: Exception) -> str:
    """Only fixed failure categories or allowlisted DDP codes leave the guest.

    In addition to provider rejection, this RPC can time out while TrueNAS
    performs password hash/PAM generation. Timeouts are indeterminate: the
    key might already exist, so the caller must never retry issuance blindly.
    Error messages, principal metadata and secret values remain private.
    """
    if isinstance(exc, TimeoutError):
        return "_TRANSPORT_TIMEOUT_INDETERMINATE"
    if isinstance(exc, (ConnectionError, EOFError)):
        return "_TRANSPORT_DISCONNECTED"
    if isinstance(exc, OSError):
        return "_TRANSPORT_IO_FAILURE"
    if type(exc) is not RuntimeError or not exc.args or type(exc.args[0]) is not str:
        return "_LOCAL_UNEXPECTED_FAILURE"
    data = exc.args[0]
    prefix = "api_key.create: "
    if not data.startswith(prefix):
        return "_DDP_UNSTRUCTURED_ERROR"
    # Native 008 returned an oversized *structured* error after 119 s
    # overall successful world staging. Keep the parser size-bounded, but
    # inspect an error object of realistic traceback size in memory so the
    # fixed allowlist can classify the DDP numeric code. Never publish the
    # remote reason/trace/details, even when malicious or unusually long.
    if len(data) > 262144:
        return "_DDP_OVERSIZE_ERROR"
    try:
        obj = json.loads(data[len(prefix):])
    except (ValueError, RecursionError):
        return "_DDP_MALFORMED_ERROR"
    if type(obj) is not dict:
        return "_DDP_NONOBJECT_ERROR"
    code = obj.get("error")
    if type(code) is int and code in {1, 2, 5, 11, 13, 17, 22, 38, 400, 401, 403, 404, 409, 422, 500, 503}:
        return "_E" + str(code) + scoped_validation_field_suffix(obj)
    if type(code) is str and code in {"EINVAL","EPERM","EACCES","VALIDATION_ERRORS","METHOD_NOT_FOUND"}:
        return "_" + code
    if type(code) is dict:
        # Middleware may nest its code/error/errno fields beneath error.
        # At most one level, with a hardcoded numeric-only allowlist; never
        # derive a public string from untrusted remote metadata.
        nested = code.get("errno")
        if type(nested) is not int:
            nested = code.get("error")
        if type(nested) is int and nested in {1, 2, 5, 11, 13, 17, 22, 38, 400, 401, 403, 404, 409, 422, 500, 503}:
            return "_E" + str(nested)
        return "_DDP_NESTED_ERROR"
    if type(code) is list:
        return "_DDP_VALIDATION_LIST"
    return "_DDP_UNRECOGNIZED_CODE"



def bounded_rbac_call(call):
    position = 0

    def invoke(method, params):
        nonlocal position
        require(position < len(RBAC_CALL_SEQUENCE) and
                method == RBAC_CALL_SEQUENCE[position][0],
                "GUEST_RBAC_API_SEQUENCE_DRIFT")
        operation = RBAC_CALL_SEQUENCE[position][1]
        position += 1
        try:
            return call(method, params)
        except Exception as exc:
            suffix = (classify_scoped_key_ddp_failure(exc)
                      if operation == "issue_scoped_key" else "")
            if operation == "issue_scoped_key" and (
                    suffix.startswith("_E11") or
                    suffix == "_TRANSPORT_TIMEOUT_INDETERMINATE"):
                # A failed issuance may be indeterminate. One exact, read-only
                # count only; never retry api_key.create or fetch key records.
                suffix += scoped_key_record_count_suffix(call)
            raise ObservationError("GUEST_RBAC_" + operation.upper() +
                                   "_API_FAILED" + suffix) from None
    return invoke


def run_real_readback(call, *, collage: pathlib.Path, https_port: int,
                      state_dir: pathlib.Path, expected_source_sha: str
                      = DEFAULT_SOURCE_SHA, profile: str = "paper") -> dict:
    """Return ONLY allowlisted, non-secret independent readback evidence."""
    require(collage.is_dir(), "PINNED_COLLAGE_CHECKOUT_MISSING")
    git = subprocess.run(["git", "-C", str(collage), "rev-parse", "HEAD"],
                         text=True, capture_output=True, timeout=5)
    require(git.returncode == 0 and git.stdout.strip() == expected_source_sha,
            "PINNED_COLLAGE_COMMIT_DRIFT")
    source_plan = collage / "examples" / "source-only-rdte.json"
    fixture = collage / "examples" / "contract-only-world.fixture"
    require(source_plan.is_file() and fixture.is_file(),
            "SOURCE_ONLY_FIXTURE_UNAVAILABLE")
    request, expected_owner, expected_world = exact_source_readback_request(
        json.loads(source_plan.read_text(encoding="utf-8")), profile=profile)
    if profile == "vanilla263":
        require(expected_source_sha == VANILLA263_SOURCE_SHA,
                "VANILLA263_COLLAGE_SOURCE_REF_DRIFT")
    source = state_dir / "collage-p2-request.json"
    source.write_text(json.dumps(request, indent=2, sort_keys=True) + "\n")
    key = provision_guest_readonly(bounded_rbac_call(call))
    trust = state_dir / "collage-p2-guest-cert.pem"
    hostname, cert_sha = discover_tls_anchor(https_port, trust)
    env = os.environ.copy()
    env["TRUENAS_API_KEY"] = key
    env["TRUENAS_PORT"] = str(https_port)
    env["SSL_CERT_FILE"] = str(trust)
    cmd = [sys.executable, str(collage / "tools" / "collage_native_readback.py"),
           "--request", str(source), "--artifact-root", str(collage),
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
            and verdict.get("native_app") == expected_owner
            and verdict.get("world_id") == expected_world,
            "NATIVE_READONLY_GUEST_JOIN_FAILED")
    return {
        "schema": SCHEMA,
        "classification": "PROVIDER_READBACK_MATCH",
        "source_sha": expected_source_sha,
        "source_plan_sha256": verdict["source_plan_sha256"],
        "native_app": expected_owner,
        "truenas_version": verdict["truenas_version"],
        "service_id": SERVICE_UUID,
        "world_id": expected_world,
        "ownership_fields_matched": 6,
        "tls_cert_sha256": cert_sha,
        "transport": "isolated_guest_tls_verified",
        "credential_scope": "APPS_READ",
        "source_profile": profile,
        "credential_mutation_phase": "disposable_guest_setup_before_observation",
        "observation_mutation_count": 0,
        "world_artifact_format_verified": False,
        "two_rivers_gameplay_qualified": False,
        "world_activated": False,
        "cloudnet_adoption_executed": False,
        "physical_true_nas_mutated": False,
    }
