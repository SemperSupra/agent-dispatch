#!/usr/bin/env python3
"""G4 oracle: exact provider capacity-two concurrency/reconnect/retirement on nested TrueNAS."""
from __future__ import annotations

import argparse
import concurrent.futures
import copy
import json
import os
import pathlib
import secrets
import subprocess
import tempfile
import time

import truenas_middleware_garm_provider_g2_probe as g2
import truenas_middleware_garm_provider_g3_probe as g3


EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"
EXPECTED_APPLIANCE = g3.EXPECTED_APPLIANCE
EXPECTED_PROVIDER_PRODUCT_SOURCE = g3.EXPECTED_PROVIDER_PRODUCT_SOURCE
EXPECTED_PROVIDER_BINARY_SHA256 = g3.EXPECTED_PROVIDER_BINARY_SHA256
EXPECTED_FIXTURE_SCHEMA = "semper-supra.garm-provider-truenas-g4-capacity-two-fixture/1"
EXPECTED_CONTROLLER_ID = "g4-controller"
EXPECTED_POOL_ID = "g4-pool"
EXPECTED_RUNNER_IMAGE = (
    "ghcr.io/actions/actions-runner:2.336.0@"
    "sha256:0cfdcc701ce933c6d243c6b0b2da767366dc9f2e99961d4c3754b0b78084cdda"
)
EXPECTED_CPU = 4
EXPECTED_MEMORY_BYTES = 8 * 1024 * 1024 * 1024
IX_APPS_PATH = "/mnt/.ix-apps"
SLOTS = ("alpha", "beta")
EXPECTED_SUBSTITUTIONS = [
    "runners[0].bootstrap_template.callback-url",
    "runners[0].bootstrap_template.metadata-url",
    "runners[0].bootstrap_template.instance-token",
    "runners[0].expected_compose_template.services.runner.environment.GARM_CALLBACK_URL",
    "runners[0].expected_compose_template.services.runner.environment.GARM_METADATA_URL",
    "runners[0].expected_compose_template.services.runner.environment.GARM_INSTANCE_TOKEN",
    "runners[1].bootstrap_template.callback-url",
    "runners[1].bootstrap_template.metadata-url",
    "runners[1].bootstrap_template.instance-token",
    "runners[1].expected_compose_template.services.runner.environment.GARM_CALLBACK_URL",
    "runners[1].expected_compose_template.services.runner.environment.GARM_METADATA_URL",
    "runners[1].expected_compose_template.services.runner.environment.GARM_INSTANCE_TOKEN",
]


def fixture_urls(slot: str) -> tuple[str, str]:
    callback = f"https://httpbin.org/anything/sempersupra-g4/{slot}/status"
    metadata = (
        "https://httpbin.org/drip?duration=1&numbytes=1&code=200&delay=60&path="
        + slot
    )
    return callback, metadata


def load_bundle(directory: pathlib.Path, expected_producer: str) -> dict:
    path = directory / "garm-provider-g4-fixture.json"
    bundle = json.loads(path.read_text(encoding="utf-8"))
    if bundle.get("schema") != EXPECTED_FIXTURE_SCHEMA:
        raise RuntimeError("unexpected G4 fixture schema")
    if bundle.get("provider_product_source") != EXPECTED_PROVIDER_PRODUCT_SOURCE:
        raise RuntimeError("G4 fixture product source drifted")
    if bundle.get("producer_source") != expected_producer:
        raise RuntimeError("G4 fixture producer source drifted")
    if bundle.get("controller_id") != EXPECTED_CONTROLLER_ID:
        raise RuntimeError("G4 fixture controller identity drifted")
    if bundle.get("pool_id") != EXPECTED_POOL_ID:
        raise RuntimeError("G4 fixture pool identity drifted")
    if bundle.get("run_local_substitutions") != EXPECTED_SUBSTITUTIONS:
        raise RuntimeError("G4 run-local substitution allowlist drifted")
    runners = bundle.get("runners")
    if not isinstance(runners, list) or len(runners) != 2:
        raise RuntimeError("G4 fixture must contain exactly two runners")
    if [r.get("slot") for r in runners if isinstance(r, dict)] != list(SLOTS):
        raise RuntimeError("G4 fixture slot identities drifted")
    names = [r.get("expected_app_name") for r in runners]
    if not all(isinstance(name, str) and name for name in names) or len(set(names)) != 2:
        raise RuntimeError("G4 fixture App identities are absent or aliased")
    runner = bundle.get("runner")
    if not isinstance(runner, dict):
        raise RuntimeError("G4 fixture runner contract absent")
    if runner.get("image") != EXPECTED_RUNNER_IMAGE:
        raise RuntimeError("G4 runner image drifted")
    if runner.get("cpu") != EXPECTED_CPU or runner.get("memory_bytes") != EXPECTED_MEMORY_BYTES:
        raise RuntimeError("G4 fixed resource profile drifted")
    if bundle.get("retirement_orders") != [["alpha", "beta"], ["beta", "alpha"]]:
        raise RuntimeError("G4 retirement-order contract drifted")
    return bundle


def lower_runner(runner: dict, callback: str, metadata: str, token: str) -> tuple[dict, dict]:
    bootstrap = copy.deepcopy(runner["bootstrap_template"])
    expected = copy.deepcopy(runner["expected_compose_template"])
    bootstrap["callback-url"] = callback
    bootstrap["metadata-url"] = metadata
    bootstrap["instance-token"] = token
    env = expected["services"]["runner"]["environment"]
    env["GARM_CALLBACK_URL"] = callback
    env["GARM_METADATA_URL"] = metadata
    env["GARM_INSTANCE_TOKEN"] = token
    return bootstrap, expected


def provider_env(
    config_path: pathlib.Path,
    api_key: str,
    ca_path: pathlib.Path,
    command: str,
    instance_id: str | None = None,
) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "GARM_INTERFACE_VERSION": "v0.1.1",
        "GARM_COMMAND": command,
        "GARM_CONTROLLER_ID": EXPECTED_CONTROLLER_ID,
        "GARM_POOL_ID": EXPECTED_POOL_ID,
        "GARM_PROVIDER_CONFIG_FILE": str(config_path),
        "TRUENAS_API_KEY": api_key,
        "SSL_CERT_FILE": str(ca_path),
    })
    if instance_id:
        env["GARM_INSTANCE_ID"] = instance_id
    else:
        env.pop("GARM_INSTANCE_ID", None)
    return env


def invoke_provider(
    provider_binary: pathlib.Path,
    config_path: pathlib.Path,
    api_key: str,
    ca_path: pathlib.Path,
    command: str,
    *,
    instance_id: str | None = None,
    stdin_object: dict | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(provider_binary)],
        env=provider_env(config_path, api_key, ca_path, command, instance_id),
        input=(json.dumps(stdin_object) if stdin_object is not None else None),
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )


def scrub_text(text: str, sensitive: list[str]) -> str:
    out = text
    for value in sensitive:
        if value:
            out = out.replace(value, "<redacted>")
    return out


def parse_provider_json(
    cp: subprocess.CompletedProcess[str],
    label: str,
    sensitive: list[str],
):
    if cp.returncode != 0:
        detail = scrub_text((cp.stderr or cp.stdout or "")[-1600:], sensitive)
        raise RuntimeError(f"{label} failed rc={cp.returncode}: {detail}")
    text = cp.stdout.strip()
    if not text:
        raise RuntimeError(f"{label} returned empty stdout")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} stdout was not JSON") from exc


def list_ids(
    provider_binary: pathlib.Path,
    config_path: pathlib.Path,
    api_key: str,
    ca_path: pathlib.Path,
    sensitive: list[str],
) -> list[str]:
    cp = invoke_provider(
        provider_binary, config_path, api_key, ca_path, "ListInstances"
    )
    listed = parse_provider_json(cp, "ListInstances", sensitive)
    if not isinstance(listed, list):
        raise RuntimeError("ListInstances did not return an array")
    return sorted(
        str(item.get("provider_id"))
        for item in listed
        if isinstance(item, dict)
    )


def get_instance(
    provider_binary: pathlib.Path,
    config_path: pathlib.Path,
    api_key: str,
    ca_path: pathlib.Path,
    app_name: str,
    sensitive: list[str],
) -> dict:
    cp = invoke_provider(
        provider_binary,
        config_path,
        api_key,
        ca_path,
        "GetInstance",
        instance_id=app_name,
    )
    got = parse_provider_json(cp, f"GetInstance {app_name}", sensitive)
    if not isinstance(got, dict) or got.get("provider_id") != app_name:
        raise RuntimeError(f"GetInstance identity drifted for {app_name}")
    return got


def delete_instance(
    provider_binary: pathlib.Path,
    config_path: pathlib.Path,
    api_key: str,
    ca_path: pathlib.Path,
    app_name: str,
    sensitive: list[str],
) -> None:
    cp = invoke_provider(
        provider_binary,
        config_path,
        api_key,
        ca_path,
        "DeleteInstance",
        instance_id=app_name,
    )
    if cp.returncode != 0:
        detail = scrub_text((cp.stderr or cp.stdout or "")[-1600:], sensitive)
        raise RuntimeError(f"DeleteInstance {app_name} failed rc={cp.returncode}: {detail}")


def require_active_delete_refusal(
    provider_binary: pathlib.Path,
    config_path: pathlib.Path,
    api_key: str,
    ca_path: pathlib.Path,
    app_name: str,
    sensitive: list[str],
    session: g2.AdminSession,
) -> None:
    cp = invoke_provider(
        provider_binary,
        config_path,
        api_key,
        ca_path,
        "DeleteInstance",
        instance_id=app_name,
    )
    if cp.returncode == 0:
        raise RuntimeError("provider unexpectedly deleted an active runner")
    if g3.query_app(session, app_name) is None:
        raise RuntimeError("active-delete refusal lost the target App")


def statfs_available(session: g2.AdminSession) -> int:
    data = session.call("filesystem.statfs", [IX_APPS_PATH])
    if not isinstance(data, dict) or not isinstance(data.get("avail_bytes"), int):
        raise RuntimeError("filesystem.statfs did not return avail_bytes")
    return int(data["avail_bytes"])


def verify_realized_pair(
    session: g2.AdminSession,
    provider_binary: pathlib.Path,
    config_path: pathlib.Path,
    api_key: str,
    cert_path: pathlib.Path,
    lowered: dict[str, dict],
    sensitive: list[str],
) -> None:
    expected_ids = sorted(v["app_name"] for v in lowered.values())
    for slot in SLOTS:
        item = lowered[slot]
        config = session.call("app.config", [item["app_name"]])
        if not isinstance(config, dict):
            raise RuntimeError(f"app.config did not return an object for {slot}")
        realized_sha = g2.canonical_json_sha256(config)
        expected_sha = g2.canonical_json_sha256(item["expected_compose"])
        if realized_sha != expected_sha:
            raise RuntimeError(f"exact Compose read-back drifted for {slot}")
        get_instance(
            provider_binary,
            config_path,
            api_key,
            cert_path,
            item["app_name"],
            sensitive,
        )
    ids = list_ids(
        provider_binary, config_path, api_key, cert_path, sensitive
    )
    if ids != expected_ids:
        raise RuntimeError(f"provider pair inventory drifted: {ids} != {expected_ids}")


def create_pair(
    provider_binary: pathlib.Path,
    config_path: pathlib.Path,
    api_key: str,
    cert_path: pathlib.Path,
    lowered: dict[str, dict],
    sensitive: list[str],
) -> None:
    def create(slot: str):
        item = lowered[slot]
        cp = invoke_provider(
            provider_binary,
            config_path,
            api_key,
            cert_path,
            "CreateInstance",
            stdin_object=item["bootstrap"],
        )
        return slot, parse_provider_json(cp, f"CreateInstance {slot}", sensitive)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, SLOTS))
    for slot, created in results:
        if not isinstance(created, dict):
            raise RuntimeError(f"CreateInstance {slot} did not return an object")
        if created.get("provider_id") != lowered[slot]["app_name"]:
            raise RuntimeError(f"CreateInstance identity drifted for {slot}")


def retire_order(
    order: tuple[str, str],
    session: g2.AdminSession,
    provider_binary: pathlib.Path,
    config_path: pathlib.Path,
    api_key: str,
    cert_path: pathlib.Path,
    lowered: dict[str, dict],
    sensitive: list[str],
) -> dict:
    first, second = order
    first_name = lowered[first]["app_name"]
    second_name = lowered[second]["app_name"]

    first_state = g3.ensure_inactive(session, first_name, 300.0)
    delete_instance(
        provider_binary, config_path, api_key, cert_path, first_name, sensitive
    )
    if g3.query_app(session, first_name) is not None:
        raise RuntimeError(f"{first} App remains after provider DeleteInstance")
    peer = g3.query_app(session, second_name)
    if peer is None:
        raise RuntimeError(f"retiring {first} corrupted peer {second}")
    peer_state = str(peer.get("state") or "")
    ids = list_ids(
        provider_binary, config_path, api_key, cert_path, sensitive
    )
    if ids != [second_name]:
        raise RuntimeError(f"peer inventory drifted after retiring {first}: {ids}")

    second_state = g3.ensure_inactive(session, second_name, 300.0)
    delete_instance(
        provider_binary, config_path, api_key, cert_path, second_name, sensitive
    )
    if g3.query_app(session, second_name) is not None:
        raise RuntimeError(f"{second} App remains after provider DeleteInstance")
    if list_ids(provider_binary, config_path, api_key, cert_path, sensitive) != []:
        raise RuntimeError("provider inventory not empty after pair retirement")
    return {
        "order": [first, second],
        "first_inactive_state": first_state,
        "peer_state_after_first_retirement": peer_state,
        "second_inactive_state": second_state,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--http-port", type=int, required=True)
    p.add_argument("--https-port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    p.add_argument("--fixture-producer-commit", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    a = p.parse_args()

    started = time.time()
    payload = {
        "schema": "truenas-garm-provider-g4/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "expected_version": EXPECTED_VERSION,
        "provider_product_source": EXPECTED_PROVIDER_PRODUCT_SOURCE,
        "provider_binary_sha256": EXPECTED_PROVIDER_BINARY_SHA256,
        "appliance": EXPECTED_APPLIANCE,
        "controller_id": EXPECTED_CONTROLLER_ID,
        "pool_id": EXPECTED_POOL_ID,
        "runner_count": 2,
        "github_credentials_present": False,
        "github_jit_registration_exercised": False,
        "private_repository_execution": False,
        "physical_truenas_mutation": False,
        "capacity_promotion": False,
        "secret_values_recorded": False,
        "synthetic_tokens_recorded": False,
    }

    if g2.EXPECTED_APPLIANCE != EXPECTED_APPLIANCE:
        raise RuntimeError("G2 helper appliance identity drifted")
    if g2.EXPECTED_PROVIDER_BINARY_SHA256 != EXPECTED_PROVIDER_BINARY_SHA256:
        raise RuntimeError("G2 helper provider binary identity drifted")

    password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()
    session = g2.AdminSession(a.host, a.http_port, password, a.timeout)
    api_key_id: int | None = None
    api_key_value: str | None = None
    imported_cert_id: int | None = None
    original_ui_cert_id: int | None = None
    app_names: list[str] = []
    fallback_cleanup_used = False
    cleanup_errors: list[str] = []
    sensitive: list[str] = []

    with tempfile.TemporaryDirectory(prefix="garm-provider-g4-") as td:
        root = pathlib.Path(td)
        try:
            bundle = load_bundle(a.fixture_dir, a.fixture_producer_commit)
            payload["fixture_producer_source"] = bundle["producer_source"]
            payload["fixture_bundle_sha256"] = g2.sha256_file(
                a.fixture_dir / "garm-provider-g4-fixture.json"
            )
            payload["source_oracles"] = bundle.get("source_oracles", {})
            payload["retirement_orders"] = bundle["retirement_orders"]
            payload["configured_resource_envelope"] = {
                "per_runner_cpu_limit": EXPECTED_CPU,
                "per_runner_memory_bytes": EXPECTED_MEMORY_BYTES,
                "runner_count": 2,
                "aggregate_cpu_limit_units": EXPECTED_CPU * 2,
                "aggregate_memory_limit_bytes": EXPECTED_MEMORY_BYTES * 2,
                "limits_are_not_reservations": True,
            }

            lowered: dict[str, dict] = {}
            for runner in bundle["runners"]:
                slot = runner["slot"]
                callback, metadata = fixture_urls(slot)
                g3.preflight_public_fixture(callback, metadata, a.timeout)
                token = f"g4-{slot}-{secrets.token_hex(12)}"
                sensitive.append(token)
                bootstrap, expected = lower_runner(
                    runner, callback, metadata, token
                )
                lowered[slot] = {
                    "app_name": runner["expected_app_name"],
                    "callback_url": callback,
                    "metadata_url": metadata,
                    "bootstrap": bootstrap,
                    "expected_compose": expected,
                }
                app_names.append(runner["expected_app_name"])
            payload["synthetic_fixture_preflight"] = True
            payload["expected_app_names"] = sorted(app_names)
            payload["callback_metadata_isolation"] = {
                slot: {
                    "callback_url": lowered[slot]["callback_url"],
                    "metadata_url": lowered[slot]["metadata_url"],
                }
                for slot in SLOTS
            }

            provider_binary = g2.extract_provider_binary(root)
            payload["provider_binary_from_appliance"] = True

            cert_path, key_path = g2.generate_tls(root)
            payload["transport"] = {
                "scheme": "wss",
                "host": a.host,
                "port": a.https_port,
                "insecure_skip_verify": False,
                "certificate_sha256": g2.sha256_file(cert_path),
                "private_key_recorded": False,
                "api_key_recorded": False,
            }

            session.connect()
            version = session.call("system.version", [])
            payload["system_version"] = version
            if version != EXPECTED_VERSION:
                raise RuntimeError(f"target version drifted: {version}")

            general = session.call("system.general.config", [])
            original_ui_cert_id = g2.ui_cert_id(general.get("ui_certificate"))
            api_key = session.call("api_key.create", [{
                "name": f"g4-provider-{secrets.token_hex(5)}",
                "username": "truenas_admin",
            }])
            if not isinstance(api_key, dict) or not isinstance(api_key.get("id"), int):
                raise RuntimeError("api_key.create did not return an id")
            api_key_id = int(api_key["id"])
            api_key_value = api_key.get("key")
            if not isinstance(api_key_value, str) or not api_key_value:
                raise RuntimeError("api_key.create did not return a key")
            sensitive.append(api_key_value)

            create_cert_id = session.call("certificate.create", [{
                "name": f"g4_provider_{secrets.token_hex(4)}",
                "create_type": "CERTIFICATE_CREATE_IMPORTED",
                "add_to_trusted_store": False,
                "certificate": cert_path.read_text(encoding="utf-8"),
                "privatekey": key_path.read_text(encoding="utf-8"),
            }])
            if not isinstance(create_cert_id, int):
                raise RuntimeError("certificate.create did not return a job id")
            cert_job = session.wait_job(
                create_cert_id, "certificate.create", a.job_timeout
            )
            cert_result = cert_job.get("result")
            if not isinstance(cert_result, dict) or not isinstance(cert_result.get("id"), int):
                raise RuntimeError("certificate.create job did not return certificate id")
            imported_cert_id = int(cert_result["id"])

            session.call("system.general.update", [{"ui_certificate": imported_cert_id}])
            try:
                session.call("system.general.ui_restart", [0])
            except Exception:
                pass
            session.close()
            g2.wait_verified_https(a.host, a.https_port, cert_path)

            provider_config = {
                "mode": "truenas",
                "truenas": {
                    "host": a.host,
                    "username": "truenas_admin",
                    "api_key_env": "TRUENAS_API_KEY",
                    "port": a.https_port,
                    "insecure_skip_verify": False,
                    "callback_host_gateway": False,
                },
            }
            config_path = root / "provider.json"
            config_path.write_text(
                json.dumps(provider_config, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            config_path.chmod(0o600)

            session.connect()
            storage_before = statfs_available(session)

            cycle_receipts = []
            for cycle, order in enumerate((("alpha", "beta"), ("beta", "alpha")), start=1):
                cycle_tokens = []
                cycle_lowered = {}
                for slot in SLOTS:
                    callback, metadata = fixture_urls(slot)
                    token = f"g4-cycle{cycle}-{slot}-{secrets.token_hex(12)}"
                    sensitive.append(token)
                    cycle_tokens.append(token)
                    source_runner = next(
                        item for item in bundle["runners"] if item["slot"] == slot
                    )
                    bootstrap, expected = lower_runner(
                        source_runner, callback, metadata, token
                    )
                    cycle_lowered[slot] = {
                        "app_name": source_runner["expected_app_name"],
                        "bootstrap": bootstrap,
                        "expected_compose": expected,
                    }

                create_pair(
                    provider_binary,
                    config_path,
                    api_key_value,
                    cert_path,
                    cycle_lowered,
                    sensitive,
                )
                verify_realized_pair(
                    session,
                    provider_binary,
                    config_path,
                    api_key_value,
                    cert_path,
                    cycle_lowered,
                    sensitive,
                )
                storage_two_apps = statfs_available(session)

                # Each command is a fresh provider process. This List/Get pass is
                # the explicit reconnect/adoption observation with both Apps present.
                reconnect_ids = list_ids(
                    provider_binary,
                    config_path,
                    api_key_value,
                    cert_path,
                    sensitive,
                )
                if reconnect_ids != sorted(app_names):
                    raise RuntimeError(
                        f"fresh-process reconnect inventory drifted: {reconnect_ids}"
                    )
                for name in app_names:
                    get_instance(
                        provider_binary,
                        config_path,
                        api_key_value,
                        cert_path,
                        name,
                        sensitive,
                    )

                if cycle == 1:
                    require_active_delete_refusal(
                        provider_binary,
                        config_path,
                        api_key_value,
                        cert_path,
                        cycle_lowered["alpha"]["app_name"],
                        sensitive,
                        session,
                    )
                    if g3.query_app(session, cycle_lowered["beta"]["app_name"]) is None:
                        raise RuntimeError("active-delete refusal corrupted peer App")

                retirement = retire_order(
                    order,
                    session,
                    provider_binary,
                    config_path,
                    api_key_value,
                    cert_path,
                    cycle_lowered,
                    sensitive,
                )
                storage_after = statfs_available(session)
                cycle_receipts.append({
                    "cycle": cycle,
                    "retirement": retirement,
                    "storage": {
                        "ix_apps_avail_bytes_before_pair": storage_before,
                        "ix_apps_avail_bytes_with_two_apps": storage_two_apps,
                        "ix_apps_avail_bytes_after_retirement": storage_after,
                        "consumed_bytes_at_two_apps": max(
                            0, storage_before - storage_two_apps
                        ),
                        "residual_consumed_bytes_after_retirement": max(
                            0, storage_before - storage_after
                        ),
                    },
                })
                storage_before = storage_after

            payload["cycles"] = cycle_receipts
            payload["oracles"] = {
                "verified_tls_transport": True,
                "api_key_auth_transport": True,
                "two_concurrent_create_calls_returned_distinct_owned_identities": True,
                "exact_realized_compose_readback_both": True,
                "fresh_process_get_list_exact_pair": True,
                "callback_metadata_config_isolated": True,
                "active_delete_refused_without_peer_corruption": True,
                "retirement_alpha_then_beta": True,
                "retirement_beta_then_alpha": True,
                "post_retirement_apps_absent": True,
                "post_retirement_provider_inventory_empty": True,
                "storage_delta_measured": True,
                "github_registration_not_exercised": True,
            }
            payload["classification"] = "SUPPORTED"
            payload["oracleSatisfied"] = True
            payload["detail"] = (
                "exact packaged provider realized two concurrent source-derived runner Apps "
                "on nested TrueNAS; both exact Compose profiles, isolated bootstrap configuration, "
                "fresh-process Get/List adoption, active-delete refusal, both retirement orders, "
                "empty final inventory, App absence, and bounded ix-apps storage deltas were "
                "verified without GitHub/JIT/private/physical/capacity authority"
            )
        except g3.FixtureEnvironmentError as exc:
            payload["classification"] = "ENVIRONMENT_FAILURE"
            payload["detail"] = scrub_text(str(exc), sensitive)
        except Exception as exc:
            payload["detail"] = scrub_text(
                f"{type(exc).__name__}: {exc}", sensitive
            )
        finally:
            try:
                session.connect()
                for name in sorted(set(app_names)):
                    if g3.query_app(session, name) is not None:
                        fallback_cleanup_used = True
                        try:
                            g2.delete_app_if_present(session, name, a.job_timeout)
                        except Exception as exc:
                            cleanup_errors.append(
                                f"fallback delete {name}: {type(exc).__name__}: {exc}"
                            )
                for name in sorted(set(app_names)):
                    try:
                        if g3.query_app(session, name) is not None:
                            cleanup_errors.append(
                                f"provider-created App remains after cleanup: {name}"
                            )
                    except Exception as exc:
                        cleanup_errors.append(
                            f"verify App absence {name}: {type(exc).__name__}: {exc}"
                        )

                if api_key_id is not None:
                    try:
                        deleted = session.call("api_key.delete", [api_key_id])
                        if deleted is not True:
                            cleanup_errors.append("api_key.delete did not return true")
                    except Exception as exc:
                        cleanup_errors.append(
                            f"api_key.delete: {type(exc).__name__}: {exc}"
                        )
                    api_key_value = None

                if original_ui_cert_id is not None and imported_cert_id is not None:
                    try:
                        session.call(
                            "system.general.update",
                            [{"ui_certificate": original_ui_cert_id}],
                        )
                        try:
                            session.call("system.general.ui_restart", [0])
                        except Exception:
                            pass
                    except Exception as exc:
                        cleanup_errors.append(
                            f"restore ui certificate: {type(exc).__name__}: {exc}"
                        )
                    session.close()
                    time.sleep(5)
                    try:
                        session.connect()
                    except Exception as exc:
                        cleanup_errors.append(
                            f"reconnect after ui restore: {type(exc).__name__}: {exc}"
                        )

                if imported_cert_id is not None and session.ws is not None:
                    try:
                        delete_result = session.call(
                            "certificate.delete", [imported_cert_id, False]
                        )
                        if isinstance(delete_result, int):
                            session.wait_job(
                                delete_result, "certificate.delete", a.job_timeout
                            )
                        elif delete_result is not True:
                            cleanup_errors.append(
                                f"certificate.delete unexpected result {delete_result!r}"
                            )
                    except Exception as exc:
                        cleanup_errors.append(
                            f"certificate.delete: {type(exc).__name__}: {exc}"
                        )
            except Exception as exc:
                cleanup_errors.append(
                    f"cleanup session: {type(exc).__name__}: {exc}"
                )
            finally:
                session.close()

    payload["cleanup"] = {
        "attempted": True,
        "fallback_cleanup_used": fallback_cleanup_used,
        "errors": cleanup_errors,
        "zero_unintended_residue": not cleanup_errors,
        "secret_values_recorded": False,
        "synthetic_tokens_recorded": False,
    }
    if cleanup_errors or fallback_cleanup_used:
        payload["oracleSatisfied"] = False
        payload["classification"] = "ORACLE_FAILURE"
        reasons = []
        if fallback_cleanup_used:
            reasons.append("provider retirement required fallback direct cleanup")
        reasons.extend(cleanup_errors)
        payload["detail"] = payload.get("detail", "") + "; cleanup: " + "; ".join(reasons)

    payload["elapsed_seconds"] = round(time.time() - started, 3)
    pathlib.Path(a.out).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
