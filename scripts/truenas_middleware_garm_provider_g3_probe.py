#!/usr/bin/env python3
"""G3 oracle: exact provider-created runner App to the synthetic GitHub credential boundary."""
from __future__ import annotations

import argparse
import copy
import json
import os
import pathlib
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import truenas_middleware_garm_provider_g2_probe as g2


EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"
EXPECTED_APPLIANCE = (
    "ghcr.io/sempersupra/garm-appliance@"
    "sha256:1af67841ddd4589e3798dcda8be49230565c849d07ab57fd05899432dcdabca9"
)
EXPECTED_PROVIDER_PRODUCT_SOURCE = "14535745dc3aa3c0b5466da7c704bca4d23dcec5"
EXPECTED_PROVIDER_BINARY_SHA256 = "911f076ba9421f7bb2a1ea72acc927327d799a5ad6265bffe2d869b2cbf5ecc2"
EXPECTED_FIXTURE_SCHEMA = "semper-supra.garm-provider-truenas-g3-create-fixture/1"
EXPECTED_CONTROLLER_ID = "g3-controller"
EXPECTED_POOL_ID = "g3-pool"
DEFAULT_CALLBACK_URL = "https://httpbin.org/anything/sempersupra-g3/status"
DEFAULT_METADATA_URL = (
    "https://httpbin.org/drip?duration=1&numbytes=1&code=200&delay=60&path="
)
EXPECTED_SUBSTITUTIONS = [
    "bootstrap_template.callback-url",
    "bootstrap_template.metadata-url",
    "bootstrap_template.instance-token",
    "expected_compose_template.services.runner.environment.GARM_CALLBACK_URL",
    "expected_compose_template.services.runner.environment.GARM_METADATA_URL",
    "expected_compose_template.services.runner.environment.GARM_INSTANCE_TOKEN",
]


class FixtureEnvironmentError(RuntimeError):
    pass


def preflight_public_fixture(callback_url: str, metadata_url: str, timeout: float) -> None:
    payload = b'{"status":"probe","message":"public synthetic G3 fixture preflight"}'
    request = urllib.request.Request(
        callback_url,
        data=payload,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "SemperSupra-G3-RDTE/1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if not (200 <= response.status < 300):
                raise FixtureEnvironmentError(
                    f"synthetic callback preflight returned HTTP {response.status}"
                )
            response.read(4096)

        metadata_probe = metadata_url.rstrip("/") + "/credentials/runner"
        request = urllib.request.Request(
            metadata_probe,
            method="GET",
            headers={
                "Accept": "application/json",
                "User-Agent": "SemperSupra-G3-RDTE/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                response.read(4096)
        except TimeoutError:
            pass
        except urllib.error.URLError as exc:
            if not isinstance(exc.reason, TimeoutError):
                raise
        else:
            raise FixtureEnvironmentError(
                "synthetic metadata hold-open returned before the preflight timeout"
            )
    except FixtureEnvironmentError:
        raise
    except Exception as exc:
        raise FixtureEnvironmentError(
            f"public synthetic callback/metadata fixture unavailable: {type(exc).__name__}: {exc}"
        ) from exc



def load_bundle(directory: pathlib.Path, expected_producer: str) -> dict:
    path = directory / "garm-provider-g3-fixture.json"
    bundle = json.loads(path.read_text(encoding="utf-8"))
    if bundle.get("schema") != EXPECTED_FIXTURE_SCHEMA:
        raise RuntimeError("unexpected G3 fixture schema")
    if bundle.get("provider_product_source") != EXPECTED_PROVIDER_PRODUCT_SOURCE:
        raise RuntimeError("G3 fixture product source drifted")
    if bundle.get("producer_source") != expected_producer:
        raise RuntimeError("G3 fixture producer source drifted")
    if bundle.get("controller_id") != EXPECTED_CONTROLLER_ID:
        raise RuntimeError("G3 fixture controller identity drifted")
    if bundle.get("pool_id") != EXPECTED_POOL_ID:
        raise RuntimeError("G3 fixture pool identity drifted")
    if bundle.get("run_local_substitutions") != EXPECTED_SUBSTITUTIONS:
        raise RuntimeError("G3 run-local substitution allowlist drifted")
    if not isinstance(bundle.get("bootstrap_template"), dict):
        raise RuntimeError("G3 fixture has no bootstrap template")
    if not isinstance(bundle.get("expected_compose_template"), dict):
        raise RuntimeError("G3 fixture has no expected Compose template")
    if not isinstance(bundle.get("expected_app_name"), str) or not bundle["expected_app_name"]:
        raise RuntimeError("G3 fixture has no expected App name")
    return bundle


def set_path(root: dict, dotted: str, value: str) -> None:
    parts = dotted.split(".")
    cur = root
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            raise RuntimeError(f"G3 substitution path is not an object: {dotted}")
        cur = nxt
    if parts[-1] not in cur:
        raise RuntimeError(f"G3 substitution target absent: {dotted}")
    cur[parts[-1]] = value


def lower_fixture(bundle: dict, callback_url: str, metadata_url: str, token: str) -> tuple[dict, dict]:
    bootstrap = copy.deepcopy(bundle["bootstrap_template"])
    expected = copy.deepcopy(bundle["expected_compose_template"])
    values = {
        "bootstrap_template.callback-url": callback_url,
        "bootstrap_template.metadata-url": metadata_url,
        "bootstrap_template.instance-token": token,
        "expected_compose_template.services.runner.environment.GARM_CALLBACK_URL": callback_url,
        "expected_compose_template.services.runner.environment.GARM_METADATA_URL": metadata_url,
        "expected_compose_template.services.runner.environment.GARM_INSTANCE_TOKEN": token,
    }
    for dotted in EXPECTED_SUBSTITUTIONS:
        target = bootstrap if dotted.startswith("bootstrap_template.") else expected
        relative = dotted.split(".", 1)[1]
        set_path(target, relative, values[dotted])
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
        timeout=120,
    )


def parse_provider_json(cp: subprocess.CompletedProcess[str], label: str, token: str):
    if cp.returncode != 0:
        detail = (cp.stderr or cp.stdout or "")[-1200:].replace(token, "<synthetic-token>")
        raise RuntimeError(f"{label} failed rc={cp.returncode}: {detail}")
    text = cp.stdout.strip()
    if not text:
        raise RuntimeError(f"{label} returned empty stdout")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} stdout was not JSON") from exc


def capture_create_failure_job(
    session: g2.AdminSession, app_name: str, token: str
) -> dict:
    jobs = session.call(
        "core.get_jobs",
        [[["method", "=", "app.create"]], {"order_by": ["-id"], "limit": 20}],
    )
    if not isinstance(jobs, list):
        raise RuntimeError("core.get_jobs did not return an array")
    selected = None
    for job in jobs:
        if not isinstance(job, dict):
            continue
        arguments = job.get("arguments")
        try:
            rendered = json.dumps(arguments, sort_keys=True)
        except TypeError:
            rendered = repr(arguments)
        if app_name in rendered:
            selected = job
            break
    if selected is None:
        return {"found": False}

    def scrub(value):
        if isinstance(value, str):
            return value.replace(token, "<synthetic-token>")
        if isinstance(value, dict):
            return {str(k): scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(v) for v in value]
        return value

    return {
        "found": True,
        "id": selected.get("id"),
        "state": selected.get("state"),
        "error": scrub(selected.get("error")),
        "exception": scrub(selected.get("exception")),
        "progress": scrub(selected.get("progress")),
        "logs_excerpt": scrub(selected.get("logs_excerpt")),
        "logs_available": bool(selected.get("logs_path")),
    }


def select_sanitized_log_excerpt(
    text: str,
    app_name: str,
    sensitive_values: list[str],
    *,
    context_lines: int = 80,
    max_chars: int = 24000,
) -> dict:
    scrubbed = text
    for value in sensitive_values:
        if value:
            scrubbed = scrubbed.replace(value, "<redacted>")
    lines = scrubbed.splitlines()
    hits = [i for i, line in enumerate(lines) if app_name in line]
    if hits:
        center = hits[-1]
        start = max(0, center - context_lines)
        end = min(len(lines), center + context_lines + 1)
    else:
        start = max(0, len(lines) - (context_lines * 2 + 1))
        end = len(lines)
    excerpt = "\n".join(lines[start:end])
    if len(excerpt) > max_chars:
        excerpt = excerpt[-max_chars:]
    return {
        "app_name_observed": bool(hits),
        "line_count": len(lines),
        "excerpt": excerpt,
    }


def capture_app_lifecycle_log(
    session: g2.AdminSession,
    host: str,
    https_port: int,
    ca_path: pathlib.Path,
    app_name: str,
    sensitive_values: list[str],
    timeout: float,
) -> dict:
    result = session.call(
        "core.download",
        ["filesystem.get", ["/var/log/app_lifecycle.log"], "app_lifecycle.log", True],
    )
    if not isinstance(result, (list, tuple)) or len(result) != 2:
        raise RuntimeError(f"core.download returned unexpected result: {type(result).__name__}")
    job_id, relative_url = result
    if not isinstance(job_id, int) or not isinstance(relative_url, str):
        raise RuntimeError("core.download did not return job id and URL")
    if not relative_url.startswith("/_download/"):
        raise RuntimeError("core.download returned unexpected download path")

    context = ssl.create_default_context(cafile=str(ca_path))
    request = urllib.request.Request(
        f"https://{host}:{https_port}{relative_url}",
        method="GET",
        headers={"User-Agent": "SemperSupra-G3-RDTE/1"},
    )
    max_bytes = 2 * 1024 * 1024
    with urllib.request.urlopen(
        request, timeout=max(timeout, 30.0), context=context
    ) as response:
        raw = response.read(max_bytes + 1)
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    text = raw.decode("utf-8", errors="replace")
    selected = select_sanitized_log_excerpt(
        text, app_name, sensitive_values
    )
    selected.update({
        "download_job_id": job_id,
        "bytes_read": len(raw),
        "truncated": truncated,
        "source": "/var/log/app_lifecycle.log",
    })
    return selected


def query_app(session: g2.AdminSession, name: str) -> dict | None:
    matches = session.call("app.query", [[["id", "=", name]]])
    if not matches:
        return None
    return matches[0]


def ensure_inactive(session: g2.AdminSession, name: str, job_timeout: float) -> str:
    app = query_app(session, name)
    if app is None:
        raise RuntimeError("provider-created App disappeared before retirement")
    state = str(app.get("state") or "")
    if state in {"STOPPED", "CRASHED"}:
        return state
    stop_id = session.call("app.stop", [name])
    if not isinstance(stop_id, int):
        raise RuntimeError("app.stop did not return a job id")
    session.wait_job(stop_id, f"app.stop {name}", job_timeout)
    app = query_app(session, name)
    if app is None:
        raise RuntimeError("provider-created App disappeared after stop")
    state = str(app.get("state") or "")
    if state not in {"STOPPED", "CRASHED"}:
        raise RuntimeError(f"provider-created App did not become inactive: {state}")
    return state


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--http-port", type=int, required=True)
    p.add_argument("--https-port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    p.add_argument("--fixture-producer-commit", required=True)
    p.add_argument("--expected-version", default=EXPECTED_VERSION)
    p.add_argument("--callback-url", default=DEFAULT_CALLBACK_URL)
    p.add_argument("--metadata-url", default=DEFAULT_METADATA_URL)
    p.add_argument("--out", required=True)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    a = p.parse_args()

    started = time.time()
    payload = {
        "schema": "truenas-garm-provider-g3/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "expected_version": a.expected_version,
        "provider_product_source": EXPECTED_PROVIDER_PRODUCT_SOURCE,
        "provider_binary_sha256": EXPECTED_PROVIDER_BINARY_SHA256,
        "appliance": EXPECTED_APPLIANCE,
        "controller_id": EXPECTED_CONTROLLER_ID,
        "pool_id": EXPECTED_POOL_ID,
        "provider_create_exercised": False,
        "provider_delete_exercised": False,
        "github_credentials_present": False,
        "github_jit_registration_exercised": False,
        "private_repository_execution": False,
        "physical_truenas_mutation": False,
        "capacity_promotion": False,
        "secret_values_recorded": False,
        "synthetic_token_recorded": False,
        "callback_fixture": {
            "callback_url": a.callback_url,
            "metadata_url": a.metadata_url,
            "authority": "public-synthetic-non-github",
            "metadata_behavior": "intentional-hold-open-no-jit-credentials",
        },
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
    app_name: str | None = None
    provider_delete_succeeded = False
    fallback_cleanup_used = False
    cleanup_errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="garm-provider-g3-") as td:
        root = pathlib.Path(td)
        token = f"g3-public-{secrets.token_hex(12)}"
        try:
            bundle = load_bundle(a.fixture_dir, a.fixture_producer_commit)
            payload["fixture_producer_source"] = bundle["producer_source"]
            preflight_public_fixture(a.callback_url, a.metadata_url, a.timeout)
            payload["synthetic_fixture_preflight"] = True
            payload["fixture_bundle_sha256"] = g2.sha256_file(
                a.fixture_dir / "garm-provider-g3-fixture.json"
            )
            payload["expected_app_name"] = bundle["expected_app_name"]
            payload["run_local_substitutions"] = EXPECTED_SUBSTITUTIONS
            app_name = bundle["expected_app_name"]

            bootstrap, expected_compose = lower_fixture(
                bundle, a.callback_url, a.metadata_url, token
            )
            expected_compose_sha = g2.canonical_json_sha256(expected_compose)

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
            if version != a.expected_version:
                raise RuntimeError(f"target version drifted: {version}")

            general = session.call("system.general.config", [])
            original_ui_cert_id = g2.ui_cert_id(general.get("ui_certificate"))

            api_key = session.call("api_key.create", [{
                "name": f"g3-provider-{secrets.token_hex(5)}",
                "username": "truenas_admin",
            }])
            if not isinstance(api_key, dict) or not isinstance(api_key.get("id"), int):
                raise RuntimeError("api_key.create did not return an id")
            api_key_id = int(api_key["id"])
            api_key_value = api_key.get("key")
            if not isinstance(api_key_value, str) or not api_key_value:
                raise RuntimeError("api_key.create did not return a key")

            create_cert_id = session.call("certificate.create", [{
                "name": f"g3_provider_{secrets.token_hex(4)}",
                "create_type": "CERTIFICATE_CREATE_IMPORTED",
                "add_to_trusted_store": False,
                "certificate": cert_path.read_text(encoding="utf-8"),
                "privatekey": key_path.read_text(encoding="utf-8"),
            }])
            if not isinstance(create_cert_id, int):
                raise RuntimeError("certificate.create did not return a job id")
            cert_job = session.wait_job(create_cert_id, "certificate.create", a.job_timeout)
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
            payload["provider_create_exercised"] = True
            create_cp = invoke_provider(
                provider_binary, config_path, api_key_value, cert_path,
                "CreateInstance", stdin_object=bootstrap,
            )
            try:
                created = parse_provider_json(create_cp, "CreateInstance", token)
            except Exception:
                try:
                    payload["create_failure_job"] = capture_create_failure_job(
                        session, app_name, token
                    )
                except Exception as capture_exc:
                    payload["create_failure_job"] = {
                        "found": False,
                        "capture_error": (
                            f"{type(capture_exc).__name__}: {capture_exc}"
                        ).replace(token, "<synthetic-token>"),
                    }
                try:
                    payload["app_lifecycle_log"] = capture_app_lifecycle_log(
                        session,
                        a.host,
                        a.https_port,
                        cert_path,
                        app_name,
                        [token, api_key_value or ""],
                        a.timeout,
                    )
                except Exception as capture_exc:
                    detail = (
                        f"{type(capture_exc).__name__}: {capture_exc}"
                    ).replace(token, "<synthetic-token>")
                    if api_key_value:
                        detail = detail.replace(api_key_value, "<redacted>")
                    payload["app_lifecycle_log"] = {
                        "captured": False,
                        "capture_error": detail,
                        "source": "/var/log/app_lifecycle.log",
                    }
                raise
            if not isinstance(created, dict):
                raise RuntimeError("CreateInstance did not return an object")
            created_app_name = str(created.get("provider_id") or "")
            if created_app_name != app_name:
                raise RuntimeError(
                    f"provider-created App identity drifted: {created_app_name!r}"
                )

            config = session.call("app.config", [app_name])
            if not isinstance(config, dict):
                raise RuntimeError("app.config did not return an object")
            realized_sha = g2.canonical_json_sha256(config)
            if realized_sha != expected_compose_sha:
                raise RuntimeError("provider-created exact Compose read-back drifted")

            get_cp = invoke_provider(
                provider_binary, config_path, api_key_value, cert_path,
                "GetInstance", instance_id=app_name,
            )
            got = parse_provider_json(get_cp, "GetInstance created", token)
            if not isinstance(got, dict) or got.get("provider_id") != app_name:
                raise RuntimeError("GetInstance did not read back created provider identity")

            list_cp = invoke_provider(
                provider_binary, config_path, api_key_value, cert_path,
                "ListInstances",
            )
            listed = parse_provider_json(list_cp, "ListInstances created", token)
            if not isinstance(listed, list):
                raise RuntimeError("ListInstances did not return an array")
            ids = sorted(
                str(item.get("provider_id"))
                for item in listed
                if isinstance(item, dict)
            )
            if ids != [app_name]:
                raise RuntimeError(f"ListInstances created inventory drifted: {ids}")

            inactive_state = ensure_inactive(session, app_name, a.job_timeout)

            payload["provider_delete_exercised"] = True
            delete_cp = invoke_provider(
                provider_binary, config_path, api_key_value, cert_path,
                "DeleteInstance", instance_id=app_name,
            )
            if delete_cp.returncode != 0:
                detail = (delete_cp.stderr or delete_cp.stdout or "")[-1200:].replace(
                    token, "<synthetic-token>"
                )
                raise RuntimeError(
                    f"DeleteInstance failed rc={delete_cp.returncode}: {detail}"
                )
            provider_delete_succeeded = True

            if query_app(session, app_name) is not None:
                raise RuntimeError("provider-created App remains after DeleteInstance")

            list_after_cp = invoke_provider(
                provider_binary, config_path, api_key_value, cert_path,
                "ListInstances",
            )
            listed_after = parse_provider_json(
                list_after_cp, "ListInstances post-delete", token
            )
            if listed_after != []:
                raise RuntimeError(
                    f"provider inventory not empty after delete: {listed_after!r}"
                )

            payload["oracles"] = {
                "verified_tls_transport": True,
                "api_key_auth_transport": True,
                "create_instance_returned_exact_owned_identity": True,
                "exact_realized_compose_readback": True,
                "get_created_instance": True,
                "list_created_instance_only": True,
                "inactive_transition_via_supported_middleware": True,
                "provider_delete_after_inactive": True,
                "post_delete_app_absent": True,
                "post_delete_provider_inventory_empty": True,
                "github_registration_not_exercised": True,
            }
            payload["retirement_inactive_state"] = inactive_state
            payload["classification"] = "SUPPORTED"
            payload["oracleSatisfied"] = True
            payload["detail"] = (
                "exact packaged provider CreateInstance realized the source-derived fixed "
                "runner App profile on real nested TrueNAS; exact Compose was read back, "
                "Get/List reconciled the created identity, the experiment App was moved "
                "inactive through supported middleware, provider DeleteInstance retired it, "
                "and no GitHub credential, JIT registration, private workload, physical "
                "TrueNAS, or capacity promotion was exercised"
            )
        except FixtureEnvironmentError as exc:
            payload["classification"] = "ENVIRONMENT_FAILURE"
            payload["detail"] = str(exc).replace(token, "<synthetic-token>")
        except Exception as exc:
            payload["detail"] = str(exc).replace(token, "<synthetic-token>")
        finally:
            try:
                session.connect()
                if app_name and query_app(session, app_name) is not None:
                    fallback_cleanup_used = True
                    try:
                        g2.delete_app_if_present(session, app_name, a.job_timeout)
                    except Exception as exc:
                        cleanup_errors.append(
                            f"fallback delete {app_name}: {type(exc).__name__}: {exc}"
                        )
                if app_name:
                    try:
                        if query_app(session, app_name) is not None:
                            cleanup_errors.append(
                                f"provider-created App remains after cleanup: {app_name}"
                            )
                    except Exception as exc:
                        cleanup_errors.append(
                            f"verify App absence {app_name}: {type(exc).__name__}: {exc}"
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
        "provider_delete_succeeded": provider_delete_succeeded,
        "fallback_cleanup_used": fallback_cleanup_used,
        "errors": cleanup_errors,
        "zero_unintended_residue": not cleanup_errors,
        "secret_values_recorded": False,
        "synthetic_token_recorded": False,
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
