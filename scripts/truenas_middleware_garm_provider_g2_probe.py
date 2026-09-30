#!/usr/bin/env python3
"""G2 oracle: exact GARM TrueNAS provider transport/adoption on disposable TrueNAS."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"
EXPECTED_APPLIANCE = (
    "ghcr.io/sempersupra/garm-appliance@"
    "sha256:1af67841ddd4589e3798dcda8be49230565c849d07ab57fd05899432dcdabca9"
)
EXPECTED_PROVIDER_PRODUCT_SOURCE = "14535745dc3aa3c0b5466da7c704bca4d23dcec5"
EXPECTED_PROVIDER_BINARY_SHA256 = "911f076ba9421f7bb2a1ea72acc927327d799a5ad6265bffe2d869b2cbf5ecc2"
EXPECTED_FIXTURE_SCHEMA = "semper-supra.garm-provider-truenas-g2-fixtures/1"
EXPECTED_CONTROLLER_ID = "g2-controller"
EXPECTED_POOL_ID = "g2-pool"
PROVIDER_PATH_IN_IMAGE = "/opt/garm/providers.d/garm-provider-truenas"


class AdminSession:
    def __init__(self, host: str, port: int, password: str, timeout: float):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.ws: WebSocket | None = None
        self.request_id = 1

    def connect(self) -> None:
        self.close()
        self.ws = WebSocket(self.host, self.port, timeout=self.timeout, tls=False)
        self.ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(self.ws, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise RuntimeError("DDP connection failed")
        auth = self.call("auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": "truenas_admin",
            "password": self.password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise RuntimeError("password authentication did not return SUCCESS")

    def call(self, method: str, params):
        if self.ws is None:
            raise RuntimeError("admin session is not connected")
        result = ddp_call(self.ws, str(self.request_id), method, params)
        self.request_id += 1
        return result

    def wait_job(self, job_id: int, label: str, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            last = self.call("core.get_jobs", [[["id", "=", job_id]], {"get": True}])
            if last and last.get("state") == "SUCCESS":
                return last
            if last and last.get("state") in {"FAILED", "ABORTED"}:
                raise RuntimeError(f"{label} job {last.get('state')}: {last.get('error')}")
            time.sleep(1)
        raise RuntimeError(f"{label} job did not reach SUCCESS: {last!r}")

    def close(self) -> None:
        if self.ws is not None:
            try:
                self.ws.close()
            finally:
                self.ws = None


def load_bundle(directory: pathlib.Path, expected_producer: str) -> dict:
    path = directory / "garm-provider-g2-fixtures.json"
    bundle = json.loads(path.read_text(encoding="utf-8"))
    if bundle.get("schema") != EXPECTED_FIXTURE_SCHEMA:
        raise RuntimeError("unexpected G2 fixture schema")
    if bundle.get("provider_product_source") != EXPECTED_PROVIDER_PRODUCT_SOURCE:
        raise RuntimeError("G2 fixture product source drifted")
    if bundle.get("producer_source") != expected_producer:
        raise RuntimeError("G2 fixture producer source drifted")
    if bundle.get("controller_id") != EXPECTED_CONTROLLER_ID:
        raise RuntimeError("G2 fixture controller identity drifted")
    if bundle.get("pool_id") != EXPECTED_POOL_ID:
        raise RuntimeError("G2 fixture pool identity drifted")
    fixtures = bundle.get("fixtures")
    if not isinstance(fixtures, dict) or set(fixtures) != {
        "valid_local", "valid_foreign", "managed_drift"
    }:
        raise RuntimeError("G2 fixture inventory drifted")
    return bundle


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_provider_binary(root: pathlib.Path) -> pathlib.Path:
    subprocess.run(
        ["docker", "pull", EXPECTED_APPLIANCE],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    cp = subprocess.run(
        ["docker", "create", EXPECTED_APPLIANCE],
        check=True,
        capture_output=True,
        text=True,
    )
    container_id = cp.stdout.strip()
    if not container_id:
        raise RuntimeError("docker create returned no container id")
    destination = root / "garm-provider-truenas"
    try:
        subprocess.run(
            ["docker", "cp", f"{container_id}:{PROVIDER_PATH_IN_IMAGE}", str(destination)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container_id],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    digest = sha256_file(destination)
    if digest != EXPECTED_PROVIDER_BINARY_SHA256:
        raise RuntimeError(f"provider binary digest drifted: {digest}")
    destination.chmod(0o755)
    return destination


def generate_tls(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    key = root / "g2-ui.key"
    cert = root / "g2-ui.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(key), "-out", str(cert),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)
    return cert, key


def ui_cert_id(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, dict) and isinstance(value.get("id"), int):
        return int(value["id"])
    raise RuntimeError(f"unexpected ui_certificate shape: {type(value).__name__}")


def wait_verified_https(host: str, port: int, cafile: pathlib.Path, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            context = ssl.create_default_context(cafile=str(cafile))
            with socket.create_connection((host, port), timeout=4) as raw:
                with context.wrap_socket(raw, server_hostname=host) as wrapped:
                    cert = wrapped.getpeercert()
                    if cert:
                        return
        except Exception as exc:
            last = exc
            time.sleep(1)
    raise RuntimeError(f"verified HTTPS did not become ready: {last}")


def create_app_stopped(
    session: AdminSession,
    app_name: str,
    compose: dict,
    job_timeout: float,
) -> dict:
    job_id = session.call("app.create", [{
        "app_name": app_name,
        "custom_app": True,
        "custom_compose_config": compose,
    }])
    if not isinstance(job_id, int):
        raise RuntimeError(f"app.create({app_name}) did not return a job id")
    session.wait_job(job_id, f"app.create {app_name}", job_timeout)
    app = session.call("app.query", [[["id", "=", app_name]], {"get": True}])
    if not app:
        raise RuntimeError(f"app {app_name} absent immediately after create")
    if app.get("state") != "STOPPED":
        stop_id = session.call("app.stop", [app_name])
        if not isinstance(stop_id, int):
            raise RuntimeError(f"app.stop({app_name}) did not return a job id")
        session.wait_job(stop_id, f"app.stop {app_name}", job_timeout)
        app = session.call("app.query", [[["id", "=", app_name]], {"get": True}])
    if not app or app.get("state") != "STOPPED":
        raise RuntimeError(f"fixture app {app_name} did not reach STOPPED")
    return app


def delete_app_if_present(session: AdminSession, app_name: str, job_timeout: float) -> None:
    matches = session.call("app.query", [[["id", "=", app_name]]])
    if not matches:
        return
    app = matches[0]
    if app.get("state") not in {"STOPPED", "CRASHED"}:
        stop_id = session.call("app.stop", [app_name])
        if isinstance(stop_id, int):
            session.wait_job(stop_id, f"cleanup app.stop {app_name}", job_timeout)
    delete_id = session.call("app.delete", [app_name, {
        "remove_images": False,
        "remove_ix_volumes": False,
        "force_remove_custom_app": False,
    }])
    if not isinstance(delete_id, int):
        raise RuntimeError(f"cleanup app.delete({app_name}) did not return a job id")
    session.wait_job(delete_id, f"cleanup app.delete {app_name}", job_timeout)


def provider_env(
    provider_binary: pathlib.Path,
    config_path: pathlib.Path,
    api_key: str,
    ca_path: pathlib.Path,
    command: str,
    instance_id: str | None = None,
) -> tuple[list[str], dict[str, str]]:
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
    if instance_id is not None:
        env["GARM_INSTANCE_ID"] = instance_id
    else:
        env.pop("GARM_INSTANCE_ID", None)
    return [str(provider_binary)], env


def invoke_provider(
    provider_binary: pathlib.Path,
    config_path: pathlib.Path,
    api_key: str,
    ca_path: pathlib.Path,
    command: str,
    instance_id: str | None = None,
) -> subprocess.CompletedProcess[str]:
    argv, env = provider_env(
        provider_binary, config_path, api_key, ca_path, command, instance_id
    )
    return subprocess.run(
        argv,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=45,
    )


def parse_json_stdout(cp: subprocess.CompletedProcess[str], label: str):
    if cp.returncode != 0:
        raise RuntimeError(f"{label} failed rc={cp.returncode}: {cp.stderr[-1000:]}")
    text = cp.stdout.strip()
    if not text:
        raise RuntimeError(f"{label} returned empty stdout")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} stdout was not JSON: {text[-1000:]}") from exc


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
        "schema": "truenas-garm-provider-g2/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "expected_version": EXPECTED_VERSION,
        "provider_product_source": EXPECTED_PROVIDER_PRODUCT_SOURCE,
        "provider_binary_sha256": EXPECTED_PROVIDER_BINARY_SHA256,
        "appliance": EXPECTED_APPLIANCE,
        "controller_id": EXPECTED_CONTROLLER_ID,
        "pool_id": EXPECTED_POOL_ID,
        "provider_create_exercised": False,
        "provider_delete_exercised": False,
        "github_credentials_present": False,
        "github_jit_registration_exercised": False,
        "physical_truenas_mutation": False,
        "secret_values_recorded": False,
    }

    password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()
    bundle = None
    fixture_names: list[str] = []
    api_key_id: int | None = None
    api_key_value: str | None = None
    imported_cert_id: int | None = None
    original_ui_cert_id: int | None = None
    session = AdminSession(a.host, a.http_port, password, a.timeout)
    cleanup_errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="garm-provider-g2-") as td:
        root = pathlib.Path(td)
        try:
            bundle = load_bundle(a.fixture_dir, a.fixture_producer_commit)
            payload["fixture_producer_source"] = bundle["producer_source"]
            payload["fixture_bundle_sha256"] = sha256_file(
                a.fixture_dir / "garm-provider-g2-fixtures.json"
            )

            provider_binary = extract_provider_binary(root)
            payload["provider_binary_from_appliance"] = True

            cert_path, key_path = generate_tls(root)
            payload["transport"] = {
                "scheme": "wss",
                "host": a.host,
                "port": a.https_port,
                "insecure_skip_verify": False,
                "certificate_sha256": sha256_file(cert_path),
                "private_key_recorded": False,
                "api_key_recorded": False,
            }

            session.connect()
            version = session.call("system.version", [])
            payload["system_version"] = version
            if version != EXPECTED_VERSION:
                raise RuntimeError(f"target version drifted: {version}")

            general = session.call("system.general.config", [])
            original_ui_cert_id = ui_cert_id(general.get("ui_certificate"))

            api_key = session.call("api_key.create", [{
                "name": f"g2-provider-{secrets.token_hex(5)}",
                "username": "truenas_admin",
            }])
            if not isinstance(api_key, dict) or not isinstance(api_key.get("id"), int):
                raise RuntimeError("api_key.create did not return an id")
            api_key_id = int(api_key["id"])
            api_key_value = api_key.get("key")
            if not isinstance(api_key_value, str) or not api_key_value:
                raise RuntimeError("api_key.create did not return a key")

            create_cert_id = session.call("certificate.create", [{
                "name": f"g2_provider_{secrets.token_hex(4)}",
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
                # Applying UI settings intentionally aborts the HTTP/WebSocket connection.
                pass
            session.close()
            wait_verified_https(a.host, a.https_port, cert_path)

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
            fixtures = bundle["fixtures"]
            for key in ("valid_local", "valid_foreign"):
                fixture = fixtures[key]
                name = fixture["app_name"]
                create_app_stopped(session, name, fixture["compose"], a.job_timeout)
                fixture_names.append(name)

            local_name = fixtures["valid_local"]["app_name"]
            foreign_name = fixtures["valid_foreign"]["app_name"]

            list_cp = invoke_provider(
                provider_binary, config_path, api_key_value, cert_path, "ListInstances"
            )
            listed = parse_json_stdout(list_cp, "ListInstances valid/foreign")
            if not isinstance(listed, list):
                raise RuntimeError("ListInstances did not return an array")
            provider_ids = sorted(
                str(item.get("provider_id"))
                for item in listed
                if isinstance(item, dict)
            )
            if provider_ids != [local_name]:
                raise RuntimeError(f"ListInstances ownership filter drifted: {provider_ids}")

            get_local_cp = invoke_provider(
                provider_binary, config_path, api_key_value, cert_path,
                "GetInstance", local_name,
            )
            got_local = parse_json_stdout(get_local_cp, "GetInstance local")
            if not isinstance(got_local, dict) or got_local.get("provider_id") != local_name:
                raise RuntimeError("GetInstance local returned wrong provider id")

            foreign_cp = invoke_provider(
                provider_binary, config_path, api_key_value, cert_path,
                "GetInstance", foreign_name,
            )
            if foreign_cp.returncode == 0:
                raise RuntimeError("GetInstance foreign unexpectedly succeeded")

            reconnect_cp = invoke_provider(
                provider_binary, config_path, api_key_value, cert_path,
                "GetInstance", local_name,
            )
            reconnect_local = parse_json_stdout(reconnect_cp, "GetInstance reconnect")
            if reconnect_local.get("provider_id") != local_name:
                raise RuntimeError("fresh provider process did not readopt local fixture")

            drift = fixtures["managed_drift"]
            drift_name = drift["app_name"]
            create_app_stopped(session, drift_name, drift["compose"], a.job_timeout)
            fixture_names.append(drift_name)

            drift_get = invoke_provider(
                provider_binary, config_path, api_key_value, cert_path,
                "GetInstance", drift_name,
            )
            if drift_get.returncode == 0:
                raise RuntimeError("GetInstance managed drift unexpectedly succeeded")

            drift_list = invoke_provider(
                provider_binary, config_path, api_key_value, cert_path,
                "ListInstances",
            )
            if drift_list.returncode == 0:
                raise RuntimeError("ListInstances with managed drift unexpectedly succeeded")

            payload["oracles"] = {
                "verified_tls_transport": True,
                "api_key_auth_transport": True,
                "list_valid_owned_only": True,
                "get_valid_owned": True,
                "foreign_not_adopted": True,
                "fresh_process_readoption": True,
                "managed_drift_get_fail_closed": True,
                "managed_drift_list_fail_closed": True,
                "provider_delete_not_invoked": True,
                "provider_create_not_invoked": True,
            }
            payload["classification"] = "SUPPORTED"
            payload["oracleSatisfied"] = True
            payload["detail"] = (
                "exact packaged provider used verified WSS plus run-local API-key auth against "
                "real nested TrueNAS; exact source-generated local fixture was listed/readopted, "
                "foreign ownership was excluded, and managed realized-profile drift failed closed; "
                "provider create/delete and GitHub/JIT paths were intentionally not exercised"
            )
        except Exception as exc:
            payload["detail"] = f"{type(exc).__name__}: {exc}"
        finally:
            # Cleanup through supported TrueNAS middleware only.
            try:
                session.connect()
                for name in reversed(fixture_names):
                    try:
                        delete_app_if_present(session, name, a.job_timeout)
                    except Exception as exc:
                        cleanup_errors.append(f"delete {name}: {type(exc).__name__}: {exc}")

                if api_key_id is not None:
                    try:
                        deleted = session.call("api_key.delete", [api_key_id])
                        if deleted is not True:
                            cleanup_errors.append("api_key.delete did not return true")
                    except Exception as exc:
                        cleanup_errors.append(f"api_key.delete: {type(exc).__name__}: {exc}")
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
                cleanup_errors.append(f"cleanup session: {type(exc).__name__}: {exc}")
            finally:
                session.close()

    payload["cleanup"] = {
        "attempted": True,
        "errors": cleanup_errors,
        "zero_unintended_residue": not cleanup_errors,
        "secret_values_recorded": False,
    }
    if cleanup_errors:
        payload["oracleSatisfied"] = False
        payload["classification"] = "ORACLE_FAILURE"
        payload["detail"] = (
            payload.get("detail", "") + "; cleanup failed: " + "; ".join(cleanup_errors)
        )

    payload["elapsed_seconds"] = round(time.time() - started, 3)
    pathlib.Path(a.out).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
