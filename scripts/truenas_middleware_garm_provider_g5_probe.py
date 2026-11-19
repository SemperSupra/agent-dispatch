#!/usr/bin/env python3
"""G5 oracle: bind one exact TrueNAS source-matrix row to the proven provider lifecycle oracle."""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
import time

import truenas_middleware_garm_provider_g3_probe as g3


EXPECTED_MATRIX_SCHEMA = "semper-supra.garm-provider-truenas-g5-version-matrix/1"
EXPECTED_PROVIDER_PRODUCT_SOURCE = g3.EXPECTED_PROVIDER_PRODUCT_SOURCE


def load_matrix(directory: pathlib.Path, expected_producer: str) -> dict:
    path = directory / "garm-provider-truenas-g5-version-matrix.json"
    matrix = json.loads(path.read_text(encoding="utf-8"))
    if matrix.get("schema") != EXPECTED_MATRIX_SCHEMA:
        raise RuntimeError("unexpected G5 version-matrix schema")
    if matrix.get("provider_product_source") != EXPECTED_PROVIDER_PRODUCT_SOURCE:
        raise RuntimeError("G5 matrix provider product source drifted")
    if matrix.get("producer_source") != expected_producer:
        raise RuntimeError("G5 matrix producer source drifted")
    if matrix.get("runtime_inheritance_allowed") is not False:
        raise RuntimeError("G5 matrix must prohibit runtime support inheritance")
    oracles = matrix.get("source_oracles")
    if not isinstance(oracles, dict) or not oracles or not all(value is True for value in oracles.values()):
        raise RuntimeError("G5 matrix source oracles are not all true")
    targets = matrix.get("targets")
    if not isinstance(targets, list) or not targets:
        raise RuntimeError("G5 matrix has no targets")
    return matrix


def select_row(matrix: dict, target_version: str, expected_middleware_commit: str) -> dict:
    matches = [
        row for row in matrix["targets"]
        if isinstance(row, dict) and row.get("version") == target_version
    ]
    if len(matches) != 1:
        raise RuntimeError(f"G5 matrix target cardinality drifted for {target_version}: {len(matches)}")
    row = matches[0]
    expected_system_version = f"TrueNAS-{target_version}"
    if row.get("system_version") != expected_system_version:
        raise RuntimeError(
            f"G5 matrix system_version drifted: {row.get('system_version')!r} != {expected_system_version!r}"
        )
    if row.get("middleware_commit") != expected_middleware_commit:
        raise RuntimeError(
            "G5 matrix middleware commit drifted: "
            f"{row.get('middleware_commit')!r} != {expected_middleware_commit!r}"
        )
    blobs = row.get("source_blobs")
    if not isinstance(blobs, dict) or len(blobs) < 7:
        raise RuntimeError("G5 matrix row has incomplete source blob evidence")
    if not isinstance(row.get("source_equivalence_group"), str) or not row["source_equivalence_group"]:
        raise RuntimeError("G5 matrix row has no source equivalence group")
    return row


def run_underlying_g3(
    args: argparse.Namespace,
    expected_system_version: str,
    out: pathlib.Path,
) -> subprocess.CompletedProcess[str]:
    script = pathlib.Path(__file__).with_name("truenas_middleware_garm_provider_g3_probe.py")
    cmd = [
        sys.executable,
        str(script),
        "--host", args.host,
        "--http-port", str(args.http_port),
        "--https-port", str(args.https_port),
        "--password-file", args.password_file,
        "--fixture-dir", str(args.fixture_dir),
        "--fixture-producer-commit", args.fixture_producer_commit,
        "--expected-version", expected_system_version,
        "--out", str(out),
        "--timeout", str(args.timeout),
        "--job-timeout", str(args.job_timeout),
    ]
    return subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=900)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--http-port", type=int, required=True)
    p.add_argument("--https-port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--matrix-dir", type=pathlib.Path, required=True)
    p.add_argument("--matrix-producer-commit", required=True)
    p.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    p.add_argument("--fixture-producer-commit", required=True)
    p.add_argument("--target-version", required=True)
    p.add_argument("--expected-middleware-commit", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    a = p.parse_args()

    started = time.time()
    payload = {
        "schema": "truenas-garm-provider-g5-version-row/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "target_version": a.target_version,
        "matrix_producer_source": a.matrix_producer_commit,
        "fixture_producer_source": a.fixture_producer_commit,
        "provider_product_source": EXPECTED_PROVIDER_PRODUCT_SOURCE,
        "runtime_inheritance_allowed": False,
        "github_credentials_present": False,
        "github_jit_registration_exercised": False,
        "private_repository_execution": False,
        "physical_truenas_mutation": False,
        "capacity_promotion": False,
    }

    try:
        matrix = load_matrix(a.matrix_dir, a.matrix_producer_commit)
        row = select_row(matrix, a.target_version, a.expected_middleware_commit)
        payload["matrix_row"] = row
        payload["matrix_source_oracles"] = matrix["source_oracles"]
        payload["source_equivalence_group"] = row["source_equivalence_group"]
        payload["expected_system_version"] = row["system_version"]

        with tempfile.TemporaryDirectory(prefix="garm-provider-g5-") as td:
            underlying_path = pathlib.Path(td) / "provider-lifecycle.json"
            cp = run_underlying_g3(a, row["system_version"], underlying_path)
            if not underlying_path.exists():
                detail = (cp.stderr or cp.stdout or "")[-1600:]
                raise RuntimeError(
                    f"underlying provider lifecycle emitted no receipt rc={cp.returncode}: {detail}"
                )
            underlying = json.loads(underlying_path.read_text(encoding="utf-8"))

        payload["underlying_provider_lifecycle"] = underlying
        if underlying.get("provider_product_source") != EXPECTED_PROVIDER_PRODUCT_SOURCE:
            raise RuntimeError("underlying provider product source drifted")
        if underlying.get("provider_binary_sha256") != g3.EXPECTED_PROVIDER_BINARY_SHA256:
            raise RuntimeError("underlying provider binary identity drifted")
        if underlying.get("system_version") != row["system_version"]:
            raise RuntimeError(
                f"runtime system version drifted: {underlying.get('system_version')!r}"
            )
        cleanup = underlying.get("cleanup")
        if not isinstance(cleanup, dict):
            raise RuntimeError("underlying lifecycle has no cleanup receipt")
        if cleanup.get("fallback_cleanup_used") is not False:
            raise RuntimeError("underlying lifecycle required fallback cleanup")
        if cleanup.get("zero_unintended_residue") is not True:
            raise RuntimeError("underlying lifecycle did not prove zero unintended residue")
        if underlying.get("oracleSatisfied") is not True or underlying.get("classification") != "SUPPORTED":
            raise RuntimeError(
                "underlying exact-version provider lifecycle did not satisfy its oracle: "
                + str(underlying.get("detail") or underlying.get("classification"))
            )

        payload["oracles"] = {
            "exact_source_matrix_row_bound": True,
            "exact_middleware_commit_bound": True,
            "exact_runtime_system_version": True,
            "exact_provider_identity": True,
            "provider_lifecycle_supported": True,
            "zero_unintended_residue": True,
            "runtime_inheritance_prohibited": True,
            "github_registration_not_exercised": True,
        }
        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["detail"] = (
            f"exact TrueNAS {a.target_version} source-matrix row matched the RDTE target and "
            "the fixed packaged provider completed CreateInstance, exact Compose read-back, "
            "Get/List, supported inactive transition, DeleteInstance, App absence, empty "
            "inventory, and zero-residue cleanup without GitHub/JIT/private/physical/capacity authority"
        )
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"

    payload["elapsed_seconds"] = round(time.time() - started, 3)
    pathlib.Path(a.out).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
