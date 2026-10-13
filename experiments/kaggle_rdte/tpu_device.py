#!/usr/bin/env python3
"""Kaggle TPU v5e-8 device/JAX attestation before any costly training.

Public synthetic arithmetic only. Never installs packages, enables internet,
prints environment values, or calls external services. Provider errors are
reported as stable classes rather than exception text.
"""
import importlib.util
import json
import sys
from pathlib import Path

SCHEMA = "kaggle-rdte-result/v1"
WORKLOAD = "tpu-v5e8-device-v1"
OUT = Path("/kaggle/working") if Path("/kaggle/working").is_dir() else Path.cwd()


def probe():
    evidence = {
        "requested_accelerator": "TpuV5E8",
        "tpu_device_node_count": len(list(Path("/dev").glob("accel[0-9]*")))
            if Path("/dev").is_dir() else 0,
        "torch_xla_installed": importlib.util.find_spec("torch_xla") is not None,
        "jax_installed": importlib.util.find_spec("jax") is not None,
        "jaxlib_installed": importlib.util.find_spec("jaxlib") is not None,
        "tpu_count": 0,
        "tpu_arithmetic": False,
    }
    if not evidence["jax_installed"] or not evidence["jaxlib_installed"]:
        return evidence, "TPU_JAX_RUNTIME_MISSING"
    try:
        import jax
        import jax.numpy as jnp
        evidence["jax_version"] = jax.__version__
        devices = [d for d in jax.devices() if d.platform == "tpu"]
        evidence["tpu_count"] = len(devices)
        evidence["jax_backend_tpu"] = jax.default_backend() == "tpu"
        if not devices:
            return evidence, "TPU_DEVICE_UNAVAILABLE"
        x = jax.device_put(jnp.arange(16, dtype=jnp.float32), device=devices[0])
        # Explicit device target, rather than default backend CPU fallback.
        with jax.default_device(devices[0]):
            answer = jnp.sum(x * x)
        evidence["tpu_arithmetic"] = float(jax.device_get(answer)) == 1240.0
        if not evidence["tpu_arithmetic"]:
            return evidence, "TPU_MATH_ORACLE_FAILED"
        if evidence["tpu_count"] != 8:
            return evidence, "TPU_COUNT_MISMATCH"
        return evidence, None
    except Exception:
        return evidence, "TPU_RUNTIME_EXECUTION_ERROR"


def main():
    result = {"schema": SCHEMA, "workload": WORKLOAD, "status": "FAIL"}
    try:
        evidence, failure = probe()
        result["metrics"] = evidence
        if failure:
            result["failure_class"] = failure
        else:
            result["status"] = "PASS"
    except Exception:
        result["failure_class"] = "TPU_PROBE_INTERNAL_ERROR"
    OUT.joinpath("kaggle_rdte_result.json").write_text(
        json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    print("KAGGLE_RDTE=" + result["status"])
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
