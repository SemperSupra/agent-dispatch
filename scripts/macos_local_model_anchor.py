#!/usr/bin/env python3
"""Generation-neutral local-model GPU anchor for macOS GHA -> sovereign Apple Silicon transfer."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.request
from typing import Any

from macos_gpu_surrogate_qualification import METAL_SWIFT, compile_run_swift, mac_host_profile

SCHEMA = "macos-local-model-anchor/raw-v1"
PROBE_VERSION = "public-macos-local-model-anchor/1"

LLAMA_TAG = "v0.4.1"
LLAMA_EXPECTED_COMMIT = "b29c606e28a01b1bc8c1351026a0fa6e616bf6c4"

MODEL_REPO = "QuantFactory/SmolLM2-135M-Instruct-GGUF"
MODEL_REVISION = "a6b7826ed969c3926a98359e39912af137b464cb"
MODEL_FILE = "SmolLM2-135M-Instruct.Q4_K_M.gguf"
MODEL_SHA256 = "8030f04528538d47bda434f6f0bdf3952c40a58123e4d5e755332f23731a8684"
MODEL_SIZE = 105454144
MODEL_URL = (
    "https://huggingface.co/QuantFactory/SmolLM2-135M-Instruct-GGUF/resolve/"
    + MODEL_REVISION + "/" + MODEL_FILE + "?download=true"
)

PROMPT = "Answer with one short sentence: What comes after the number 41?"
GENERATION_ARGS = [
    "-n", "16",
    "--temp", "0",
    "--top-k", "1",
    "--seed", "4242",
    "--no-display-prompt",
    "--no-warmup",
    "-ngl", "all",
]

def run(argv: list[str], timeout: int = 300, cwd: str | None = None):
    try:
        cp = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return cp.returncode, cp.stdout, cp.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", f"{type(exc).__name__}: {exc}"

def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def download_model(path: pathlib.Path) -> dict[str, Any]:
    req = urllib.request.Request(MODEL_URL, headers={"User-Agent": "agent-dispatch-macos-anchor/1"})
    h = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(req, timeout=120) as src, path.open("wb") as dst:
            while True:
                block = src.read(1024 * 1024)
                if not block:
                    break
                dst.write(block)
                h.update(block)
                size += len(block)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "size": size, "sha256": h.hexdigest()}
    digest = h.hexdigest()
    return {
        "ok": size == MODEL_SIZE and digest == MODEL_SHA256,
        "size": size,
        "sha256": digest,
        "expected_size": MODEL_SIZE,
        "expected_sha256": MODEL_SHA256,
        "url_revision": MODEL_REVISION,
    }

def parse_gpu_evidence(stderr: str) -> dict[str, Any]:
    lower = stderr.lower()
    pairs = [
        (int(a), int(b))
        for a, b in re.findall(r"offloaded\s+(\d+)\s*/\s*(\d+)\s+layers?\s+to\s+gpu", lower)
    ]
    return {
        "metal_initialized": (
            "ggml_metal_init" in lower
            or "ggml_metal_device_init" in lower
            or "apple paravirtual device" in lower
        ),
        "metal_device_seen": "apple paravirtual device" in lower or "metal" in lower,
        "offload_pairs": pairs,
        "offloaded_layers": max((a for a, _ in pairs), default=0),
        "total_layers_reported": max((b for _, b in pairs), default=0),
        "cpu_fallback_warning": (
            "no usable gpu found" in lower
            or "gpu-layers option will be ignored" in lower
        ),
    }

def clean_candidate(stdout: str) -> str:
    # Preserve candidate semantics while removing only terminal whitespace.
    return stdout.strip()

def inference_rep(exe: pathlib.Path, model: pathlib.Path) -> dict[str, Any]:
    argv = [str(exe), "-m", str(model), "-p", PROMPT, *GENERATION_ARGS]
    rc, out, err = run(argv, timeout=180)
    return {
        "exit_code": rc,
        "candidate": clean_candidate(out),
        "candidate_sha256": hashlib.sha256(clean_candidate(out).encode("utf-8")).hexdigest(),
        "gpu": parse_gpu_evidence(err),
        "stderr_tail": err[-8000:] or None,
        "argv": argv[1:],
    }

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--label", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "probe_version": PROBE_VERSION,
        "provenance": {
            "requested_label": args.label,
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "workflow_sha": os.environ.get("GITHUB_SHA", ""),
            "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"),
        },
        "host_profile": mac_host_profile() if platform.system() == "Darwin" else {},
        "model": {
            "repo": MODEL_REPO,
            "revision": MODEL_REVISION,
            "file": MODEL_FILE,
            "expected_sha256": MODEL_SHA256,
            "expected_size": MODEL_SIZE,
            "license": "Apache-2.0",
        },
        "runtime": {
            "name": "llama.cpp",
            "tag": LLAMA_TAG,
            "expected_commit": LLAMA_EXPECTED_COMMIT,
            "metal_required": True,
        },
        "task": {
            "evidence_mode": "anchor",
            "task_class": "runtime.local-model-deterministic-inference",
            "prompt": PROMPT,
            "generation_args": GENERATION_ARGS,
            "repetitions": 2,
        },
        "metal_preflight": None,
        "download": None,
        "build": None,
        "repetitions": [],
        "producer_status": "INCOMPLETE",
        "warnings": [
            "This anchor qualifies a runtime/procedure realization, not general model competence.",
            "GHA performance is not evidence of sovereign Apple Silicon throughput or capacity.",
            "Host silicon identity and guest-visible Metal capability profile are separate dimensions.",
        ],
    }

    if platform.system() != "Darwin" or platform.machine() != "arm64":
        receipt["producer_status"] = "SKIPPED_GUARDRAIL"
        receipt["producer_reason"] = "first local-model transfer anchor is Apple-Silicon/arm64 only"
    else:
        receipt["metal_preflight"] = compile_run_swift(METAL_SWIFT)
        if receipt["metal_preflight"].get("classification") != "SUPPORTED":
            receipt["producer_status"] = "PREFLIGHT_FAILED"
            receipt["producer_reason"] = "native Metal preflight did not pass"
        else:
            with tempfile.TemporaryDirectory(prefix="mac-local-model-anchor-") as td:
                root = pathlib.Path(td)
                model = root / MODEL_FILE
                receipt["download"] = download_model(model)
                if not receipt["download"].get("ok"):
                    receipt["producer_status"] = "MODEL_INTEGRITY_FAILURE"
                    receipt["producer_reason"] = "pinned model artifact failed size/SHA-256 verification"
                else:
                    git = shutil.which("git")
                    cmake = shutil.which("cmake")
                    if not git or not cmake:
                        receipt["producer_status"] = "HARNESS_FAILURE"
                        receipt["producer_reason"] = "git/cmake unavailable"
                    else:
                        src = root / "llama.cpp"
                        rc, out, err = run(
                            [git, "clone", "--depth", "1", "--branch", LLAMA_TAG,
                             "https://github.com/ggml-org/llama.cpp.git", str(src)],
                            timeout=240,
                        )
                        if rc != 0:
                            receipt["producer_status"] = "RUNTIME_ACQUISITION_FAILURE"
                            receipt["producer_reason"] = "llama.cpp clone failed"
                            receipt["runtime"]["clone_stderr"] = err[-4000:] or None
                        else:
                            _, commit, _ = run([git, "rev-parse", "HEAD"], cwd=str(src), timeout=20)
                            commit = commit.strip()
                            receipt["runtime"]["resolved_commit"] = commit
                            if commit != LLAMA_EXPECTED_COMMIT:
                                receipt["producer_status"] = "RUNTIME_INTEGRITY_FAILURE"
                                receipt["producer_reason"] = "llama.cpp tag resolved to unexpected commit"
                            else:
                                rc, out, err = run(
                                    [cmake, "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Release",
                                     "-DGGML_METAL=ON", "-DGGML_METAL_EMBED_LIBRARY=ON",
                                     "-DLLAMA_BUILD_TESTS=OFF"],
                                    cwd=str(src), timeout=180,
                                )
                                receipt["build"] = {
                                    "configure_exit": rc,
                                    "configure_stdout_tail": out[-2500:] or None,
                                    "configure_stderr_tail": err[-3500:] or None,
                                }
                                if rc == 0:
                                    rc2, out2, err2 = run(
                                        [cmake, "--build", "build", "--config", "Release", "-j", "2",
                                         "--target", "llama-cli"],
                                        cwd=str(src), timeout=600,
                                    )
                                    receipt["build"].update({
                                        "build_exit": rc2,
                                        "build_stdout_tail": out2[-2500:] or None,
                                        "build_stderr_tail": err2[-3500:] or None,
                                    })
                                else:
                                    rc2 = None

                                exe = src / "build" / "bin" / "llama-cli"
                                if rc != 0 or rc2 != 0 or not exe.exists():
                                    receipt["producer_status"] = "RUNTIME_BUILD_FAILURE"
                                    receipt["producer_reason"] = "pinned llama.cpp Metal runtime failed to build"
                                else:
                                    help_rc, help_out, help_err = run([str(exe), "--help"], timeout=30)
                                    receipt["runtime"]["help_exit"] = help_rc
                                    receipt["runtime"]["help_sha256"] = hashlib.sha256(
                                        help_out.encode("utf-8")
                                    ).hexdigest()
                                    receipt["repetitions"] = [
                                        inference_rep(exe, model),
                                        inference_rep(exe, model),
                                    ]
                                    receipt["producer_status"] = "PRODUCED"
                                    receipt["producer_reason"] = "raw anchor evidence produced; independent validator required"

    path = pathlib.Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"MAC_LOCAL_MODEL_RAW_RECEIPT={path}")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
