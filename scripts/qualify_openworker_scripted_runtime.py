#!/usr/bin/env python3
"""Ephemeral original OpenWorker full-headless scripted-provider qualification.

Public immutable source + disposable venv, synthetic prompt and a fake scripted
model only. This is a build/run/O&M proof, not real LLM inference or mail access.
A deterministic deny-write test exercises the real OpenWorker engine and records.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

SCHEMA = "public-openworker-scripted-full-runtime/v1"
REPOSITORY = "https://github.com/andrewyng/openworker.git"
COMMIT = "ecb445490fc054d52b8ea610d97ba947f57033d2"
BLOBS = {
    "LICENSE": "60d3824636ee279c14389ea0b858f00fe0c4a913",
    "coworker/headless/runner.py": "3cadae25bd4a3c90d363ae296522058e578af917",
    "coworker/connectors/email_tools.py": "7be4e1f9e78e8fd9d1ef81b58bbc86a916c48e76",
    "pyproject.toml": "19b9ccb3f1e59e66d19a23acef116f71d7903947",
}
MAX_RUN_SECONDS = 235
SCRIPT = [
    {"text": "Attempt to create the requested note.", "tool_calls": [
        {"name": "write_file", "arguments": {
            "path": "forbidden.txt", "content": "this must not be written"}}]},
    {"text": "The file write was refused; no changes made.",
     "finish_reason": "stop"},
]


class QualifyError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + data).hexdigest()


def run(argv: list[str], *, cwd: Path, env: dict[str, str],
        timeout: float) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(argv, cwd=cwd, env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=max(1.0, timeout),
                                check=False)
    except subprocess.TimeoutExpired as exc:
        raise QualifyError("SUBPROCESS_TIMEOUT") from exc
    if result.returncode != 0:
        raise QualifyError("SUBPROCESS_FAILED_" + str(result.returncode))
    return result


def scrub_environment(home: Path, *, path: str) -> dict[str, str]:
    return {
        "HOME": str(home), "PATH": path,
        "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1",
        "PYTHONUNBUFFERED": "1", "PIP_NO_INPUT": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def inspect_record(out: Path, workspace: Path) -> dict:
    mandatory = ["events.jsonl", "messages.json", "summary.json",
                 "answers.json", "audit.db", "model_calls.jsonl",
                 "trajectory.json"]
    if not all((out / n).is_file() and (out / n).stat().st_size > 0
               for n in mandatory):
        raise QualifyError("MISSING_ENGINE_RECORD")
    summary = json.loads((out / "summary.json").read_bytes())
    trajectory = json.loads((out / "trajectory.json").read_bytes())
    calls = [json.loads(x) for x in (out / "model_calls.jsonl").read_text().splitlines()
             if x.strip()]
    isolation = summary.get("isolation", {})
    if not isinstance(isolation, dict) or "COWORKER_STATE_DIR" not in isolation:
        raise QualifyError("MISSING_ISOLATION_RECORD")
    try:
        Path(isolation["COWORKER_STATE_DIR"]).resolve().relative_to(out.resolve())
    except (ValueError, OSError) as exc:
        raise QualifyError("HOST_STATE_PATH_NOT_ISOLATED") from exc
    if (workspace / "forbidden.txt").exists():
        raise QualifyError("UNAPPROVED_WRITE_OCCURRED")
    if summary.get("tool_calls_denied", 0) < 1:
        raise QualifyError("REAL_ENGINE_APPROVAL_NOT_DENIED")
    if summary.get("args", {}).get("scripted") is not True:
        raise QualifyError("UNTRUSTED_MODEL_ROUTE")
    if trajectory.get("schema_version") != "ATIF-v1.7":
        raise QualifyError("TRAJECTORY_SCHEMA_DRIFT")
    if trajectory.get("agent", {}).get("name") != "openworker":
        raise QualifyError("UNEXPECTED_AGENT")
    if not calls or len(calls) > 5:
        raise QualifyError("MODEL_CALL_BUDGET_DRIFT")
    return {
        "outcome": summary.get("outcome"),
        "tool_calls_denied": summary.get("tool_calls_denied"),
        "model_calls": len(calls),
        "audit_bytes": (out / "audit.db").stat().st_size,
        "artifact_count": len(mandatory),
        "trajectory_steps": len(trajectory.get("steps", [])),
        "record_sha256": sha256((out / "summary.json").read_bytes()),
        "no_unapproved_workspace_write": True,
    }


def qualify() -> dict:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="ow-scripted-public-") as temp:
        root = Path(temp)
        home = root / "home"
        home.mkdir()
        src = root / "src"
        src.mkdir()
        build_env = scrub_environment(home, path=os.environ.get("PATH", "/usr/bin:/bin"))
        run(["git", "init", "-q", str(src)], cwd=root, env=build_env, timeout=12)
        run(["git", "-C", str(src), "remote", "add", "origin", REPOSITORY],
            cwd=root, env=build_env, timeout=10)
        run(["git", "-C", str(src), "fetch", "-q", "--depth", "1",
             "origin", COMMIT], cwd=root, env=build_env, timeout=35)
        run(["git", "-C", str(src), "checkout", "-q", "--detach", "FETCH_HEAD"],
            cwd=root, env=build_env, timeout=10)
        head = run(["git", "-C", str(src), "rev-parse", "HEAD"],
                   cwd=root, env=build_env, timeout=5).stdout.decode().strip()
        if head != COMMIT:
            raise QualifyError("UPSTREAM_COMMIT_DRIFT")
        for name, digest in BLOBS.items():
            path = src / name
            if not path.is_file() or git_blob(path.read_bytes()) != digest:
                raise QualifyError("UPSTREAM_GIT_BLOB_MISMATCH")
        if not (src / "LICENSE").read_text(encoding="utf-8").startswith("MIT License"):
            raise QualifyError("RIGHTS_UNQUALIFIED")
        venv = root / "venv"
        run([sys.executable, "-m", "venv", str(venv)], cwd=root,
            env=build_env, timeout=30)
        python = str(venv / "bin" / "python")
        # Prefer wheels and refuse fallback source-build dependency execution.
        # This is an experimental *unlocked* dependency closure: never publish
        # the resulting venv or consider it a reproducible production install.
        build = run([python, "-m", "pip", "install", "--only-binary=:all:",
                     "--no-cache-dir", "--disable-pip-version-check",
                     str(src)], cwd=root, env=build_env, timeout=160)
        install_seconds = round(time.monotonic()-started, 2)
        installed = run([python, "-m", "pip", "list", "--format=json"],
                        cwd=root, env=build_env, timeout=12).stdout
        package_inventory = json.loads(installed)
        normalized = json.dumps(sorted(
            (p["name"].lower(), p["version"]) for p in package_inventory),
            separators=(",", ":")).encode()
        runtime_env = scrub_environment(home,
            path=str(venv / "bin") + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"))
        script = root / "scripted.json"
        script.write_text(json.dumps(SCRIPT), encoding="utf-8")
        reports = []
        for index in (1, 2):
            workspace = root / ("workspace-" + str(index))
            workspace.mkdir()
            out = root / ("out-" + str(index))
            cmd = [python, "-m", "coworker.cli", "run",
                   "--prompt", "Fictional task: please create forbidden.txt; seek approval.",
                   "--workspace", str(workspace),
                   "--model", "fixture/noop", "--scripted", str(script),
                   "--approval-mode", "ask", "--auto-answer",
                   "--isolated", "--no-web-tools",
                   "--max-iterations", "3", "--timeout-seconds", "45",
                   "--out", str(out)]
            run(cmd, cwd=src, env=runtime_env, timeout=62)
            reports.append(inspect_record(out, workspace))
        behavior = [(x["outcome"], x["tool_calls_denied"], x["model_calls"])
                    for x in reports]
        if behavior[0] != behavior[1]:
            raise QualifyError("CLEAN_START_REPLAY_MISMATCH")
        elapsed = round(time.monotonic()-started, 2)
        # Disk size and memory cost are observations, not an allowance to
        # transmit package bytes or logs to the public artifact store.
        wheel_bytes = sum(p.stat().st_size for p in venv.rglob("*") if p.is_file())
        return {
            "schema": SCHEMA,
            "classification": "ORIGINAL_SCRIPTED_HEADLESS_RUNTIME_ONLY",
            "upstream_commit": COMMIT,
            "upstream_license": "MIT",
            "qualified": True,
            "headless_engine_executed": True,
            "model_inference": False,
            "scripted_provider_only": True,
            "real_mail": False,
            "smtp_sent": False,
            "shell_tools_executed": False,
            "approval_denial_observed": True,
            "clean_restart_replay": True,
            "atif_schema": "ATIF-v1.7",
            "run_count": len(reports),
            "record_count_per_run": 7,
            "install_seconds": install_seconds,
            "elapsed_seconds": elapsed,
            "installed_package_count": len(package_inventory),
            "dependency_inventory_sha256": sha256(normalized),
            "dependencies_hash_locked": False,
            "venv_size_bytes": wheel_bytes,
            "total_model_calls": sum(r["model_calls"] for r in reports),
            "total_denied_calls": sum(r["tool_calls_denied"] for r in reports),
        }


def main() -> int:
    try:
        result = qualify()
    except (QualifyError, OSError, UnicodeError, ValueError) as exc:
        if isinstance(exc, QualifyError):
            code = str(exc)
        else:
            code = "UPSTREAM_RUNTIME_OR_DEPENDENCY_ERROR"
        print("OPENWORKER_SCRIPTED_BLOCKED=" + code, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["qualified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
