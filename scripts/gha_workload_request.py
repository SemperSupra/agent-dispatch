#!/usr/bin/env python3
"""Validate and execute committed GitHub Actions workload requests."""

from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, subprocess, sys
from typing import Any

SCHEMA = "gha-workload-request/v1"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
ALLOWED_RUNNERS = {
    "ubuntu-24.04", "ubuntu-26.04", "ubuntu-24.04-arm", "ubuntu-26.04-arm",
    "windows-2025", "windows-11-arm", "macos-26", "macos-26-intel", "xcode-27",
}
ALLOWED_SETUP_PROFILES = {"none"}
MAX_TIMEOUT_MINUTES = 60
MAX_ARGC = 64
MAX_ARG_BYTES = 8192

class RequestError(ValueError):
    pass

def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()

def _safe_relpath(value: str, field: str) -> str:
    p = pathlib.PurePosixPath(value)
    if not value or p.is_absolute() or ".." in p.parts:
        raise RequestError(f"{field} must be a non-empty repository-relative path")
    return value

def load_request(path: pathlib.Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RequestError(f"cannot read request: {exc}") from exc
    if not isinstance(data, dict):
        raise RequestError("request root must be an object")
    unknown = set(data) - {"schema","id","runner","timeout_minutes","setup_profile","argv","artifact_name","artifact_relpath"}
    if unknown:
        raise RequestError(f"unknown request fields: {sorted(unknown)}")
    if data.get("schema") != SCHEMA:
        raise RequestError(f"schema must be {SCHEMA}")
    rid = data.get("id")
    if not isinstance(rid, str) or not ID_RE.fullmatch(rid):
        raise RequestError("id must be 3-96 lowercase safe identifier characters")
    if data.get("runner") not in ALLOWED_RUNNERS:
        raise RequestError(f"runner is not admitted: {data.get('runner')!r}")
    timeout = data.get("timeout_minutes")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_TIMEOUT_MINUTES:
        raise RequestError(f"timeout_minutes must be 1-{MAX_TIMEOUT_MINUTES}")
    setup = data.get("setup_profile", "none")
    if setup not in ALLOWED_SETUP_PROFILES:
        raise RequestError(f"setup_profile is not admitted: {setup!r}")
    argv = data.get("argv")
    if not isinstance(argv, list) or not argv or len(argv) > MAX_ARGC or not all(isinstance(x, str) and x for x in argv):
        raise RequestError(f"argv must contain 1-{MAX_ARGC} non-empty strings")
    if sum(len(x.encode()) for x in argv) > MAX_ARG_BYTES:
        raise RequestError("argv exceeds byte budget")
    if argv[0] not in {"python3", "python"} or len(argv) < 2:
        raise RequestError("v1 admits only direct Python entrypoints")
    script = _safe_relpath(argv[1], "argv[1]")
    if not script.startswith("scripts/") or not script.endswith(".py"):
        raise RequestError("v1 admits only scripts/*.py entrypoints")
    artifact_name = data.get("artifact_name")
    if not isinstance(artifact_name, str) or not ID_RE.fullmatch(artifact_name):
        raise RequestError("artifact_name must use safe lowercase identifier characters")
    _safe_relpath(data.get("artifact_relpath", ""), "artifact_relpath")
    return data

def normalized_plan(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "id": request["id"], "runner": request["runner"],
        "timeout_minutes": request["timeout_minutes"], "setup_profile": request.get("setup_profile", "none"),
        "argv": request["argv"], "artifact_name": request["artifact_name"],
        "artifact_relpath": request["artifact_relpath"], "request_sha256": _digest(request),
    }

def write_github_output(plan: dict[str, Any], output: pathlib.Path) -> None:
    fields = {
        "request_id": plan["id"], "runner": plan["runner"], "timeout_minutes": str(plan["timeout_minutes"]),
        "artifact_name": plan["artifact_name"], "artifact_relpath": plan["artifact_relpath"],
        "request_sha256": plan["request_sha256"],
    }
    with output.open("a", encoding="utf-8") as fh:
        for key, value in fields.items():
            fh.write(f"{key}={value}\n")

def _expand_arg(value: str) -> str:
    expanded = value.replace("{runner_temp}", os.environ.get("RUNNER_TEMP", ""))
    expanded = expanded.replace("{workspace}", os.environ.get("GITHUB_WORKSPACE", ""))
    if "{" in expanded or "}" in expanded:
        raise RequestError(f"unsupported placeholder in argument: {value!r}")
    return expanded

def execute(request: dict[str, Any], expected_digest: str) -> int:
    plan = normalized_plan(request)
    if plan["request_sha256"] != expected_digest:
        raise RequestError("request digest changed between planning and execution")
    if plan["setup_profile"] != "none":
        raise RequestError("unimplemented setup profile")
    artifact = pathlib.Path(os.environ["RUNNER_TEMP"]) / plan["artifact_relpath"]
    artifact.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run([_expand_arg(x) for x in plan["argv"]], check=False)
    return int(completed.returncode)

def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    pp = sub.add_parser("plan")
    pp.add_argument("--request", required=True); pp.add_argument("--github-output")
    pe = sub.add_parser("execute")
    pe.add_argument("--request", required=True); pe.add_argument("--expected-digest", required=True)
    args = parser.parse_args()
    try:
        request = load_request(pathlib.Path(args.request))
        if args.command == "plan":
            plan = normalized_plan(request)
            if args.github_output:
                write_github_output(plan, pathlib.Path(args.github_output))
            print(json.dumps(plan, sort_keys=True))
            return 0
        return execute(request, args.expected_digest)
    except RequestError as exc:
        print(f"gha workload request rejected: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
