#!/usr/bin/env python3
import argparse
import json
import os
import queue
import subprocess
import tempfile
import threading
import time
from pathlib import Path

READ_ONLY_METHODS = [
    ("config/read", {}),
    ("configRequirements/read", {}),
    ("experimentalFeature/list", {}),
    ("collaborationMode/list", {}),
    ("model/list", {}),
    ("plugin/list", {}),
    ("permissionProfile/list", {}),
    ("app/list", {}),
    ("mcpServerStatus/list", {}),
    ("skills/list", {}),
    ("windowsSandbox/readiness", None),
    ("thread/realtime/listVoices", {}),
    ("remoteControl/status/read", None),
    ("thread/list", {}),
    ("account/read", None),
    ("account/rateLimits/read", None),
    ("account/usage/read", None),
    ("account/workspaceMessages/read", None),
]

AUTH_ENV_NAMES = [
    "ACCESS_TOKEN",
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
    "OPENAI_ACCESS_TOKEN",
    "CHATGPT_ACCESS_TOKEN",
]

def summarize(value):
    if isinstance(value, dict):
        summary = {"type": "object", "keys": sorted(value.keys())[:80]}
        for key in ("models", "items", "data", "plugins", "apps", "skills", "threads"):
            child = value.get(key)
            if isinstance(child, list):
                summary[f"{key}_count"] = len(child)
        return summary
    if isinstance(value, list):
        return {"type": "array", "count": len(value)}
    return {"type": type(value).__name__, "value_present": value is not None}

def classify_error(err):
    message = str(err.get("message", ""))
    lower = message.lower()
    if any(word in lower for word in ("auth", "login", "token", "credential", "unauthorized", "forbidden")):
        return "AUTH_REQUIRED"
    if any(word in lower for word in ("invalid params", "missing", "required field", "deserialize")):
        return "INVALID_PARAMS"
    return "ERROR"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    env = os.environ.copy()
    for name in AUTH_ENV_NAMES:
        env.pop(name, None)

    isolated_home = tempfile.mkdtemp(prefix="suprachat-codex-guest-")
    env["CODEX_HOME"] = isolated_home
    env["XDG_CONFIG_HOME"] = str(Path(isolated_home) / "xdg-config")
    env["XDG_DATA_HOME"] = str(Path(isolated_home) / "xdg-data")

    cmd = [
        args.codex,
        "app-server",
        "--listen", "stdio://",
        "-c", 'model_provider="openai_chatgpt_plan"',
        "-c", 'model_providers.openai_chatgpt_plan.name="ChatGPT plan"',
        "-c", 'model_providers.openai_chatgpt_plan.base_url="https://api.openai.com/v1"',
        "-c", 'model_providers.openai_chatgpt_plan.env_key="ACCESS_TOKEN"',
        "-c", "model_providers.openai_chatgpt_plan.wire_api=\"responses\"",
        "-c", "model_providers.openai_chatgpt_plan.requires_openai_auth=false",
        "-c", "model_providers.openai_chatgpt_plan.supports_websockets=false",
    ]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )

    stdout_q = queue.Queue()
    stderr_lines = []

    def read_stdout():
        try:
            for line in proc.stdout:
                stdout_q.put(line.rstrip("\r\n"))
        finally:
            stdout_q.put(None)

    def read_stderr():
        for line in proc.stderr:
            stderr_lines.append(line.rstrip("\r\n"))
            if len(stderr_lines) > 200:
                del stderr_lines[:50]

    threading.Thread(target=read_stdout, daemon=True).start()
    threading.Thread(target=read_stderr, daemon=True).start()

    next_id = 1
    server_requests = []

    def send(payload):
        proc.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        proc.stdin.flush()

    def request(method, params, timeout):
        nonlocal next_id
        req_id = str(next_id)
        next_id += 1
        payload = {"id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
        send(payload)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.05, deadline - time.monotonic())
            try:
                line = stdout_q.get(timeout=remaining)
            except queue.Empty:
                break
            if line is None:
                break
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            msg_id = msg.get("id")
            msg_method = msg.get("method")
            if msg_id is not None and msg_method is not None:
                server_requests.append(msg_method)
                send({
                    "id": msg_id,
                    "error": {
                        "code": -32000,
                        "message": "SupraChat guest probe denies all server requests"
                    }
                })
                continue

            if str(msg_id) != req_id:
                continue

            if "error" in msg:
                err = msg["error"] if isinstance(msg["error"], dict) else {"message": str(msg["error"])}
                return {
                    "outcome": classify_error(err),
                    "error_code": err.get("code"),
                    "error_message": str(err.get("message", ""))[:500],
                }
            return {
                "outcome": "RESULT",
                "result_summary": summarize(msg.get("result")),
            }

        return {"outcome": "TIMEOUT"}

    evidence = {
        "schema": "suprachat-codex-guest-probe/v1",
        "authorization": {
            "openai_credentials_provided": False,
            "removed_environment_names": AUTH_ENV_NAMES,
            "isolated_codex_home": True,
        },
        "codex": str(Path(args.codex).name),
        "initialize": None,
        "methods": {},
        "server_requests_denied": [],
    }

    try:
        evidence["initialize"] = request(
            "initialize",
            {
                "clientInfo": {
                    "name": "suprachat-guest-probe",
                    "title": "SupraChat guest probe",
                    "version": "0.1.0",
                },
                "capabilities": {"experimentalApi": True},
            },
            args.timeout,
        )

        if evidence["initialize"]["outcome"] == "RESULT":
            send({"method": "initialized"})
            for method, params in READ_ONLY_METHODS:
                evidence["methods"][method] = request(method, params, args.timeout)
    finally:
        evidence["server_requests_denied"] = sorted(set(server_requests))
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    evidence["process_exit_code"] = proc.poll()
    evidence["stderr_tail"] = stderr_lines[-30:]

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps({
        "schema": evidence["schema"],
        "initialize": evidence["initialize"],
        "method_outcomes": {k: v["outcome"] for k, v in evidence["methods"].items()},
        "server_requests_denied": evidence["server_requests_denied"],
        "output": str(output),
    }, indent=2, sort_keys=True))

    if evidence["initialize"]["outcome"] in ("TIMEOUT",):
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
