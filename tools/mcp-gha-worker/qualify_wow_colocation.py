#!/usr/bin/env python3
"""Bounded public-safe co-location probe: synthetic MCP + public WOW Sidecar.

No credentials, private source, arbitrary shell, remote endpoints or mutation routes.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

class QualificationError(Exception):
    pass

def fetch_json(url, payload=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        url, data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"} if payload is not None else {},
        method="POST" if payload is not None else "GET")
    with opener.open(request, timeout=2) as response:
        data = response.read(65537)
        if len(data) > 65536:
            raise QualificationError("oversized_response")
        return json.loads(data)

def await_health(processes, url):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if any(process.poll() is not None for process in processes):
            raise QualificationError("premature_process_exit")
        try:
            value = fetch_json(url)
            if value.get("status") == "ok":
                return value
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise QualificationError("health_timeout")

def run(args):
    receipt = {
        "schema": "agent-dispatch.public-mcp-wow-colocation.v1",
        "scope": "public-synthetic-loopback-only",
        "wow_source_sha": args.wow_revision,
        "status": "FAIL", "first_failure": None, "cleanup": "NOT_STARTED",
        "openai_tunnel_used": False, "private_source_used": False,
        "credential_used": False, "actuator_invoked": False,
    }
    root = None
    processes = []
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.wow_revision):
            raise QualificationError("invalid_wow_revision")
        if args.receipt.exists():
            raise QualificationError("receipt_already_exists")
        if not args.mcp_binary.is_file() or not args.wow_binary.is_file():
            raise QualificationError("missing_binary")
        root = Path(tempfile.mkdtemp(prefix="mcp-wow-public-", dir=os.environ.get("RUNNER_TEMP")))
        wow_state = root / "wow"
        wow_state.mkdir()
        # Do not inherit GitHub credentials, proxies, site-specific configuration,
        # or arbitrary WOW control and peer-rendezvous environment variables.
        base_env = {"PATH": "/usr/bin:/bin", "LANG": "C"}
        wow_env = dict(base_env, WOW_NODE_ID="ci-synthetic-embodiment",
                       WOW_LOCALITY="cloud", WOW_LISTEN_ADDR="127.0.0.1:18766",
                       WOW_GENERATION_STATE_FILE=str(wow_state / "generation.json"),
                       WOW_LEASE_SECONDS="15")
        with open(os.devnull, "wb") as quiet:
            wow = subprocess.Popen([str(args.wow_binary.resolve())], env=wow_env,
                                   stdin=subprocess.DEVNULL, stdout=quiet, stderr=quiet)
            processes.append(wow)
            mcp = subprocess.Popen([str(args.mcp_binary.resolve()), "--listen", "127.0.0.1:18765"],
                                   env=base_env, stdin=subprocess.DEVNULL,
                                   stdout=quiet, stderr=quiet)
            processes.append(mcp)
            await_health(processes, "http://127.0.0.1:18765/healthz")
            wow_health = await_health(processes, "http://127.0.0.1:18766/healthz")
            card = fetch_json("http://127.0.0.1:18766/v1/card")
            if (wow_health.get("source_revision") != args.wow_revision
                    or wow_health.get("node_id") != "ci-synthetic-embodiment"
                    or card.get("schema") != "wow-sidecar.embodiment-card.v1"
                    or card.get("node_id") != "ci-synthetic-embodiment"
                    or card.get("capabilities") != ["system.identity"]
                    or card.get("endpoints") != []
                    or card.get("incarnation_id") != wow_health.get("incarnation_id")
                    or card.get("generation") != wow_health.get("generation")):
                raise QualificationError("wow_identity_mismatch")
            rpc_url = "http://127.0.0.1:18765/mcp"
            listed = fetch_json(rpc_url, {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}})
            tools = listed.get("result", {}).get("tools", [])
            if [tool.get("name") for tool in tools] != ["worker_ping"]:
                raise QualificationError("tool_allowlist_mismatch")
            ping = fetch_json(rpc_url, {"jsonrpc":"2.0","id":2,"method":"tools/call",
                                        "params":{"name":"worker_ping","arguments":{}}})
            if ping.get("result", {}).get("content", [{}])[0].get("text") != "PUBLIC_SYNTHETIC_MCP_WORKER_OK":
                raise QualificationError("mcp_ping_mismatch")
            denied = fetch_json(rpc_url, {"jsonrpc":"2.0","id":3,"method":"tools/call",
                                          "params":{"name":"dispatch_execution","arguments":{}}})
            if denied.get("error", {}).get("code") != -32602:
                raise QualificationError("mcp_write_not_denied")
            try:
                fetch_json("http://127.0.0.1:18766/v1/peer/rendezvous", {})
                raise QualificationError("wow_mutation_route_exposed")
            except urllib.error.HTTPError as err:
                if err.code != 404:
                    raise QualificationError("unexpected_wow_mutation_status") from err
            receipt["mcp"] = "PING_AND_WRITE_DENIAL_PASS"
            receipt["wow"] = "CARD_AND_MUTATION_ROUTE_DENIAL_PASS"
    except Exception as exc:
        receipt["first_failure"] = str(exc) if isinstance(exc, QualificationError) else type(exc).__name__
    finally:
        errors = []
        for process in reversed(processes):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                errors.append("forced_termination")
        if any(process.poll() is None for process in processes):
            errors.append("live_child_after_cleanup")
        if root is not None:
            try:
                shutil.rmtree(root)
            except OSError:
                errors.append("temp_cleanup_failed")
        receipt["cleanup"] = "FAIL" if errors else "PASS"
        receipt["remaining_processes"] = sum(process.poll() is None for process in processes)
        if errors and receipt["first_failure"] is None:
            receipt["first_failure"] = errors[0]
        if receipt["first_failure"] is None:
            receipt["status"] = "PASS"
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        try:
            with args.receipt.open("x", encoding="utf-8") as out:
                json.dump(receipt, out, sort_keys=True, indent=2)
                out.write("\n")
        except OSError:
            return 2
    return 0 if receipt["status"] == "PASS" else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp-binary", type=Path, required=True)
    parser.add_argument("--wow-binary", type=Path, required=True)
    parser.add_argument("--wow-revision", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    return run(args)

if __name__ == "__main__":
    sys.exit(main())
