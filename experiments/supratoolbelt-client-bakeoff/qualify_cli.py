#!/usr/bin/env python3
"""Credential-free RDTE: exercise real OpenCode V2 and Qwen Code MCP configuration.

Configuration is an interface contract, not proof of an authenticated MCP session.
For full C1/C2 qualification a real CLI must discover and invoke a local synthetic
gateway with an admitted inference entitlement (not part of this C0 workcell).
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

URL = "http://127.0.0.1:39200/mcp"
CONTEXTS = {
    "research": "SUPRATOOLBELT_RESEARCH_RDTE_TOKEN",
    "engineering": "SUPRATOOLBELT_ENGINEERING_RDTE_TOKEN",
}

def cli(executable, home, workspace, *args):
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["XDG_DATA_HOME"] = str(home / ".local" / "share")
    env["XDG_CACHE_HOME"] = str(home / ".cache")
    env["CI"] = "true"
    env["NO_COLOR"] = "1"
    env["OPENCODE_DISABLE_AUTOUPDATE"] = "true"
    env["QWEN_CODE_NO_RELAUNCH"] = "1"
    for name in CONTEXTS.values():
        env[name] = "synthetic-not-an-auth-token-" + name
    completed = subprocess.run(
        [executable, *args], cwd=workspace, env=env, text=True,
        capture_output=True, timeout=90,
    )
    if completed.returncode:
        raise RuntimeError(
            f"{executable} {' '.join(args[:3])}: exit={completed.returncode}; "
            f"stderr={completed.stderr[-600:]}"
        )
    return completed.stdout + completed.stderr

def check_opencode(home, workspace, envname):
    manifest = {
        "$schema": "https://opencode.ai/config.json",
        "mcp": {"servers": {"supra-toolbelt": {
            "type": "remote",
            "url": URL,
            "oauth": False,
            "disabled": True,
            "protocol": "2026-07-28",
            "pool": False,
            "headers": {"Authorization": "Bearer {env:" + envname + "}"},
        }}},
    }
    target = workspace / "opencode.json"
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    out = cli("opencode", home, workspace, "mcp", "list")
    saved = json.loads(target.read_text())
    actual = saved["mcp"]["servers"]["supra-toolbelt"]
    assert actual["type"] == "remote" and actual["url"] == URL
    assert actual["protocol"] == "2026-07-28"
    assert actual["headers"]["Authorization"] == "Bearer {env:" + envname + "}"
    assert "supra-toolbelt" in out.lower(), "real CLI did not recognize configured MCP server"
    return {"nativeConfig": "opencode.json", "registered": True,
            "protocol": "2026-07-28", "configuredDisabledToAvoidUnapprovedNetwork": True}

def check_qwen(home, workspace, envname):
    # Qwen uses mcpServers under project .qwen/settings.json; no token is supplied.
    out = cli("qwen", home, workspace, "mcp", "add", "--scope", "project",
              "--transport", "http", "supra-toolbelt", URL)
    target = workspace / ".qwen" / "settings.json"
    if not target.exists():
        raise AssertionError("Qwen did not write project-scoped settings.json")
    config = json.loads(target.read_text())
    entry = config["mcpServers"]["supra-toolbelt"]
    assert entry.get("httpUrl") == URL
    listed = cli("qwen", home, workspace, "mcp", "list")
    assert "supra-toolbelt" in listed.lower(), "real Qwen CLI did not list configured server"
    return {"nativeConfig": ".qwen/settings.json", "registered": True,
            "protocol": "streamable-http", "projectScoped": True}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", choices=["opencode", "qwen"], required=True)
    args = parser.parse_args()
    root = Path("rdte-client-contexts").absolute()
    root.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema": "m1-supratoolbelt-cli-config-rdte-v1",
        "client": args.client,
        "profiles": {},
        "checks": {},
        "passed": False,
        "limitations": [
            "C0 configuration and installation qualification only",
            "No real MCP server connection, LLM inference, OAuth, or live tool calls",
            "No private repo or auth credentials on GitHub Actions",
            "External per-request gateway authorization is not replaced by CLI config",
        ],
    }
    try:
        version = cli(args.client, root, root, "--version").strip()
        receipt["cliVersion"] = version[:140]
        for context, envname in CONTEXTS.items():
            home = root / context / "home"
            workspace = root / context / "workspace"
            home.mkdir(parents=True, exist_ok=True)
            workspace.mkdir(parents=True, exist_ok=True)
            if args.client == "opencode":
                detail = check_opencode(home, workspace, envname)
            else:
                detail = check_qwen(home, workspace, envname)
            receipt["profiles"][context] = detail | {"envRef": envname}
        # Neither client should ever serialize the dummy token or alter the other context.
        for context in CONTEXTS:
            workspace = root / context / "workspace"
            for config in workspace.rglob("*.json"):
                content = config.read_text()
                if "synthetic-not-an-auth-token-" in content:
                    raise AssertionError("dummy token persisted to client configuration")
        receipt["checks"]["two-independent-workspaces"] = len(receipt["profiles"]) == 2
        first = root / "research" / "workspace"
        second = root / "engineering" / "workspace"
        shutil.rmtree(first)
        receipt["checks"]["other-context-survives-disposal"] = (
            (second / ("opencode.json" if args.client == "opencode"
                       else ".qwen/settings.json")).exists()
        )
        receipt["checks"]["credential-nonpersistence"] = True
        receipt["passed"] = all(receipt["checks"].values())
    except Exception as exc:
        receipt["failure"] = repr(exc)[:900]
    Path("client-rdte-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["passed"] else 1

if __name__ == "__main__":
    sys.exit(main())
