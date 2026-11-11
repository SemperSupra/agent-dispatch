#!/usr/bin/env python3
"""RDTE only: exercise the real Codex CLI MCP config lifecycle without model/API credentials.

Three isolated CODEX_HOME contexts may map to three independent agent logins.
This verifies client configuration and secret non-persistence, NOT authenticated
MCP tool discovery, actual provider sign-in, or real Tool Belt authorization.
"""
import json
import os
import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path("codex-rdte-contexts").absolute()
BASE_URL = "http://127.0.0.1:39200/mcp"
PROFILES = {
    "research": "SUPRATOOLBELT_RESEARCH_RDTE_TOKEN",
    "engineering": "SUPRATOOLBELT_ENGINEERING_RDTE_TOKEN",
    "operations": "SUPRATOOLBELT_OPERATIONS_RDTE_TOKEN",
}

def cmd(home, *args):
    env = dict(os.environ)
    env["CODEX_HOME"] = str(home)
    for key in PROFILES.values():
        env[key] = "synthetic-secret-would-never-be-written-" + key
    result = subprocess.run(["codex", *args], env=env, text=True, capture_output=True, timeout=50)
    if result.returncode:
        # CLI diagnostic only. No tokens are ever given on its arguments or in its config.
        raise RuntimeError(f"{' '.join(args[:3])}: exit={result.returncode}: {result.stderr[:450]}")
    return result.stdout

def verify():
    ROOT.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema": "supra-toolbelt-codex-mcp-config-rdte-v1",
        "codexVersion": subprocess.check_output(["codex", "--version"], text=True).strip(),
        "profiles": {},
        "checks": {},
        "passed": False,
        "limitations": [
            "real Codex CLI registration, retrieval and removal only",
            "no model/API login, no actual MCP tool discovery or invocation",
            "no user OAuth, provider entitlement, or remote ChatGPT tunnel qualification",
            "bearer environment variable names are not authorization proof",
        ],
    }
    for profile, env_name in PROFILES.items():
        home = ROOT / profile
        home.mkdir(parents=True, exist_ok=True)
        cmd(home, "mcp", "add", "supra-toolbelt", "--url", BASE_URL,
            "--bearer-token-env-var", env_name)
        listed = json.loads(cmd(home, "mcp", "list", "--json"))
        got = json.loads(cmd(home, "mcp", "get", "supra-toolbelt", "--json"))
        config_text = (home / "config.toml").read_text()
        parsed = tomllib.loads(config_text)
        candidate = parsed.get("mcp_servers", {}).get("supra-toolbelt", {})
        if candidate.get("url") != BASE_URL:
            raise AssertionError(f"{profile}: incorrect HTTP URL")
        if candidate.get("bearer_token_env_var") != env_name:
            raise AssertionError(f"{profile}: incorrect environment binding")
        if "synthetic-secret-would-never-be-written" in config_text:
            raise AssertionError("synthetic environment token value leaked to config")
        if not listed or not got:
            raise AssertionError(f"{profile}: list/get returned empty")
        receipt["profiles"][profile] = {
            "url": BASE_URL,
            "bearerTokenEnvVar": env_name,
            "configurationIsolated": True,
            "registeredViaRealCli": True,
            "listedViaRealCli": True,
            "retrievedViaRealCli": True,
        }
    # Modify exactly one context and ensure the others are unaffected.
    cmd(ROOT / "research", "mcp", "remove", "supra-toolbelt")
    research_after = tomllib.loads((ROOT / "research" / "config.toml").read_text())
    receipt["checks"]["research-removed"] = "supra-toolbelt" not in research_after.get("mcp_servers", {})
    for profile in ("engineering", "operations"):
        config = tomllib.loads((ROOT / profile / "config.toml").read_text())
        receipt["checks"][profile + "-survives-other-context-delete"] = (
            config["mcp_servers"]["supra-toolbelt"]["bearer_token_env_var"] == PROFILES[profile]
        )
    receipt["checks"]["profile-count"] = len(receipt["profiles"]) == 3
    receipt["passed"] = all(receipt["checks"].values())
    return receipt

def main():
    try:
        receipt = verify()
    except Exception as exc:
        receipt = {
            "schema": "supra-toolbelt-codex-mcp-config-rdte-v1",
            "passed": False,
            "failure": repr(exc)[:700],
        }
    pathlib.Path("codex-rdte-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["passed"] else 1

if __name__ == "__main__":
    sys.exit(main())
