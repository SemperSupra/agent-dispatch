#!/usr/bin/env python3
"""Public-safe static qualification of candidate MCP aggregation implementations.

Evidence-only: no secrets, private source, provider credentials, or live exposure.
Never turn static source evidence into a claim of runtime security.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

CANDIDATES = {
    "mcphub": {
        "repo": "https://github.com/samanhappy/mcphub.git",
        "checks": [
            ("src/services/authorizationService.ts", "server.invoke", "server admission action"),
            ("src/services/toolPolicyService.ts", "filterTools", "tool filtering"),
            ("src/services/principalRuntimeService.ts", "principal.username", "principal-isolated runtime"),
            ("src/services/activityLoggingService.ts", "storeToolPayload !== false", "payload-default audit hazard"),
            ("src/services/activityLoggingService.ts", "Don't let logging failures affect the main flow", "audit fail-open hazard"),
        ],
    },
    "obot": {
        "repo": "https://github.com/obot-platform/obot.git",
        "checks": [
            ("pkg/vmcp/profiles.go", "func AllowedTools(", "per-component grants"),
            ("pkg/vmcp/profiles.go", "grant == nil", "nil-vs-empty grant risk"),
            ("pkg/mcp/vmcp.go", "component.DisableTools = len(tools) == 0", "empty intersection disables tools"),
            ("pkg/mcp/session_recovery.go", "safeToReplay :=", "non-blind recovery"),
            ("pkg/mcp/auditlogs/auditlog.go", "RequestBody", "raw payload possible"),
        ],
    },
    "agentgateway": {
        "repo": "https://github.com/agentgateway/agentgateway.git",
        "checks": [
            ("crates/agentgateway/src/mcp/rbac.rs", "if !self.0.has_rules()", "missing policy hazard"),
            ("crates/agentgateway/src/mcp/rbac.rs", "return true;", "empty rules acceptance"),
            ("crates/agentgateway/src/mcp/handler.rs", "async fn resolve_unprefixed(", "unprefixed fanout"),
            ("crates/agentgateway/src/mcp/handler.rs", "TODO cache list results", "uncached lookup"),
            ("crates/agentgateway/src/mcp/auth.rs", "McpAuthenticationMode::Permissive", "permissive authentication risk"),
        ],
    },
    "contextforge": {
        "repo": "https://github.com/IBM/mcp-context-forge.git",
        "checks": [
            ("pyproject.toml", "fastapi", "Python API stack"),
            ("mcpgateway", "", "source directory exists"),
        ],
    },
}
def run(argv, cwd=None):
    return subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate", choices=sorted(CANDIDATES), required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    spec = CANDIDATES[args.candidate]
    started = time.monotonic()
    root = Path("candidate-source")
    # Clone only public upstream; the exact commit is recorded in evidence.
    run(["git", "clone", "--depth", "1", "--filter=blob:none", spec["repo"], str(root)])
    revision = run(["git", "rev-parse", "HEAD"], root).stdout.strip()
    checks = []
    for path, needle, label in spec["checks"]:
        f = root / path
        is_dir = f.is_dir()
        content = f.read_text(encoding="utf8", errors="replace") if f.is_file() else ""
        matched = (f.exists() if needle == "" else needle in content)
        checks.append({"path": path, "description": label, "matched": matched,
                       "blob_sha256": hashlib.sha256(content.encode()).hexdigest() if f.is_file() else None,
                       "directory": is_dir})
    receipt = {"schema": "public-safe-mcp-bakeoff-source-v1", "candidate": args.candidate,
               "repo": spec["repo"], "commit": revision,
               "elapsed_seconds": round(time.monotonic()-started,3),
               "static_checks": checks, "passed": all(c["matched"] for c in checks),
               "limitations": ["Static source pattern checks only", "No vulnerability conclusion",
                               "No MCP behavior, runtime, AAA, or free-tier entitlement verified"]}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n")
    print(json.dumps(receipt, indent=2))
    return 0 if receipt["passed"] else 1
if __name__ == "__main__":
    raise SystemExit(main())
