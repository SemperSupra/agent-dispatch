"""Read-only TrueNAS 25.04.2.6 G1a middleware status reducer.

Only accepts a caller-supplied RPC function; never creates a session or changes state.
"""
TARGET = "TrueNAS-25.04.2.6"
ALLOWED = ("system.version", "docker.status", "docker.config")
STATES = {"RUNNING", "PENDING", "STOPPED", "INITIALIZING", "STOPPING", "UNCONFIGURED", "FAILED"}


def observe(call):
    out = {"schema": "book2epub-g1a-middleware-observe/v1",
           "classification": "BLOCKED_OBSERVATION",
           "guest_identity_verified": False,
           "network_reachability_verified": False,
           "registry_trust_verified": False,
           "image_pull_verified": False,
           "physical_apply": "HOLD",
           "observations": {}}
    try:
        version = call(ALLOWED[0])
        if version != TARGET:
            out["observations"]["version_match"] = False
            return out
        out["observations"]["version_match"] = True
        service = call(ALLOWED[1])
        if not isinstance(service, dict) or service.get("status") not in STATES:
            return out
        out["observations"]["service_status"] = service["status"]
        config = call(ALLOWED[2])
        if not isinstance(config, dict) or "pool" not in config:
            return out
        pool = config["pool"]
        if pool is not None and (not isinstance(pool, str) or not pool.strip()):
            return out
        out["observations"]["apps_pool_configured"] = isinstance(pool, str)
        if service["status"] == "RUNNING" and isinstance(pool, str):
            out["classification"] = "MIDDLEWARE_STATUS_OBSERVED_GUEST_UNVERIFIED"
    except Exception:
        out["observations"]["failure"] = "read_only_rpc_error"
    return out
