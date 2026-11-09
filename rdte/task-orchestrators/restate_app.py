"""Public synthetic Restate endpoint for ARM64 integration qualification.
No external effects beyond locally generated tempfile test receipts.
This initial handler does NOT yet journal individual steps; it is only
a real service registration, ingress, invocation, and receipt test.
"""
from pathlib import Path
import restate
from bench import action, verify

service = restate.Service("bakeoff")

@service.handler()
async def run(ctx: restate.Context, root: str) -> str:
    # No external inputs besides runner-generated temp path; runner is disposable.
    path = Path(root)
    for name in ("prepare", "branch_a", "branch_b", "verify"):
        action(path, name)
    verify(path)
    return "verified"

app = restate.app(services=[service])
