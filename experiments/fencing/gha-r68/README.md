# R68 — native public GitHub Actions correlation (read-only)

This bounded fixture, invoked from a **public** pull-request GitHub Actions runner, reads **its own** native workflow run through the official GitHub REST GET endpoint using the ephemeral `GITHUB_TOKEN` with `actions: read`. It binds observed repository, event, run ID, attempt, workflow ID and API HEAD SHA, and runs negative controls for mismatches. It does **not** submit `workflow_dispatch`, call private endpoints, create an effect or use a token with write privileges.

Native probe: `python3 experiments/fencing/gha-r68/receipt.py --native` inside this exact public workflow only. Offline: `python3 -m unittest discover -s experiments/fencing/gha-r68 -p 'test_*.py' -v`.

**Acceptance boundary:** a provider's acknowledged run ID can support correlation/readback; it does **not** prove native `workflow_dispatch` attribution for a real accepted workset, exactly-once submission after an ACK loss, commit-time fencing, native effect idempotency, authenticated cross-host authority or production execution. API `head_sha` is *not* assumed equal to a PR checkout merge SHA. No user/personal token, private Actions minutes, secrets, or production worksets. This tests the read-only observation half of an effect/UNKNOWN boundary, not admission or dispatch.
