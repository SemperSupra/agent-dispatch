# GHA workload requests

Agent Dispatch should add workload **requests**, not new workflow YAML, when an existing qualified executor shape is sufficient.

The v1 flow is:

`committed request -> fail-closed plan -> stable executor -> native receipt`

`requests/gha/*.json` are repository-controlled inputs. The dispatch input is only a path to one of those committed requests. It is not inline shell and is never evaluated.

## v1 contract

`gha-workload-request/v1` admits an explicit hosted runner label from a small allowlist, a 1-60 minute timeout, setup profile `none`, a direct Python `scripts/*.py` argv, and one receipt/evidence artifact path under `RUNNER_TEMP`.

The executor canonicalizes the request, binds a SHA-256 during planning, and revalidates that digest in the execution job. Workloads run via `subprocess.run(argv)`, not through shell evaluation.

Two initial requests model existing workflow shapes:
- `github-runner-primitive-docker-ubuntu24.json`
- `github-runner-frontier-android-ubuntu24.json`

These are proving requests, not automatic migration authority. Existing workflows remain until before/after receipt equivalence is recorded.

## Deliberate v1 exclusions

Do not generalize these by weakening the contract. Add an audited profile or a different executor only when a second real workload earns it.

Excluded: arbitrary inline shell, user-selected self-hosted labels, arbitrary package installation, service containers, privileged/nested-virtualization setup, secrets/private-value projection, dynamic workflow generation, and semantic PASS inferred from workflow success.

Workload-specific oracles remain authoritative. The executor only provides a stable placement/execution envelope.

Private campaign authority: `SemperSupra/agent-dispatch-private#485`.
