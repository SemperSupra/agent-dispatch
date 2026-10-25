# Public-source agent execution rep

Status: first one-use FolioRelay rep failed closed at Actions run 40214545018;
the assignment is consumed. This public repo provides execution mechanics
only. The first task is the exact FolioRelay Keycloak catalog source audit in
`tasks/foliorelay-keycloak-catalog-audit.md`. The private workset and project
qualification authority decide placement and acceptance.

`jules-public-source-agent.yml` accepts only the registered workset,
delegation, assignment and a protected-side age X25519 public recipient. The
workflow runs from `main` in the existing protected `jules-dispatch`
environment, verifies that the Jules Source is the exact public Foundry
repository, and compares the task bytes with their registered SHA-256. The
single-assignment gate rejects a prior Actions attempt or an existing
same-title Jules session. An ambiguous provider POST or timeout is UNKNOWN;
there is no automatic retry or session adoption.

The provider receives only a public-source prompt and public Source. Its
instruction forbids repository edits and PR creation; the API does not request
automatic PR creation. A Jules workspace may still change internally, so the
workflow does not assert read-only provider execution. It requires provider
`COMPLETED` and checks the final message's required sections. It encrypts the
completed native message even when those sections are missing; in that case
the workflow fails the content contract and the sealed message remains
unreviewed for trusted-side recovery. Its public artifact contains only
`result.age` and a small correlation/integrity receipt, with seven-day
retention. Logs contain no finding text. The trusted private pickup and
independent source review happen outside this repository.

This rep does not perform TrueNAS runtime qualification, grant HIL access,
accept an agent finding, or configure the WOW Sidecar product cutover. A
second assignment needs its own exact authority and task binding; this
registered task is intentionally narrow while the general transport is
qualified.
