# MCP GHA: parallel public-runner qualifications

**Authority:** public-safe synthetic transport/custody qualification in
[draft PR #557](https://github.com/SemperSupra/agent-dispatch/pull/557).
Private Search Adapters #240 owns the reference-versus-CPE scientific
experiment; private CPE #229 owns treatment validity and blinded Stage P;
Agent Dispatch private #485 owns admission and actor workcell control.

## Native topology (no cross-arm oracle)

- **Two parallel physical GitHub-hosted VMs:** independently run the
  fixed public reference and CPE-labelled synthetic query plans with
  fresh local SearXNG; upload only sanitized `receipt.json` and
  `result.age`, encrypted to disposable, local test recipients.
- **One dependent public collector VM:** starts *after both arms* finish,
  resolves exact GitHub-native job/artifact IDs, retrieves both by ID,
  checks signed-by-nobody receipt consistency, stages ciphertext in a
  private-mode **ephemeral test directory**, and tests idempotent replay.
- **Three independent Go race-test VMs:** admission/manifest checks;
  file staging/replay/concurrency negative controls; and native
  GitHub/composite-source checks. Each targets only its own tests with
  `go test -race -count=12` and `GOPROXY=off`. Fail-fast disabled,
  `max-parallel: 3`, no mutable Actions write token.
- **One separate static policy VM:** checks exact permission boundaries,
  pinned action commits, no `secrets` expressions, one-day synthetic
  artifact retention, two-arm native IDs and v2 source provenance.
- **Existing read-only baseline CI:** independently runs the whole Go
  race/vet/build and historical GitHub observation regression.

Runner unit is an ephemeral GitHub-hosted VM with standard `ubuntu-24.04`,
not a private enclave. Public runners may see public synthetic queries,
source and test data. They **must never** receive full private CPE code,
private keys, confidential assignments, rights-limited source copies
or held-out grading oracles. They do not become confidential by
encrypting outbound artifacts.

## Observed qualification, 2026-10-28

- [First parallel public-runner run #40629498974](https://github.com/SemperSupra/agent-dispatch/actions/runs/40629498974):
  all three isolated Go race/negative-control workstreams **SUCCESS**,
  while static policy gate **FAILED** on a checker self-match: the forbidden
  literal `secrets.` appeared in the scanner's own source code, not in
  an actual GitHub Actions expression.
- **Correction:** match actual YAML permission lines and real GitHub
  expression syntax, rather than substring-scanning its own source text.
  Do not weaken the requirement of no Actions write, no secrets
  references, and pinned exact action revisions.
- [Native parallel run #40629592489](https://github.com/SemperSupra/agent-dispatch/actions/runs/40629592489):
  **4/4 independent jobs SUCCESS**. Three separate public Go jobs each
  ran their bounded subtest class 12 times under `-race`; the fourth
  completed the separate public-only source-policy gate.
- [Two-arm artifact round-trip on same corrected head](https://github.com/SemperSupra/agent-dispatch/actions/runs/40629592463)
  and [baseline read-only Go qualification](https://github.com/SemperSupra/agent-dispatch/actions/runs/40629592460)
  are independent jobs that must each be checked before the final
  source-acceptance baton; a green parallel race matrix alone does not
  prove live retrieval or artifact transport.

## Three audiences

| Audience | Read/observe | Control/hold |
| --- | --- | --- |
| Human | Native GitHub Actions matrix job status, summaries and DLE | Review draft PR #557; owner-controlled merge and deployment |
| Automation | `go test -race`, typed Go `describe`, `verify-receipt`, `stage-pair`, `verify-native-pair` | Fail closed on mismatch, never auto-promote evidence |
| Agent | Authorized Agent Dispatch DLE assignments, GitHub native run/artifact observation, next baton | Private host admission/decrypt/source-rights/Stage P remain distinct gates |

## Next execution choices

1. Keep the existing parallel branches and source-only tests; do **not**
   serially add independent work just for convenience.
2. For actual protected experiments, freeze two independently authorized
   plans and precommit source roles before dispatch. Genuine CPE treatment
   and blinded reference ancestry cannot be inferred from a label on a
   public synthetic fixture.
3. Admit an owner-controlled private host and persistent public
   encryption recipient (private age identity stays only in a trusted
   vault), then add independently observed, durable artifact re-intake.
   Current ephemeral GHA results expire and do not meet this gate.
4. Audit whether a public source projection or sanctioned sealed
   workcell is sufficient for each confidential task before dispatch.
   Do not expose held-out or rights-limited source data on a public VM.

**Explicit holds:** PRs #555 and #557 remain draft until separate review;
#556 is already merged on main. No private source exposure, secret
distribution, production deployment, cancellation privileges, owner
merge, scientific adjudication or canonical CPE acceptance is implied
by passing synthetic CI.
