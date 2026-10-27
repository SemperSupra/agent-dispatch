# MCP GHA — paired ciphertext custody candidate

This is an offline, **source-only** candidate stacked as draft PR #557
on read-only controller draft PR #556. Nothing here deploys to a
private host, reads an age secret or makes a scientific claim.

## Native GitHub artifact lifecycle evidence (2026-10-27)

**Source-only test:** [public Actions run 40562713367](https://github.com/SemperSupra/agent-dispatch/actions/runs/40562713367) is a completed **three-job success**.

- Reference VM job **122395739738** uploaded artifact ID
  **12760379376**, name `mcp-gha-artifact-test-reference-40562713367-1`.
- CPE-labelled VM job **122395740256** uploaded artifact ID
  **12760628947**, name `mcp-gha-artifact-test-cpe-40562713367-1`.
- Collector job **122396260895** independently read GitHub's native
  jobs/artifacts, downloaded both archives by their **immutable artifact
  IDs**, verified both receipt/ciphertext hashes, created the two-arm
  manifest and ran `stage-pair` twice. First stage committed, second
  returned `IDEMPOTENT_CIPHERTEXT_ALREADY_STAGED`.

The artifact source itself was an **immutable exact checkout** of the
still-unmerged public Stage R candidate `330c65f4701a3a1e9aa25ad4dc60d06c1477a4fa`,
while the workflow source revision was
`d0505fbb3c52616d2679fdca06b4c4d26fcd5e9c`.
These are **distinct** and the qualification manifest explicitly
identifies the collector source. This is a composite-source transport
test; it **does not pass** the production native one-source attestation
contract. Keep both source revisions in the admission record for any
composed execution and require independent source provenance checks
before ingesting real findings.

Both upstream providers returned three public synthetic results sets per
arm, but the test does **not** qualify actual CPE authority. Disposable
age identity files never left the temporary arm VM. Only encrypted
`result.age` and public-safe `receipt.json` were uploaded; each
artifact has **one-day retention**. No trusted host was reached and the
collector-stage private directory expired with the test job.

**First failures:**
1. Initial test attempted to run Stage R source absent from the stacked
   custody PR. Corrected with pinned, separate checkout rather than
   duplicated source.
2. Initial pinned v4 download-by-artifact-ID placed files one directory
   deeper than the collector expected. Corrected by pinning the
   official `actions/download-artifact` v8.0.2 commit
   `9000827ccba6bdab643e8b6fd33ac0654aef8333`,
   which also fails on artifact digest mismatch by default.

Independent connected GitHub Actions artifact listing confirmed both
IDs, that they belonged to native run 40562713367, and that they were
unexpired at collection. This is a **real GitHub transport acceptance
receipt**, not a retained private research corpus.

## Composite-source qualification contract (v2, synthetic only)

The actual GHA artifact lifecycle workflow in stacked draft PR #557 and
the Stage R collector in draft PR #555 currently have **different**
Git revisions. The original v1 single-source validator correctly refuses
to treat a public PR merge workflow revision as if it were the Stage R
collector revision. The correction is an explicit, **synthetic-only** v2
contract, not a relaxation of production authority.

| Field | Meaning | Source check |
| --- | --- | --- |
| `workflow_head_sha` | GitHub's PR-head SHA for the qualifying run | Native GitHub run/job/artifact `head_sha` |
| `source_sha` | Stage R collector revision actually checked out | Exact pinned collector commit `330c65f4701a3a1e9aa25ad4dc60d06c1477a4fa` and `git rev-parse HEAD` |
| `workflow` | Allowed synthetic artifact-lifecycle workflow path | Exact `.github/workflows/mcp-gha-artifact-lifecycle-qualification.yml` |
| `schema` | Explicit synthetic or single-source contract | v2 composite only for this synthetic suite; v1 remains single-source |

A PR **head SHA is not necessarily the executed workflow merge SHA**.
In a `pull_request` event, GitHub can execute against a generated
merge ref. Therefore this native v2 receipt proves compatibility with
the GitHub-reported head identity and a separately pinned checked-out
collector; it is **not a cryptographic proof of the executed workflow
bytes or of an independent trusted precommit**. Review the pinned
workflow file and exact PR merger before production admission.

The Go command `verify-native-pair --manifest ...` is source-staged
as a read-only GitHub-native run/job/artifact check. It pins the official
GitHub API origin; no arbitrary endpoint is accepted by the CLI, and
`GITHUB_TOKEN` is used only on this fixed Actions origin. The
underlying Go test helper accepts a local mock endpoint for negative
cases. A production private host must independently authorize the
manifest and bind its source authority; the Go command does not grant
that authorization by itself.

The v2 validator admits only the named **public synthetic** workflow,
the fixed collector SHA and `pull_request` event. Its expected arm
labels are `Synthetic sealed reference GHA arm` and
`Synthetic sealed cpe GHA arm`, and its artifacts use the
`mcp-gha-artifact-test-<arm>-<run>-<attempt>` convention.
The v1 validator continues to require the fixed MCP GHA production
workflow, a single source SHA, and owner-authorized workflow events.

## Verified v2 composite-source native evidence

Native Go race/vet/build regression:
[Actions 40588967608](https://github.com/SemperSupra/agent-dispatch/actions/runs/40588967608)
**SUCCESS**. This included v1 preservation, v2 source-role isolation,
mock-GitHub negative tests for incorrect head/job/artifact/event, ciphertext
preflight, staging replay and symlink controls.

Real pinned-source synthetic artifact lifecycle:
[Actions 40588967670](https://github.com/SemperSupra/agent-dispatch/actions/runs/40588967670)
**3/3 jobs SUCCESS**, including both isolated source-checked collectors and
independent ID-based collection into ephemeral ciphertext-only storage.
Connected GitHub Actions API was separately queried after run completion:

| Role | Native job ID | Native artifact ID | GitHub artifact state |
| --- | ---: | ---: | --- |
| Reference | 122487875033 | 12773980261 | 24,055 bytes, unexpired at observation |
| CPE-labelled | 122487874657 | 12772922821 | 23,320 bytes, unexpired at observation |

Native workflow path:
`.github/workflows/mcp-gha-artifact-lifecycle-qualification.yml`;
GitHub-reported PR-head SHA `67796b083d50adfeb98a694b379995ce5dfae0c1`;
separately checked-out collector SHA
`330c65f4701a3a1e9aa25ad4dc60d06c1477a4fa`.
Workflow run attempt **1**, event `pull_request`, terminal
`completed/success`, each arm's native job `completed/success`.
Both native artifacts belonged to the same run and reported the GitHub
head SHA. These are **distinct** source roles, not a single revision.

This checked real GitHub native API data after completion; the new
`verify-native-pair` Go CLI has compiled and passed mocked HTTP negative
tests but was not separately invoked against this completed live run.
Do not claim such a Go-CLI production qualification.

The artifact candidates have **one-day retention** in this synthetic
workflow. Stage output was inside a disposable GHA runner and was
discarded after job completion. No owner-controlled private age
recipient/key, durable evidence ingester, signed private admission,
actual CPE projection or independent Stage P adjudication has been
verified.

## Composition

The private research supervisor freezes an authenticated assignment
before dispatch. Two independent GHA matrix jobs should produce
`mcp-gha-sealed-arm-receipt/v1` and `result.age` for reference and CPE.

1. **Preflight**: `pairPreflight()` verifies two arm files, exact run
   IDs, distinct job/artifact IDs, matching source/config/plan digests,
   receipt hashes, and ciphertext byte consistency. Its manifest is
   **not self-authenticating**.
2. **GitHub-native read**: `checkNativePairMetadata()` checks the exact
   original repository/workflow/run attempt, both independently
   successful matrix jobs, their native job IDs, their named artifact
   IDs and nonexpired artifacts, with complete bounded pagination.
   This function is read-only; a trustworthy caller must use GitHub's
   legitimate HTTPS API endpoint. Mock-provider tests are not proof of
   production connectivity or the existence of real artifacts.
3. **Offline stage**: `stagePair()` copies the five fixed ciphertext
   metadata/files to a mode-0700 directory. Each staged file is 0600.
   The temporary directory is verified before committing by an
   atomic same-filesystem rename. Same-content repeats are accepted
   as idempotent; conflicting ciphertext under the same identity is
   rejected. No caller-controlled file names are used for this
   operation beyond the already validated assignment/run identifier.
4. **Private ingestion** (NOT IMPLEMENTED): independently validate
   the externally admitted request, download two authoritative
   native artifact IDs, decrypt on the privately approved host using
   its preauthorized age identity, freeze both inner Stage-R packets,
   durably record receipts and invoke independent Stage P/CPE review.

These are separate library primitives. No public or private workflow
has been wired to turn them into autonomous execution. A public
fixture can exercise their negative tests without exposing any
research results.

## Human / automation / agent control contract

- Human: existing GitHub Actions run and summary, plus later
  ChatGPT/DLE retrieval. `CIPHERTEXT_STAGED` is not `INGESTED`.
- Automation: typed JSON input/output and deterministic Go tests;
  exact repeated inputs are idempotent and conflicting replays fail.
- Agent: existing Agent Dispatch admission/observation; the staged
  library functions do **not** grant an agent permission to create,
  decrypt, cancel, dispatch or release research material.

## State and evidence requirements

| State | What is actually proven |
| --- | --- |
| `PAIR_LOCAL_BYTE_CONSISTENCY_ONLY` | Two arm files match a manifest supplied by the caller |
| `NATIVE_GITHUB_METADATA_MATCH_ONLY_NOT_DECRYPTED` | GitHub read-only metadata matches source/workflow/two jobs/two artifacts |
| `CIPHERTEXT_ONLY_NOT_INGESTED` | A verified local snapshot has been placed in owner-only storage |
| `INGESTED` | NOT YET QUALIFIED: requires authenticated assignment, decryption, inner-stage verification and durable private recording |
| `VALIDATED` | NOT YET QUALIFIED: held-out independent Stage P and CPE adjudication |

## Threats and follow-on holds

Do not use the API helper with an untrusted origin. The native result
must be obtained through GitHub HTTPS with an independently admitted
assignment; fake mock metadata does not establish authority.
No confidential task or full CPE projection can be sent to a public
hosted runner merely because its resulting artifact is encrypted.
Separate VMs strengthen process separation but do not alone
establish blinded science.

Offline stage tests cover replay, file and symlink substitution,
conflict and concurrency. The current staging helper is **not**
credentialed, has not been installed on an admitted private host,
and does not write to an authoritative DLE. It does not create
any missing provider secrets or recipient configuration.

Existing PR #555 remains a separate unmerged public synthetic
runner candidate; PR #556 is the narrower read-only observer,
and PR #557 is the stacked ciphertext-custody qualification.
Do not merge, deploy, promote policy or release source without
the distinct owner approvals and security review.
