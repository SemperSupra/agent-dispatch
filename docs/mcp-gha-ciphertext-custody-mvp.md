# MCP GHA — paired ciphertext custody candidate

This is an offline, **source-only** candidate stacked as draft PR #557
on read-only controller draft PR #556. Nothing here deploys to a
private host, reads an age secret or makes a scientific claim.

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
