# Sealed public execution

Status: experimental public-safe execution adapter.

## Platform entrypoints

The same bounded archive, SHA-256 validation, age result encryption, receipt and
private-side reconciliation contract is shared across qualified platforms.

| Public runner | Execution entrypoint | Status |
| --- | --- | --- |
| Ubuntu/Linux | top-level `run.sh` via Bash | Existing qualified implementation |
| Windows Server 2025 | top-level `run.ps1` via native Windows PowerShell 5.1 | Draft extension; requires independent admission for each workload |
| macOS | top-level `run.sh` via Bash | Candidate reuse only; no sealed Mac qualification yet |

The Windows workflow is `.github/workflows/sealed-public-execution-windows.yml`.
It uses the same public-safe five-input dispatch contract. An authorized
trusted-side caller must admit a bounded request before dispatch; the public
workflow itself does not grant authority to read private sources. Its PR qualification job exercises a
synthetic PowerShell 5.1 execution and age encrypt/decrypt round trip, with
no private repository checkout or private material. The public runner can
observe the capsule even though result data are encrypted. The originating
authority must therefore approve any public projection **before** dispatch.

### Windows filename policy — corrective qualification

The Windows sealed-worker profile pins **Python 3.13** for native hosted
qualification and execution. Windows tar member components are checked with
CPython's maintained `ntpath.isreserved()` rather than a hand-maintained
Win32 device-name list. This handles platform-reserved characters, DOS
device aliases (including superscript COM/LPT digits), trailing dots/spaces,
and other cases as defined by the pinned Python runtime. The explicit colon
rejection remains to prevent drive-qualified/ADS syntax such as
`C:relative` from bypassing per-component reserved-name classification.

**Separate archive invariants remain local:** forward-slash-only relative
members; no empty, dot or parent components; case-folded collision rejection;
no symlink, hardlink, or device members; extraction-root containment; member
count and byte limits; and exact top-level `run.ps1`. These safeguards are
not Windows filename rules and cannot be delegated to `ntpath.isreserved()`.

If `ntpath.isreserved` is unavailable (for example Python 3.12), the
Windows path fails closed before extraction. The Linux `run.sh` worker does
not require Python 3.13 for execution, but the shared Linux **contract test**
is pinned to Python 3.13 so Windows-policy regression cases execute there
too. The source-of-truth Windows native test remains the hosted
`windows-2025` runner.

This change only qualifies *public-safe synthetic* archive admission.
The capsule contents are public-observable; encrypted result transport does
not authorize projecting private repository source, and an accepted CI result
is not a Sidecar dispatch/admission or an owner-approved deployment.

No platform-specific work is equivalent to a grant for arbitrary private
source; native shell execution, runner profile, and task-class acceptance
remain separate evidence. The Linux worker is the default, and adding the
Windows option does not change Linux `run.sh` behavior. macOS is a future
demand-driven qualification, not a new provider or accepted runner in this PR.

## Purpose

Use standard GitHub-hosted Actions capacity in this public repository for work that a trusted/private authority has already determined is safe to project into a public runner, while keeping substantive result evidence out of Git history and returning it to the trusted side as short-lived ciphertext.

This adapter is an execution/materialization mechanism only. It does not own project intent, acceptance truth, research state, task prioritization, or declassification decisions.

## Boundary

Trusted/private side responsibilities:

1. resolve the originating project-native authority;
2. determine whether the work may execute on a public runner;
3. derive the least-sufficient public-safe capsule;
4. generate a per-assignment age X25519 keypair and retain the private identity outside GitHub;
5. dispatch the public workflow with only the opaque assignment ID, capsule, capsule digest, exact age X25519 public recipient, and bounded timeout;
6. retrieve the encrypted Actions artifact, verify the receipt/ciphertext digest, decrypt privately, and reconcile useful evidence back to the originating authority;
7. delete the public artifact/run when it no longer has diagnostic value.

Public runner responsibilities:

1. verify the capsule digest and strict archive bounds;
2. validate the exact age X25519 public-recipient shape;
3. execute only the platform's fixed top-level runner (`run.sh` on Linux, `run.ps1` via native Windows PowerShell 5.1 on Windows), with no private credentials;
4. capture task stdout/stderr into the private result bundle rather than Actions logs;
5. collect files written beneath `SEALED_RESULT_DIR`;
6. bound result material before packaging so one task cannot silently consume unbounded artifact storage;
7. package and encrypt the result to the supplied age recipient;
8. upload only `result.age` plus a minimal `receipt.json` as a seven-day Actions artifact;
9. preserve task success/failure in the workflow verdict.

## Capsule contract

The workflow accepts a gzip-compressed tar archive encoded as base64. Current hard bounds are intentionally small:

- base64 input: at most 60,000 characters;
- archive entries: at most 256;
- unpacked content: at most 16 MiB;
- no symlinks, hardlinks, devices, or path traversal;
- a regular platform-specific top-level entrypoint (`run.sh` on Linux or `run.ps1` on Windows) is required;
- task timeout is at most 7,200 seconds;
- recipient must be the exact Bech32 shape used by an age X25519 `age1...` recipient.

At runtime the worker sets:

- `SEALED_ASSIGNMENT_ID` — opaque correlation identity;
- `SEALED_RESULT_DIR` — directory for substantive result files.

The capsule itself is public-observable execution material. Do not put information in it that the originating authority has not approved for public-runner exposure.

## Result contract

The public artifact contains only:

- `result.age` — age-encrypted gzip tar containing execution metadata, captured stdout/stderr, and result files;
- `receipt.json` — opaque assignment ID, completed/failed status, ciphertext SHA-256/size, public worker revision, and Actions run correlation.

The plaintext result is bounded before sealing:

- captured stdout: at most 1 MiB after deterministic head/tail truncation;
- captured stderr: at most 1 MiB after deterministic head/tail truncation;
- substantive result files: at most 252 regular files;
- one substantive result file: at most 8 MiB;
- substantive result files plus stored stdout/stderr: at most 16 MiB total.

If substantive result files exceed a hard bound, the worker does **not** upload an arbitrary partial result. It removes those files, writes a small `result-budget-exceeded.json` diagnostic inside the sealed bundle, records the original task exit code separately, and marks the worker execution failed with the bounded result-budget exit status. Stream truncation by itself is diagnostic and does not change an otherwise-successful task verdict.

These limits apply to result material only; they intentionally do not cap task scratch/work files because legitimate public workloads may temporarily acquire large models or datasets during execution. Runtime disk exhaustion remains a separate host/provider boundary and may justify a later control if real reps demonstrate the need.

Retention is set to seven days. This is a pickup/recovery window, not a durable evidence store. Trusted-side reconciliation should normally retrieve and delete the artifact sooner after successful pickup/decryption.

The artifact is transport, not durable project authority. Durable conclusions, accepted evidence, negative results, or follow-on decisions belong back in the originating private/project-native authority.

## Security / value-preservation invariants

- No private credential is required by the execution workflow.
- No private repository checkout occurs in this lane.
- The private decryption identity never enters GitHub.
- No plaintext result artifact is uploaded.
- Task stdout/stderr are not intentionally emitted to Actions logs.
- Public runner visibility of the projected capsule is accepted by the originating authority before dispatch.
- The public repository must not accumulate experiment interpretation, private hypotheses, result corpora, or project-specific research history merely because it provided compute.
- A second project does not need to adopt this adapter unless its own authority chooses to use it.

## Non-goals

This increment does not add a scheduler, task database, queue, generic provider registry, automatic public/private classifier, result archive, or new portfolio authority. It also does not make `agent-dispatch` mandatory for interactive/local execution paths.
