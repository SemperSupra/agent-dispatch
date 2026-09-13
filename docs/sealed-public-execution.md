# Sealed public execution

Status: experimental public-safe execution adapter.

## Purpose

Use standard GitHub-hosted Actions capacity in this public repository for work that a trusted/private authority has already determined is safe to project into a public runner, while keeping substantive result evidence out of Git history and returning it to the trusted side as short-lived ciphertext.

This adapter is an execution/materialization mechanism only. It does not own project intent, acceptance truth, research state, task prioritization, or declassification decisions.

## Boundary

Trusted/private side responsibilities:

1. resolve the originating project-native authority;
2. determine whether the work may execute on a public runner;
3. derive the least-sufficient public-safe capsule;
4. generate a per-assignment age X25519 keypair and retain the private identity outside GitHub;
5. dispatch the public workflow with only the opaque assignment ID, capsule, capsule digest, public recipient, and bounded timeout;
6. retrieve the encrypted Actions artifact, verify the receipt/ciphertext digest, decrypt privately, and reconcile useful evidence back to the originating authority;
7. delete the public artifact/run when it no longer has diagnostic value.

Public runner responsibilities:

1. verify the capsule digest and strict archive bounds;
2. execute only the capsule's top-level `run.sh` with no private credentials;
3. capture task stdout/stderr into the private result bundle rather than Actions logs;
4. collect files written beneath `SEALED_RESULT_DIR`;
5. package and encrypt the result to the supplied age recipient;
6. upload only `result.age` plus a minimal `receipt.json` as a one-day Actions artifact;
7. preserve task success/failure in the workflow verdict.

## Capsule contract

The workflow accepts a gzip-compressed tar archive encoded as base64. Current hard bounds are intentionally small:

- base64 input: at most 60,000 characters;
- archive entries: at most 256;
- unpacked content: at most 16 MiB;
- no symlinks, hardlinks, devices, or path traversal;
- a regular top-level `run.sh` is required;
- task timeout is at most 7,200 seconds.

At runtime the worker sets:

- `SEALED_ASSIGNMENT_ID` — opaque correlation identity;
- `SEALED_RESULT_DIR` — directory for substantive result files.

The capsule itself is public-observable execution material. Do not put information in it that the originating authority has not approved for public-runner exposure.

## Result contract

The public artifact contains only:

- `result.age` — age-encrypted gzip tar containing execution metadata, captured stdout/stderr, and result files;
- `receipt.json` — opaque assignment ID, completed/failed status, ciphertext SHA-256/size, public worker revision, and Actions run correlation.

Retention is set to one day. Private reconciliation should normally delete the artifact sooner after successful pickup/decryption.

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
