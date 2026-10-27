# MCP GHA — protected pair collection contract

**Status:** public-safe source-only implementation in draft PR #556.
This is a specification for the trusted private ingester, not a deployment.

## Distinct responsibilities

- GitHub Actions: isolated public-safe synthetic Track A/B workcells; each
  publishes only `result.age` and sanitized `receipt.json`.
- GitHub native Actions API: authoritative run, job, attempt, artifact-ID
  metadata; do not infer these fields from a downloaded receipt.
- Agent Dispatch Sidecar: separately admitted, durable work request and
  approved source and language/source-role bounds. Existing authority.
- Trusted private ingest: approved private host/vault, owner-authorized
  age identity, independently frozen source and CPE projection references.
- Private Search Adapters/CPE: Stage P, independent reference scoring,
  source ancestry, proposal decisions after both retrieval tracks freeze.

## Preflight source API

`tools/mcp-gha-control/pair.go` implements an **offline read-only**
`pairPreflight(manifest,inbox)` method, currently tested but not exposed
as a command-line subcommand. It expects a separately trusted
`mcp-gha-private-pair-preflight/v1` manifest containing assignment ID,
repo/workflow/run/attempt/source SHA, pinned provider image and config,
plus two fixed arms. Each arm records the native job ID, artifact ID,
plan digest, and receipt digest; job/artifact identities must be distinct.

The local inbox is:
```text
inbox/
  reference/
    result.age
    receipt.json
  cpe/
    result.age
    receipt.json
```

Preflight checks both arm receipts, expected run, attempt, code/config
source, per-arm plan, ciphertext bytes/hashes and bounded counters. It
rejects duplicate job/artifact references, swapped tracks, changed
receipts or ciphertext, unapproved science claims and symlinked inputs.

**Its only success state** is
`PAIR_LOCAL_BYTE_CONSISTENCY_ONLY`, with
`UNATTESTED_MANIFEST_NATIVE_JOB_AND_ARTIFACT_IDS`.
It does not prove the manifest was authorized, the job/artifact IDs
were returned by GitHub, the private key exists, or real CPE science.

## Required trusted private ingestion (not yet implemented)

1. Independently load an immutable admitted assignment and verify source
   repository, workflow, requested arm plans, privacy/rights classification.
2. Read GitHub native Actions run and every job *for the exact attempt*;
   verify native source SHA, worker identity, two distinct successful
   matrix jobs, arm coverage, artifact ID/name and run retention.
3. Download each artifact by independently verified native artifact ID.
   Never follow user-controlled path, URL, relative redirect or symlink.
4. Require the frozen manifest to match both native sources and
   locally retrieved receipts, then run the offline pair preflight.
5. On the approved private host, decrypt each `age` ciphertext with the
   preauthorized key, validate inner Stage-R schema, query hash/role/locale
   counts, and freeze it before allowing the CPE/research comparator
   to see either other's findings.
6. Store exact immutable ciphertext, source evidence pointers and
   per-arm native receipts to the private DLE-backed evidence store.
   Commit idempotently; same assignment+run+digest is a no-op; different
   digest on same identity is a conflict. Stage/verify before
   atomically recording completion; incomplete re-ingestion must be
   recoverable without partial semantic publication.
7. Mark `SEALED`, `INGESTED`, and `VALIDATED` independently.
   Stage R retrieval or GitHub success alone cannot make a finding valid.
   Cleanup must not remove the sole retained copies.

## Negative controls for acceptance

Reject wrong tenant/repo, arbitrary workflow and actor, duplicate arms,
duplicate job or artifact IDs, stale run attempts, altered source/config
or CPE projection digests, mismatched receipt-to-ciphertext hashes,
colliding retained assignment identities, a failed native job masked by
a successful workflow, missing/expired artifacts, tampered inner
plaintext schemas, leaked reference oracle and encrypted artifacts
whose decryption identity is not authorized.

Keep the private age identity in an approved vault/sovereign host;
never send it through GitHub comments, public Actions inputs/logs,
PRs, this public repo or ChatGPT messages.

**Activation hold:** PRs #555 and #556 remain draft; the production
`/mcp gha sweep pilot` source path is not merged. No persistent
recipient has been verified here and no actual CPE-generated paired
experiment or private artifact decryption has been performed.
