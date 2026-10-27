# MCP GHA — read-only evidence controller (standalone)

This deliberately small public-safe module is carved out of the large
draft [MCP GHA sealed concept-sweep PR #555](https://github.com/SemperSupra/agent-dispatch/pull/555).
It contains **no** GitHub Actions write/cancel capability, arbitrary
script/workflow selection, secret storage, decryption key or exposed
research question.

It provides three interfaces for human/automation/agent workflows:

- `describe`: versioned typed discovery including limitations.
- `status --run-id N`: read native GitHub Actions state of *only*
  `.github/workflows/mcp-gha-worker.yml` in
  `SemperSupra/agent-dispatch`. Success means only executor finished.
- `verify-receipt --receipt FILE --ciphertext FILE --run-id N --arm reference|cpe`:
  validate an encrypted Stage-R arm result's bounded metadata, track/run
  identity, image/config/plan digest formats, native provider counters,
  bytes and ciphertext SHA256. Legacy combined public synthetic canaries
  remain readable for compatibility.

The expected run ID/arm must come from the **trusted assignment**, not
from an untrusted downloaded artifact. Both arm receipts are explicitly
`SYNTHETIC_TRANSPORT_ONLY_NOT_BLIND_RESEARCH`. A passing verifier
returns `SELF_REPORTED_UNAUTHENTICATED_NEEDS_NATIVE_RUN_AND_PRIVATE_INGEST`
and `CIPHERTEXT_DIGEST_MATCH_ONLY_NOT_DECRYPTED`, not false provider
attestation, decrypted findings or CPE policy conclusions.

The downloaded `receipt.json` can itself be forged. An attacker can
construct matching ciphertext and receipt; verifying these two files alone
does not authenticate their GitHub origin. A later authorized private
ingester must independently bind artifact ID, native workflow/job/attempt,
source SHA, trusted assignment, private decryption and separate reference/
CPE comparison before promoting evidence.

Run locally or in the free public native test runner:

```bash
cd tools/mcp-gha-control
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race -count=3 ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go build -o mcp-gha-evidence .
./mcp-gha-evidence describe
./mcp-gha-evidence status --run-id 40448376152
./mcp-gha-evidence verify-receipt --receipt receipt.json \
  --ciphertext result.age --run-id 40506152579 --arm reference
```

**Source custody:** public synthetic-only; no full CPE code, protected
questions, plaintext results or private keys. This PR is *read-only
evidence qualification*, not production activation. The main application
still runs only the previously accepted `/mcpgha start smoke` trigger
until the independent runner/sweep activation PRs are reviewed and merged.
Merging this verifier alone grants no Actions-write, private ingest, or
scientific adjudication capability.
