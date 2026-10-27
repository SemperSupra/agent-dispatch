# MCP GHA — sealed multilingual concept sweep (Stage R transport)

This module is a **public-safe transport primitive**, not a second
Concept Policy Engine or independent research adjudicator. It consumes
a **reviewed public-safe** original/reference query plan and an independently
pinned/minimized CPE search-projection file. The program records **actual**
SearXNG JSON retrieval outcomes and writes only to a 0600 local output file.
It does not classify policy, propose semantic truth, invoke arbitrary commands,
or generate its own CPE queries.

## Execution placement

Both tracks are scheduled inside ephemeral **GitHub Actions runners**. The
single fixed `/mcp gha sweep pilot` trigger dispatches a `reference` and
a `cpe` matrix job; these run on **two distinct temporary VMs**, each with
its own SearXNG service, release-approved arm-specific manifest, local
temporary result, encrypted artifact and independent native job receipt.
Each checkout allowlists only six exact files: shared Go source/module,
script/config and *that arm's* fixture; the other arm's manifest and legacy
combined synthetic plan are excluded.

The existing combined-mode CLI/tests are retained for backward compatible
transport verification, but **must not be scored as a blinded dual-track
study**. The new `--arm-plan` CLI fails closed unless the input is a
`mcp-gha-stage-r-arm/v1` public synthetic manifest for exactly one arm.
No independent CPE authority output is available/attested yet. The GHA
`/mcp gha sweep pilot` workflow is source-staged only until PR acceptance
and permanent age-recipient configuration.

Stage A and B are both worker-side *retrieval*. Private CPE authority
prepares authorized B query projections before the run, and private
adjudication decrypts/compares their independent frozen results afterward.
Protected questions must be routed to trusted **private ephemeral workers**
instead of public hosted GHA; encryption protects result artifacts, not
plaintext execution or upstream search queries.

## Authority and comparison

The authoritative private methodology remains CPE paired-sweep #229 and the
Search Adapters canonical two-stage Stage-R/Stage-P contract from #78/#68.
This public worker is a Stage-R producer only.

1. Trusted private supervisor freezes the neutral original intent, native
   multilingual/source-role obligations, provider/CPE revisions, reference
   queries and separately generated exact CPE projection *before retrieval*.
2. The original reference arm and CPE treatment receive equal bounded budgets
   and cannot see each other's **retrieval findings**. This primitive does not
   enforce actor-level blindness; that must be proven by separate workcell
   admissions and private corpus/source custody.
3. This worker checks bytes against the CPE projection digest before sending
   any search request, but explicitly reports
   `PROJECTION_DIGEST_MATCH_ONLY_NOT_AUTHORITY_VERIFIED`. Only the trusted
   private boundary may validate whether those bytes truly came from the
   pinned CPE authority. Never count a text file labeled "CPE" as proof.
4. Provider HTTP failure yields `FAILED_PROVIDER`, not an invented hit.
   Successful provider HTTP does **not** imply true relevance, distinct upstream
   corroboration or conceptual validity. Retain each native language as a
   separate query-language field, not as proof of upstream language enforcement.
5. The private ingester freezes both tracks, verifies the native GitHub run,
   source/config digests and encrypted artifact, then applies the existing
   Stage-P evidence-bound proposal harness and *independent* reference
   adjudication. Canonical CPE changes require separate approved #202 intake.

The supported schema is `mcp-gha-stage-r/v1`. Search queries are an
array of objects with `language`, `text`, and `role` (currently only `web` is provider-qualified; dictionary
and ontology roles fail closed until exact engine/source configuration is
independently validated). Each track is limited to 24 queries, each at most 240 Unicode
characters, at least three approved language identifiers in the plan.
A production "global sweep" must select additional native-language, region,
historical, and source-family coverage before experiment freeze; three languages
are merely a lower-bound validation gate, not proof of global coverage.

## Trust boundary and sealing

A public GitHub-hosted runner is **not confidential computing**. It and
the upstream engine providers may observe plaintext query contents. Raw URL,
title and snippet fields produced by Stage R must remain on runner-local disk
and be encrypted using a reviewed persistent **public age recipient before**
any GitHub artifact upload. The existing
`.github/workflows/sealed-public-execution.yml` has an age-encrypted result
mailbox; prefer integrating this primitive through that existing sealed
execution contract and its trusted private capsule projector, not creating
a second scheduler or duplicate encryption/archive implementation.

The workflow
`.github/workflows/mcp-gha-concept-sweep-qualification.yml`
currently demonstrates **only synthetic HTTP source tests** and ephemeral
encryption round-trip, discarding the private test-only age key. It does
**not** upload an unrecoverable artifact or claim live SearXNG/CPE retrieval.
The separately qualified MCP GHA GitHub-comment wake can start a job, but
there is **not yet** a reviewed, precommitted `/mcp gha sweep` launch
operation for arbitrary private questions.

For private or source-sensitive queries, use a private/sealed sovereign
workcell holding CPE query/answer material, or project only a deliberately
release-approved public-safe minimized search capsule to public Actions.
Encrypting outputs on a shared GitHub-hosted runner does not make secret
inputs private from that runner.

## Offline qualification

```bash
cd tools/concept-sweep
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race -count=3 ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go vet ./...
```

The CLI is `go run . --plan APPROVED.json --projection CPE-PROJECTION.json
--endpoint http://127.0.0.1:18888 --out PRIVATE-RUNNER-LOCAL.json`.
The endpoint is *strictly loopback*; callers must pin SearXNG image/config
outside the CLI. An unreachable provider yields `SOURCE_EXECUTOR_GAP`, not
a retrieval PASS. The resulting JSON is plaintext **until the caller seals
it** and must not be put into logs, comments or GitHub artifacts.

## Three-audience contract

- Human: ask ChatGPT for a research sweep, receive a durable DLE/run ID,
  distinguish running/blocked/completed, and later request independently
  summarized, citable results.
- Automation: typed plan/projection/run/source digests, bounded source role,
  locale/query budget, sealed result mailbox, terminal provider failure
  classification, cleanup and replay-safe re-intake.
- Agents: discover the fixed manifest/Stage R schema, call only admitted
  dispatcher operations, observe native Actions IDs, defer semantic claims
  until an independent Stage P/CPE review and preserve source ancestry.

No new central queue, generic shell executor, live CPE mutation, private
metadata publication or broad remote-work delegation is created here.
