# MCP GHA: one research control plane, three audiences

**Status 2026-10-27:** Source-only candidate in public draft PR #555.
The *existing* `/mcp gha start smoke` wake is already proved through a
native GitHub Actions run. The `/mcp gha sweep pilot` wake and synthetic
encrypted artifact mailbox are **not active** until reviewed and merged;
real CPE authority, persistent recipient, private re-intake, and blind
comparison are **not qualified**. Do not present a CI-green canary as
scientific evidence.

## One contract, three interfaces

| Action | Human UI/UX | Automation API/DX | Agent MCP/DX |
| --- | --- | --- | --- |
| Discover | ChatGPT asks "What can MCP GHA do?" and Actions README | `mcp-gha-control describe` JSON | `worker_describe` on live synthetic canary; persistent Sidecar's projection/plan |
| Request | ChatGPT sends an exact authorized PR comment; GitHub Actions manual dispatch for operators | Versioned fixed `workflow_dispatch` inputs (or owner's exact authenticated PR command) | `plan_execution` and admitted `dispatch_execution` on persistent Agent Dispatch, never raw shell |
| Observe | Actions run page, readable job summary, evidence link | `mcp-gha-control status --run-id 40448376152` | `observe_execution` using exact DLE; correlate native run ID |
| Cancel | GitHub Actions **Cancel workflow** button | Native Actions API requires separately admitted Actions-write authority; the read-only controller cannot cancel | Sidecar remains `CANCEL_NOT_ADMITTED`; an agent cancellation path requires separate review |
| Validate artifact | GitHub artifact listing (encrypted only) and sanitized receipt | `mcp-gha-control verify-receipt --receipt receipt.json --ciphertext result.age` | Same immutable digest verification via owned inspector; protected decryption only on trusted host |
| Interpret | ChatGPT returns independently validated, citable research summary | Frozen Stage R/P reference comparator under CPE #229 | Evidence-bound Stage P proposals with explicit uncertainty and separate CPE adjudication |
| Resume days later | Supply run ID (or ask ChatGPT to locate its GitHub DLE baton) | Poll native Actions API/owned DLE; durable private encrypted re-ingestion | Fresh MCP session re-observes from GitHub + private DLE; no assumed in-memory session |

### UX details

A ChatGPT conversation should ask for an ordinary question, geographic/
language coverage, source rights and scope once and submit *only*
release-approved typed inputs. Show receipt immediately as:
- `run_id`, link to GitHub Actions native run, source SHA,
  status `REQUESTED/QUEUED/RUNNING`;
- stage-specific health and search/provider status when observed;
- after completion, `SEALED` and ciphertext digest, then private
  `INGESTED` and `VALIDATED` only when independently proven;
- blockers including missing age recipient, unreachable SearXNG,
  provider refusals, unknown native language coverage, stale CPE
  projection, ambiguous ancestry, or insufficient review authority;
- selected results plus sources **only** after trusted decryption,
  identity/custody validation and post-freeze adjudication.

Avoid controls that imply the service can perform something it cannot.
Actions **Cancel workflow** is available to authenticated GitHub operators,
but ChatGPT's connected GitHub tool has not been qualified to cancel or
manage other users' jobs. No fabricated "cancelled" status.

### Portable command examples

```sh
# Build once in the public repo or in a trusted DX toolchain
cd tools/mcp-gha-control
go build -trimpath -o mcp-gha-control .

# Machine-readable, provenance-aware discovery
./mcp-gha-control describe

# Requires only public GitHub Actions read access
./mcp-gha-control status --run-id 40448376152

# After downloading a sealed artifact to an authorized environment:
./mcp-gha-control verify-receipt \
  --receipt receipt.json --ciphertext result.age \
  --run-id 40506152579 --arm reference
# The declared run/arm must match the independently expected assignment.
# The local ciphertext digest matches; receipt fields are not signatures.
# Output means ciphertext hash matches only. It does NOT decrypt findings
# or attest to the provenance of the claimed CPE projection.
```

No local tunnel, GitHub token, privileged API or private keys are required
for these three public read-only functions; GitHub public API rate limits
can apply. Private runs must instead use the private admitted control
service, not a public metadata client.

### Authoritative state machine

Public native read-only observation deliberately distinguishes:
`REQUESTED`, `ADMITTED`, `QUEUED`, `RUNNING`,
`SEALED`, `INGESTED`, `VALIDATED`, plus
`BLOCKED`, `FAILED`, `CANCELLED`, `EXPIRED`.

- These are a **contract**, not a claim they are all implemented.
- GitHub run status is authoritative only for native executor activity.
- A sealed artifact and public receipt attest to bytes, not scientific truth.
- Private ingestion validates ciphertext hash, source/run SHA and assignment
  authority, decrypts with an approved private key, and freezes Stage R.
- Independent Stage P/reference adjudication decides `VALIDATED`.
- Public quick status cannot report private semantic results.

## Two physical ephemeral GitHub Actions workers

The single public on-demand `/mcp gha sweep pilot` request now expands into
**two independent GitHub-hosted matrix jobs** (not two goroutines or two
queries in one long-running worker):

- `reference`: own fresh Linux VM, exact-file sparse checkout of only the
  reference arm's frozen public test input and shared Go source, own loopback
  SearXNG container, own age encryption, own per-arm ciphertext/receipt.
- `cpe`: a distinct fresh Linux VM with ONLY the CPE-labelled public
  synthetic arm input, independent SearXNG, and its own encrypted result.

There are no `needs` edges or arm-to-arm artifacts, and matrix `fail-fast`
is disabled so a provider failure in one does not erase the other arm's
evidence. The shared workflow's GitHub run ID identifies the paired launch;
the matrix job ID and artifact name identify each individual workcell.
Evidence is only accepted after both separately signed/native identities
are re-ingested and independently checked in private custody.

**Verification boundary:** GHA matrix jobs isolate VM processes and source
checkout, but **do not by themselves prove researcher blindness**. The
current checked-in queries are *public synthetic canaries*, including the
CPE-labelled arm. True independent seed preparation, CPE provenance,
separate research actor access, external provider ancestry checks, frozen
blind Stage P, and independent comparison remain private gates. Both arms
must remain eligible for GitHub-public processing; confidential prompts and
full CPE internals do not belong in either public VM.

## Verified runner-to-controller receipt seam

The runner emits `mcp-gha-sealed-arm-receipt/v1` once per track, rather
than the old combined `mcp-gha-sealed-transport-canary/v1`. The controller
now accepts **both** existing versions; per-arm verification checks the
fixed research-status marker, native run/attempt text, arm identity,
image/config/plan hashes, provider counters, ciphertext byte length
and SHA256. Use `--run-id` and `--arm` from an independently admitted
assignment to reject swapped evidence. Neither field comes from an
untrusted downloaded receipt.

A passing `verify-receipt` means that the bytes on disk match the
receipt's *self-declared* hash. It is **not an authenticated producer
signature**, independently verified GitHub Actions job identity,
private decryption, Stage P adjudication or genuine CPE research.
The private ingester must also fetch/check the native Actions run,
workcell job/attempt, assignment source SHA and ciphertext custody before
reporting `INGESTED` or `VALIDATED`.

The native qualification job now exercises the actual arm producer,
disposable age-encrypted artifact and Go verifier in the **same
ephemeral runner**, then deletes those test-only bytes.

## Scientific design: the two tracks must stay independent

The new matrix transport canary uses two separate ephemeral GHA runners, but
this still **does not qualify a blinded experiment**: inputs are public synthetic
fixtures and no actual CPE generation, independent held-out reference,
or Stage-P science has been verified.

For real paired work, freeze a neutral task with source/locale/query budgets,
then use independently admitted workcells for:
1. A: multilingual/native-first independent reference.
2. B: CPE-projected queries with **cryptographically pinned provenance**
   from the authoritative CPE output, executed through SearXNG.

Neither arm receives the other's proposed concepts/results before both Stage R
and Stage P freeze. Collapse duplicated upstream source ancestry after freeze.
The private adapter `src/content_search_adapters/two_stage.py` owns schema
translation, evidence-bound proposals, and CPE #229 scorekeeping; CPE #202
alone can accept canonical discovery proposals. A GitHub 200 status or a
retrieval match is not semantic proof.

## Cloudflare Tunnel ADR: DENY_BY_DEFAULT

**Do not attach Cloudflare Quick Tunnel to every public GHA worker.**
Cloudflare's current docs say Quick Tunnels are testing-only, issue a random
`trycloudflare.com` hostname that changes on restart, have no uptime
guarantee, and do not support SSE. Anyone with a Quick Tunnel URL can reach
the origin without a separate authentication layer. Its email gate relies
on an interactive browser and is not suitable for autonomous clients.

Why it isn't required:
- GitHub `issue_comment` and `workflow_dispatch` already wake a
  stopped runner, and native GitHub Actions offers durable run state.
- The GHA artifact mailbox stores ciphertext that survives the process,
  unlike a transient HTTP endpoint.
- OpenAI's already-selected official outbound MCP tunnel is the direct
  temporary ChatGPT-to-worker transport.
- A second live URL increases credential, metadata, revocation, and
  correlation surface without improving scientific blindness.

If a true interactive browser UI or callback is subsequently justified,
first qualify an **independent**, explicitly admitted Cloudflare *named*
Tunnel with Cloudflare Access (identity/service-token enforcement,
least-privilege, fixed origin paths, short lease, cleanup/revocation,
no public raw research material). Prefer the existing persistent OCI
front door for interactive cross-session controls. The tunnel should
expose only an authenticated control proxy, never SearXNG or plaintext
sealed workcell contents. It is an optional provider, not a precondition.

Official reference links:
- https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/
- https://developers.cloudflare.com/tunnel/get-started/
- https://developers.cloudflare.com/tunnel/reference/tunnel-tokens/
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel/

## Access and capability invariants

The publicly visible command grammar is exact. Ownership is checked
against an immutable GitHub user ID and PR #553; unknown commands skip
execution. No arbitrary prompt strings, source URLs, shell scripts,
repo names, full CPE policy-context documents, or keys may be smuggled
into public workflow inputs.

Source/evidence rights must be independently released for public processing;
encrypted outputs do **not** make public GHA a confidential enclave.
The API and role taxonomy must distinguish the three audiences while
enforcing the **same immutable request and identity contract**. Do not create
parallel schedulers, policy engines, or a second evidence authority.

## Remaining work

- Independent peer review and merge gate for public PR #555.
- Persistent approved age recipient + trusted private decryption/ingest
  operation; get long-lived evidence out of 30-day GHA artifacts.
- An admitted private workset for real query material; keep public GHA
  synthetic/public-reviewed only.
- A source-verified CPE projection adapter and separate reference/cpe
  workcell custody; native-first multilingual source-role expansion.
- Qualify separately scoped GitHub cancellation; explicitly grant Sidecar agent cancellation and retry semantics; at-most-once
  duplicate/out-of-order race reps.
- Real ChatGPT-to-worker OpenAI MCP tunnel and read-back from a later
  conversation, separately from the proven GitHub comment wake.

This file intentionally describes the **operational contract and
admission plan**, not capabilities that have already been accepted.
