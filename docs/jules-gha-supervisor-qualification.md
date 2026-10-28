# Jules supervises public GHA: synthetic interview and native qualification

Status: **public synthetic contract staged; real Jules is not yet invoked or qualified.** Originating authority is held in the protected project-native DLE; reuse existing governed Jules and public-runner adapters without additional permissions. This public repo contains only public-safe execution mechanics, not private project or provider decisions.

## Experiment

One path-scoped PR workflow runs two standard public Ubuntu 24.04 GHA jobs in parallel. The reference arm returns PASS / BASELINE_OK; the fault arm returns OBSERVED_FAILURE / SYNTHETIC_ASSERTION_MISSING. The latter is an **intentionally injected synthetic diagnostic**, not a failed production test. Both independently run stdlib-only Go tests, race checks and vet, then upload short-lived (one day) public JSON artifacts. The join downloads both actual artifacts and checks the immutable PR head SHA, native GitHub run ID, attempt, signals and duplicate-arm mismatches.

The bounded interview packet can be given to a separately admitted Jules actor. The first workflow runs only a **mock answer**, and checks two independent states:
- SYNTHETIC_CONTRACT_PASS: positive/negative evidence-contract tests succeeded.
- PROVIDER_ATTESTATION_REQUIRED: the mock has **not** been established as a Jules session.

A passing GHA job does not imply Jules executed or that any generated fix is accepted. The provider mode of this tool intentionally never asserts provider attestation; native Jules session identity, session/ChangeSet observation and authority must come from the existing protected controller and independent verifier, not from a self-asserted answer.

## Human / automation / agent interface

- **Human:** draft PR checks, run/job/artifact links, first failures and protected project-native DLE verdicts.
- **Automation:** run Go tests/race/vet from tools/jules-gha-interview. Four commands (arm, prepare, mock-answer, judge) accept bounded flags and return JSON. No API key or provider token.
- **Agent:** consume the emitted jules-gha-interview/v1 packet, propose a **fix only**, and return jules-gha-answer/v1 with exact source/run/attempt, grounded evidence and auto_dispatch=false, accept_candidate=false.

The Go tests fail closed on stale source/run/attempt, wrong signals, fabricated or missing evidence, duplicate evidence, unauthorized dispatch/merge, self-acceptance, unknown schemas and malformed inputs. Real Jules must additionally pass native correlation, resumability, diagnosis and bounded correction.

## Native Jules interview (separate admission)

1. Reconcile protected project-native authority and select an existing, unclaimed bounded Agent Dispatch assignment. Freeze public source commit and evidence packet.
2. Verify Jules connected Source, free/quota-safe execution, caller and target/admission rights and **one-use owner-authorized** CreateSession. Reuse existing governed Jules integration; no ad hoc adapter, label bypass or secret-bearing PR action.
3. Observe and persist native Jules session ID, source/base, lifecycle and ChangeSet via existing observer. Ambiguous create/response is UNKNOWN with no automatic retry.
4. Independently review any proposed correction on a controller-owned immutable candidate. A fresh public GHA run is separately admitted by the trusted controller.
5. Return real native session/run/job/artifact IDs, first failures and outcomes to the protected project-native DLE.

## Holds

No private GitHub-hosted Actions minutes, paid runners, private payload projection, new secrets, unrestricted GHA actuation, automatic PR/merge/release, private-workcell materialization or second scheduler/controller. PR code runs with a read-only token. Protected existing Jules environments are **not** exposed to this PR. A successful synthetic workflow is evidence of the substrate and interview contract only.


## Source membrane / webhook / reasoning extension — synthetic qualification

The real private→public source membrane MUST be enforced **before** this repository or any public runner sees source. Its existing private constructive projector and Concept Membrane/CPE authority are upstream systems, not implementations provided by this lab. For this public experiment, the original private source remains out of scope. This lab supplies independent **public-side challenge/verification only**.

The Go synthetic signed-projection verifier rejects duplicate JSON object keys and case-variant aliases at every nesting level, including signed inputs, to prevent first-value/last-value parser disagreement. The authenticated webhook observation uses the same fail-closed check. These are transport/byte-contract checks, not source-classification decisions. A production release also requires a separately approved, destination/purpose-bound private authorization and signer-to-policy mapping; a syntactically valid policy digest alone is insufficient.

The Go synthetic signed-projection verifier checks exact listed file bytes, size, sorted unique paths, V0/V1/V4 class allowlist, absence of extra files and symlinks, valid release-manifest syntax and a signature from a **trusted key pinned independently of the candidate**. The signing key in the unit tests is an explicitly synthetic, non-production fixture. It does **not** prove upstream private classification, source history safety, semantic leak detection, aggregation safety, authorization of the signer, trusted key provisioning or actual materialization. The manifest's capsule digest now covers a deterministic, NUL-delimited listing of all declared paths, value classes, per-file SHA-256 digests and sizes. This verifier does not validate a separate archive, private source identity, classification rationale, or a trusted policy document. Always perform the actual private-side classification/constructive export, scanner/independent validation and release gate before public staging. A public runner cannot grant release just because its own tests are green.

The pure Go webhook contract accepts only an HMAC SHA-256 signed, exact-repository-bound GitHub workflow_run **completed** observation with bounded JSON, positive run/attempt and exact source SHA. It rejects forged, changed, unknown, wrong-repository and duplicate deliveries. The in-memory duplicate map is **only an offline test primitive**: a durable controller must use native delivery/run/attempt identities or project DLE for crash-safe replay prevention. It does not expose a listening HTTP endpoint, host a public tunnel, obtain GitHub webhook credentials, or dispatch a job.

Parallel GitHub Actions matrix lanes independently test the webhook and membrane negative cases on standard public runners without secrets. The original two-arm runner + join remains independent. Nothing here creates a source-publication actuator.

### Optional transport and reasoning placement

Use GitHub-native workflow_run and authenticated GitHub App webhooks for durable triggers. An accountless Cloudflare Quick Tunnel may be used to probe a **low-consequence, unprivileged, ephemeral** webhook receiver, with signature validation, strict path/event allowlisting, rate and payload bounds. Quick Tunnel URLs change and have no uptime guarantee; never make their presence a durability assumption. Do not expose Sidecar/admin credentials through a tunnel. A named tunnel or a trusted edge endpoint is a separate persistent service choice.

Reasoning models (Jules or free inference API) consume only an already-approved public packet in the public lane; private reasoning remains on an authorized private side. An agent's declassification recommendation is **untrusted** and cannot replace a mechanically verified projection or controller-owned promotion decision. Cross-check model diagnosis against deterministic independent oracle; compare costs, retry rate and first-pass correctness, and retain native provider IDs before concluding qualification.

No new provider key, tunnel, webhook registration, listener, public-private transfer, release certificate or trusted signer is deployed by this experiment.
