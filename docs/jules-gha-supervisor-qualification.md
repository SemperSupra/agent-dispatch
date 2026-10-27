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
5. Return real native session/run/job/artifact IDs, first failures and outcomes to **private** DLE #700.

## Holds

No private GitHub-hosted Actions minutes, paid runners, private payload projection, new secrets, unrestricted GHA actuation, automatic PR/merge/release, private-workcell materialization or second scheduler/controller. PR code runs with a read-only token. Protected existing Jules environments are **not** exposed to this PR. A successful synthetic workflow is evidence of the substrate and interview contract only.
