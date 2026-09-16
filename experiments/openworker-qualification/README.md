# OpenWorker zero-cost qualification

Status: bounded experiment; **not adopted**.

## Question

Can OpenWorker act as a useful replaceable worker runtime beneath Agent Dispatch without becoming authoritative work state or requiring paid infrastructure?

This experiment tests the smallest claim first: can an immutable OpenWorker revision install and execute its core headless runtime correctly on a standard public GitHub-hosted runner with no model credentials and no paid model/API calls?

## Upstream under test

- repository: `andrewyng/openworker`
- revision: `5bc10d928e0b64aae74313349a3b17bd19643ae2`
- source is cloned directly from the public upstream and checked against the exact commit before installation

Changing the upstream revision creates a new experimental condition and must be explicit.

## Resource envelope

The first gate intentionally consumes only resources that do not draw from scarce private Actions minutes or model credits:

- one standard `ubuntu-latest` runner in this public repository;
- 15 minute hard job timeout;
- no larger runner;
- no repository/provider/model secrets;
- no OpenAI, Anthropic, Gemini, or other paid model/API calls;
- no Actions artifact upload/storage;
- ordinary network access only for fetching public source/Python dependencies.

The workflow must remain safe to run as a public pull-request contract test. It never receives the secret-bearing Agent Dispatch environment.

## Planned methodology

The independent harness installs OpenWorker as a consumer would and checks:

1. installed `openworker`, `openworker-server`, `openworker-connectors`, and `ocw` entry points start and expose help successfully;
2. a scripted provider requests an approval-gated `write_file` action;
3. the side effect does **not** occur before approval;
4. the suspended live turn is cancelled and the in-memory engine is discarded to simulate restart/loss of the original process context;
5. the durable Inbox approval is resolved after that simulated restart;
6. the authorized write actually occurs and the resumed assistant result is persisted;
7. the automation scheduler uses real SQLite state, executes a bounded injected runner, and durably records the run;
8. the automation REST surface exposes the durable scheduled task;
9. selected upstream regression tests independently witness durable resume, automation behavior, and approval integrity.

The scripted provider is intentional. Gate 1 asks whether the worker/control machinery works without allowing model quality, model price, or provider availability to hide failures in the runtime.

## Acceptance gate

Gate 1 passes only if all independent checks and selected upstream regression witnesses pass inside the resource envelope.

A passing Gate 1 proves only that the current OpenWorker revision can provide the tested worker/runtime primitives on an ephemeral public Linux runner. It does **not** prove live model quality, browser usefulness, GUI/desktop embodiment, SaaS connectors, or long-duration reliability.

## Kill / defer criteria

Do not proceed to a live-model rep if any of these remain true after one bounded repair attempt:

- the pinned revision cannot install reproducibly on the public runner;
- core headless functionality depends on the desktop GUI;
- approval can be bypassed or the write occurs before approval;
- restart/resume loses the pending authority decision or fails to execute an approved action;
- scheduler state is not durable enough to reconstruct the run;
- the experiment requires model credentials merely to exercise core runtime behavior;
- the job routinely exceeds the 15-minute envelope;
- adapting OpenWorker requires substantial changes to Agent Dispatch semantics rather than a thin executor adapter.

Failure evidence is a useful result; do not weaken the gate to make OpenWorker pass.

## Gate 2 if Gate 1 earns it

Only after Gate 1 passes, run the same bounded contract with actual reasoning fuel:

1. **sovereign lane first:** local Ollama/model endpoint on an authorized local execution node;
2. **small API-credit canary:** one tightly capped provider/API rep only if it adds information not obtainable from the sovereign lane;
3. **subscription-backed comparator:** use supported subscription executors (for example the existing Jules path) as separate Agent Dispatch executors rather than pretending a consumer subscription is a generic OpenWorker API key.

The same task, authority envelope, acceptance criteria, evidence fields, and validator should be used across executors so the comparison measures worker/runtime value rather than changing the experiment for each implementation.

## Evidence

The qualification harness emits a structured JSON result to the Actions log and a compact GitHub job summary. No long-lived Actions artifact is uploaded. Durable interpretation/adoption decisions belong back in the private/project-native authority after the rep completes.
