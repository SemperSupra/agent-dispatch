# OpenWorker original complete scripted-headless runtime — public candidate

This workcell is independent of prior static module interviews. It installs and runs the actual OpenWorker v0.3.4 headless engine with its built-in scripted fake provider, restricted to an ephemeral public GitHub Actions Ubuntu x64 runner. No private emails or API tokens, actual external LLM inference, real SMTP, stored user agent settings, or privileged sandbox are involved.

## Immutable source/rights and build

- Source: MIT `andrewyng/openworker@ecb445490fc054d52b8ea610d97ba947f57033d2`, with four exact independently known Git blobs checked after a bounded `git fetch --depth 1`. Git commit and source rights must match before any installation.
- Build: new `python3 -m venv`, pip installs from exact Git source checkout with `--only-binary=:all:` to refuse source-build dependencies, no pip cache and a safe environment with only allowlisted public variables. It installs the complete declared package dependency graph, not a fake stub or vendored imitation.
- Dependency lock limitation: upstream package requires floating minimum version ranges, so there is no cross-date hash-locked dependency closure yet. The runner captures a deterministic name/version inventory SHA, environment byte count, package count, install time, and total runtime. It **does not** claim artifact reproducibility, license closure or supply-chain integrity of every transitive wheel. Automatic real-agent deployment is barred until a reviewed hash-locked wheelhouse, vulnerability/license scan, and explicit build/image digest are qualified.

## Exact runtime and operations

One fixed scripted fake-provider prompt attempts `write_file(forbidden.txt)`; the real headless engine must refuse it under `--approval-mode ask`, `--auto-answer`, `--isolated`, `--no-web-tools`, `--max-iterations 3`, and `--timeout-seconds 45`. The whole process runs twice from separate new workspaces/state folders. Both must retain an untouched workspace, a denied tool call and an identical high-level outcome/denial/call-count record. Verify all seven real engine artifacts: `events.jsonl`, `messages.json`, `summary.json`, `answers.json`, `audit.db`, `model_calls.jsonl`, `trajectory.json` with schema ATIF-v1.7. Only bounded summarized metrics enter the GitHub artifact (no conversation transcript or directory archive).

The upstream source is downloaded from GitHub, dependencies from standard Python index, then model execution uses a local scripted provider: do **not** claim network isolation at OS level. The subprocess environment does not inherit a credential/proxy variable. No email connector is registered, and the fixed script contains no shell, SMTP, or network tools.

This is a $0-incremental-cost public synthetic research profile (one attempt, standard `ubuntu-24.04`, max 235 seconds); **no model calls to external servers and no private GitHub-hosted actions**. It reuses existing `gha-typed-public-cpu.yml` and the independent fixed workload receipt verifier. A red install/timeout/runtime record is an experimental finding, not permission to relax source, rights, privacy or billing gates.

## Maintain, rollback, extend

All source/venv/state is deleted as its temporary directory exits; no persistent service, background tasks, account enrollment or model weights. Rerun from the same immutable source with exact package inventory to assess drift, then hard-pin and hash transitive wheels before any OCI image. Production candidates should use the already preferred Go supervisor and versioned OCI image or a separately justified isolated Python worker, never modify PSTriage's PS5.1 constraints. For a future live agent, require independently authorized host action broker, actual no-network process egress isolation, fake IMAP/SMTP integration with full imported package, and semantic held-out tasks; none of those is satisfied by this fake-model test.
