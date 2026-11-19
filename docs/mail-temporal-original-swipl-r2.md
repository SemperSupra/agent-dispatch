# R2-SWI — Original SWI-Prolog temporal truth-maintenance research qualification

Product DLE authority: [Mail Evidence #4](https://github.com/SupraShellScripts/mail-evidence-private/issues/4) and [mail reasoning DOE #39](https://github.com/SupraShellScripts/mail-evidence-private/issues/39).

## Prior art and bounded purpose

The existing Go four-valued proof contract has passed but is not an established general-purpose truth-maintenance system. This workcell instead **executes the original SWI-Prolog interpreter** using a static reviewed Prolog program, with an independently checked provider-bound receipt. The program models source assertion versus observed truth, late-arriving retroactive evidence, repeated physical export lineage, planned versus actual, beta tenant boundaries, and a conservative derived two-premise implication. SWI-Prolog source: https://www.swi-prolog.org; Ubuntu 24.04 `swi-prolog-nox` package (distribution 9.0.x). The interpreter is installed only for the fixed reviewed PR matrix workcell using distro apt repositories; transitive package SHA/version closure is **not pinned** here, so this is research/runtime qualification only.

## Actual experiment

A fixed `requests/gha/mail-temporal-swipl-r2.json` typed public request admits one Ubuntu x64, declared $0, one attempt, 180-second runtime. The immutable reviewed source `tools/mail-evidence-challenge/temporal_prolog/qualify.pl` has eight fictional source occurrences and source-anchored claims (all static, no user source or raw PST). The source includes nine plunit tests; a Python standard-library wrapper launches original `swipl -q -s <fixed-reviewed-file> -g qualify -t halt` in a stripped environment and verifies the bounded JSON, source SHA, exact tested case count and no model inference. It independently replays a second clean run and requires byte-identical output. No arbitrary goal, source path, shell argv, private data, account credentials or paid model endpoint is accepted from a request. The host process is not a security sandbox; source is source-reviewed and execution must remain in ephemeral public synthetic CI.

The tests assert: knowledge-as-of old state refuses future-acquired retrospective correction; current historical view retains BOTH supporting/refuting sources; a duplicated source appearance retains both original occurrences but only one independent lineage; planned future state does not imply accomplished state; tenant beta source does not join alpha; rule `transfer_ready` is justified by original paid+receipt source IDs; a later invoice refutation quarantines the derived rule, preserving earlier knowledge assessments.

## Required source qualification and O&M

- Retain two original clocks: event effective time and system acquisition time; valid-time for this fixture uses lexicographically comparable full UTC ISO8601 strings, *not* arbitrary natural language or time zones. Normalize with the reviewed Go timezone adapter before passing to the rule engine.
- A Prolog proof is a **policy-dependent derivation**, not objective truth or a replacement for immutable source evidence.
- The supplied original program has static rules; it neither performs general ATMS belief revision nor proves SWI-Prolog Event Calculus, tabling, constraint propagation or s(CASP) behavior. Those require separately approved experiments.
- The current Ubuntu package provides an interpreter but does not establish a cryptographically locked binary/OS SBOM. Requalify if Ubuntu apt changes runtime version; compare memory, licensing, interpreter startup, and error behavior before production deployment.
- The original Prolog code and Python wrapper are deployed as fixed files under the existing public GitHub typed workflow. The installer is gated to the specific fixed request profile; no cron, new workflow, scheduler or full-project swipl requirement. After a first native provider-bound receipt is obtained, remove its installer and workcell from the **routine** matrix, preserving the reviewed typed profile for explicitly admitted future reruns. Prolog source remains under research branch; no change to PSTriage's PS5.1 Windows dependency policy.
