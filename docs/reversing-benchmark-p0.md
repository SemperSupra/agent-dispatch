# RE-BENCH-P0 — public synthetic reversing evidence pilot

Authority: [project-native Ghidra Tools #4](https://github.com/mark-e-deyoung/ghidra-tools/issues/4). Governance: adopted [Way of Working](https://github.com/SemperSupra/engineering-governance-private/blob/main/WAY_OF_WORKING.md); public executor is the existing `github-runner-frontier.yml` in **draft** Agent Dispatch. This is not a new benchmark platform, new CoS daemon or a release.

## Purpose and scope

Exercise exactly **four** bounded evidence claims on the already-qualified **public generated**, stripped Linux x86-64 SysV synthetic fixture:

- Two optimized branch seeds, each with `RDI=0`: single sampled **native PC witness** at the fourth GNU/Ghidra code island start.
- Same two optimized seeds with `RDI=1`: **no breakpoint observed in that one run** at the same PC (not unreachable).

The same native workflow also retains hardening tests for contradictory GDB hit/exit receipts and wrong/duplicate input evidence. The four-claim reducer cross-checks exact code interval RVAs, independent GNU branch target, Ghidra/objdump interval agreement, file SHA equality before/after GDB, first-argument ABI and detailed per-island statuses. A **second, separately implemented replay module** now directly hashes the *actual* temporary stripped ELF and uses fresh native GDB processes to independently remeasure the n=0 witness and n=1 non-hit for each O2 seed. Its output is compared against the first per-island result; disagreement fails closed. This is **same-runner, same-GDB corroboration**, not independent security-grade packet authentication, hostile-output proof, external grading or sealed evaluator custody.

Training exposure class: `GENERATED_PUBLIC_SYNTHETIC_POSSIBLY_TRAINING_EXPOSED`. It is wrong to describe this as an unseen generalization or blind benchmark. No external protected corpus is acquired.

## Discover / use / observe / diagnose — the same scientific claim for all audiences

**Human and assistive-technology users:** Open the pull-request **GitHub Actions** job named *GitHub Runner Frontier Oracles*. The **job summary** contains a linear, text-based Markdown report including authority, work ID, claim ID, input, outcome and target RVA, followed by limitations. No color conveys the verdict, and no interactive CFG graphic is required. GitHub/Markdown structure is only an accessible baseline: neither NVDA/VoiceOver manual testing nor WCAG 2.2 AA conformance is claimed at this stage. The job log also emits a single-line `RE_BENCH_P0_JSON=` receipt and an exact success marker. Do not mistake a GitHub Actions green check or a sampled no-hit for broad decompilation success.

**Deterministic automation:** The ordinary, self-locating repository script is `scripts/reversing_benchmark_p0.py` (see `--help`), consuming the **same-run** generated `reversing-contrast-receipt.json`. Example after the existing native probe generates a real receipt in an admitted disposable environment:

```sh
python3 scripts/reversing_benchmark_p0.py \
  --input "$RUNNER_TEMP/reversing-contrast-receipt.json" \
  --json-output "$RUNNER_TEMP/re-bench-p0.json" \
  --markdown-output "$RUNNER_TEMP/re-bench-p0.md"
```

Success means that a **bounded synthetic report is internally consistent and fresh same-host native replay agrees**; failures return a non-zero process code, error text and no accepted scientific claim. The replayer is an **import-only helper** called before the fixed fixture's temporary ELF is deleted, not a general command for arbitrary executables. JSON fields include `schema, work_id, authority_ref, exposure_class, verifier_kind, source_receipt_sha256, cases, overall, limitations`. Verdicts are exactly `NATIVE_PC_WITNESS` and `NOT_OBSERVED_SAMPLE` on the admitted P0 inputs, not `REACHABLE_ALL_PATHS` or `UNREACHABLE`. Repeating the reducer on identical valid input yields identical output, without side effects other than explicitly named output files.

**Reasoning agents:** Read the project-native DLE first and discover this script and its typed JSON output. Keep the assigned mission/authority/work ID. Reconcile the precise `source_receipt_sha256` and per-case `claim_id, artifact_sha256, target_rva, input_n, verdict` before proposing a next proof obligation. Do not read grader outcome as independent peer approval. Missing/forged/contradictory inputs are an **evidence-integrity failure**, not evidence of inability to reach the target. A more powerful reasoning model does not confer additional executor/secret/publishing authority. Do not rerun native work just to produce redundant output if the exact verified receipt is already available.

**Cross-audience invariant:** identical claim IDs, scientific outcomes, DLE authority reference, and receipt digest in human Markdown, automation JSON, and agent-consumed JSON. The workflow validates agreement and rejects forged internal fields. A future GUI/MCP adapter, if earned by actual demand, must project this same record without maintaining an independent benchmark database.

## Explicit non-achievements and gates

- The tool is **not** an independent trusted analyzer of arbitrary hostile GDB output or a cryptographic proof that a runtime event occurred. The native parser is designed for a fixed public synthetic, no-stdout inferior.
- Neither a static signed JLE nor an observed PC proves that the branch was dynamically taken or the entire function interval executed.
- Fresh GDB processes rehash the same stripped ELF, but **both observers share the public runner and debugger**. Even agreement cannot independently authenticate hostile inferior GDB console output. The replay must not be promoted to a sealed independent grader.
- A no-hit under `n=1` does not prove code is dead, infeasible, or unreachable.
- The fixed public fixture can have appeared in model training; an unseen-problem claim requires *separate, admitted and truly withheld evaluator custody*. Arbitrary corpus upload to public GHA is prohibited.
- The private project evidence contract [ghidra-tools draft PR #5](https://github.com/mark-e-deyoung/ghidra-tools/pull/5) still requires full JSON Schema 2020-12 conformance, semantic verifier and independent acceptance. This public reducer is **not** a migration or grant of rights.
- Windows PE, Android JNI/ART, firmware, QEMU virtualization, local actor, signed native-trace instrumentation and model comparisons require their own scopes and qualification.
- Zero incremental spending; standard public GitHub Actions only; zero private hosted Actions minutes, credentials, new Sidecar caller, cross-boundary grant, merge, release or production activity.

## Red/blue acceptance tests and follow-on

Native CI must pass the existing complete pinned Ghidra/GDB tests, plus reducer tests for (1) all four fixed claim cases, (2) false witnessed outcome, (3) forged aggregate status, (4) shifted target PC, (5) altered branch target, (6) swapped/all-zero/malformed artifact hash, (7) duplicate/missing input, (8) absent independent interval geometry and (9) deterministic cross-audience projections. RDI parser red tests reject target PC hit followed by clean/abnormal exit and double normal-exit lines. Additional second-replay unit tests reject forged/misaligned breakpoints, wrong signed register values, event-order errors, contradictory hit/exit messages, duplicate markers, substituted ELF hashes, and in-flight ELF modification. Preserve the first failing CI and qualified corrections.

**Next warranted work:** a genuinely independent reviewer of the exact new replay PR and native receipts; project-owned candidate-schema PR #5 conformance checking; fresh-actor same-claim handoff and actual assistive-technology observation when a qualified actor/device exists. Separate-host/custody trusted native attestation and a tiny license-reviewed external corpus remain conditional on demonstrated need and admission. Do not add a new scheduler or registry solely for this case. Stop immediately on native/source conflict, running-cost or custody breach, and preserve UNKNOWN. Promote no draft solely because CI is green.
