# R6 — Actual open-weights small-model mail evidence benchmark (public $0 CPU)

**First genuine model inference lane**, with independent held-out source/answer scoring and fixed dev-only policy choice. This is not native PST extraction, a production mail agent, real customer data, self-modifying weights or an automatic optimization release. Source authority remains private Mail Evidence #39; execution is in the existing public typed Agent Dispatch CPU workflow.

## Immutable open-source and model rights

- Original model publisher: `Qwen/Qwen2.5-0.5B-Instruct-GGUF`, model repository commit `9217f5db79a29953eb74d5343926648285ec7e67`; file `qwen2.5-0.5b-instruct-q2_k.gguf`, expected SHA-256 `9ee36184e616dfc76df4f5dd66f908dbde6979524ae36e6cefb67f532f798cb8`. Rights published as **Apache-2.0**, 415 MB model; verify digest before execution. Model weight file is fetched only from the publisher's exact-commit Hugging Face URL, never uploaded to GitHub artifacts.
- Model runtime: `ggml-org/llama.cpp@8642541b255bfb5dc39cd351a178be09013a55d6`, MIT license, official release v0.8.0. Clone fixed tag, require exact commit, compile unprivileged CPU-only `llama-cli` from source with `LLAMA_CURL=OFF` and no CUDA/Vulkan. No third-party Python packages, no hosted model API, no secrets, no private project code.
- Hard one-attempt cap, `public-synthetic`, `ubuntu-24.04`, `max_cost_usd=0`; source download/size SHA, timeouts, model call counts, CPU thread count, no new workflow, no runtime service persistent state. Actual cost is declared zero incremental under standard public repo GitHub Actions; this does not verify external provider billing independently.

Sources: https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF and https://github.com/ggml-org/llama.cpp/releases/tag/v0.8.0 .

## DOE and independent held-out score

One fictional, entirely public-safe evidence collection of 8 observations (7 alpha; 1 beta excluded from model prompt), including duplicate Internet Message-ID across separate unrelated messages, a changed budget, source reacquisition, German denial, Thai approval, missing-ID release item and an off-limits beta-only claim.

Ten independently authored EN/DE/TH questions split into **3 dev** and **7 held-out**. Model sees only its question and the bounded alpha evidence; the gold ID/value and task partition labels are not in the prompt. Two fixed reviewed prompts: `plain` and `evidence-first`. Model chooses `source_id` plus `value` JSON from an explicitly constrained schema (no external API/tool call), temperature 0, seed 19. Both prompts evaluated on dev; candidate selection is by dev exact answer only, tie prefers plain; then both evaluated on held-out to measure a fixed-prompt baseline and selected policy, but held-out results do not influence selection. Count exactly **20 real local model calls**.

The **independent evaluator** compares full expected source ID+exact answer, invalid JSON, wrong source cited, abstention, language, per-sample duration. A result may be bad (e.g. Thai misinterpretation or incorrect time scope) and still qualify as *a genuine measured inference experiment*. The receipt separates `real_model_inference=true` from `semantic_quality_gate` and explicitly sets `automatic_promotion=false`, `model_weights_updated=false`. Quality non-regression policy is **not** automatically promoted to the product. The threshold is 6/7 held-out exact and 0 wrong sources, but this is an exploratory small sample, not meaningful statistical generalization or proof of compliance. Source-context ACL is enforced by the harness excluding beta before the model, so it does **not** measure model-side secrecy.

## Build / deployment / operations

Research use only. `python3 scripts/qualify_mail_qwen_real_cpu.py` inside a fresh public Linux runner downloads a fixed 415 MB model, builds the exact C++ runtime in a disposable temp directory, executes both policy arms under 2 CPU threads and counts source-citation errors. One Python stdout JSON document forms a SHA-pinned origin/metric receipt; the original model weights, build cache and prompts are not uploaded. `gha_workload_request.py` admits only `requests/gha/mail-qwen-real-cpu-v1.json` with a fixed 420-second internal timeout and a parent 8-minute job ceiling. A first install/download/compile/timeout/JSON error is a **failed experiment** and must be recorded, not hidden by substituting fake-model outputs or relaxing the original digest.

Dispose of the entire temporary checkout/build/model/cache after the rep. A production service needs a version-pinned slim OCI artifact and model file with retention rights, hash-verified disk, cold-start and memory profiling, host network egress firewall, corruption/restart/rollback, explicit model routing and secret isolation. This experiment has none of those production guarantees. Runtime/source license checks are source-and-model disclosures only, not a complete transitive SBOM/license/attestation.

## CI/runner hygiene

The first on-PR test temporarily adds a fifth CPU matrix profile to obtain independent native evidence. **After evidence**, remove it from the routine PR matrix while leaving the fixed reviewed manifest/contract for explicitly admitted on-demand retests. Routine four-core matrix and previous proofs should remain; no new scheduler, arbitrary URL or user shell. The model's 0.5B size limits generalization; negative/weak results are valid evidence and should direct larger-model comparisons on an authorized zero-cost venue.
