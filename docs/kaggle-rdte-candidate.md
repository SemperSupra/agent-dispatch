# Kaggle RDT&E — public executor candidate

**Status:** experimental, no authenticated Kaggle execution from GHA yet. [Public implementation PR #415](https://github.com/SemperSupra/agent-dispatch/pull/415), [private governing DLE #638](https://github.com/SemperSupra/agent-dispatch-private/issues/638), [real CPU-only GitHub Actions PASS](https://github.com/SemperSupra/agent-dispatch/actions/runs/38454032707). That run executed 14 offline tests, Python syntax and typed planning; it allocated no GPU/TPU resources.

The public code exposes a small fixed set of Kaggle research work, not a generic queue or command executor. `scripts/kaggle_rdte.py` supports `--action plan|submit|observe`, `--assignment`, `--workload gpu-cuda-smoke-v1|tpu-jax-bridge-v1`, and `--version` for exact-version observation. It uses Kaggle's official Python SDK and guards on quota, notebook collision, configured hardware, status and receipt oracles. Unknown states do not authorize retries.

The GPU workload checks actual CUDA execution. The TPU workload performs a **synthetic** paired-latent alignment training experiment with a shuffled negative control on JAX TPU; this tests training plumbing, not actual Neuralese, cross-model transfer or scientific reasoning improvements. Real latent-interface and continuous-reasoning research belongs to Model Spelunker and Latent Reasoning authorities, with independent falsification.

## Trust and actuation

PR/fork workflows can run the offline contract suite **without credentials**. The privileged GHA Kaggle launcher workflow is **not installed**; the connected write path declined that operation. An authorized repository owner must separately review/install a static protected-main workflow using `workflow_dispatch`, no dynamic code/prompt inputs, one typed assignment per execution and a short GHA timeout. Do not feed the Kaggle token to PR-triggered code or the generic sealed capsule runner.

The existing Kaggle new-style token may be installed once as a restricted GitHub Actions **environment secret**. The human-owner bootstrap is at `SemperSupra/agent-dispatch-private` draft PR #639, `experiments/kaggle-batch-smoke/Provision-KaggleGhaEnvironment.ps1`. It uses the trusted local token file as `gh secret set` stdin, configures/validates the environment branch gate for **main only**, and never logs secret content. GitHub repo administration rights are required; the bootstrap has not been run. Verify main branch review protection and configure required environment reviewers as appropriate before accepting any privileged workflow.

## DLE artifact movement, including local ↔ remote

Authoritative DLE specifies exact source revision, approved input/output manifest, model/dataset versions and SHA-256 digests. Physical payloads may use native storage backends; provider URLs alone do not create new task authority.

**Offline preferred:** GitHub code/manifest → short GHA launch → Kaggle Dataset / Model / Notebook sources attached to the notebook → offline GPU/TPU run → Kaggle output API → short GHA read-only observation → independent result oracle → DLE receipt. Local actors stage input through an approved DLE transfer; the remote side consumes the exact immutable reference. GitHub Actions artifacts are temporary evidence, not a durable model-weight store.

**Internet-enabled later, separately qualified:** Hugging Face Hub, public GitHub releases, Cloudflare R2 via time-limited object-scoped signed requests, Google Cloud Storage/Drive and Microsoft Azure Blob/OneDrive via provider APIs. Network access in Kaggle API-submitted notebooks is **not guaranteed**: internet setting may be ignored by provider; verify a real egress probe. No credentials or signed URLs in public notebooks/receipts/logs. Colab is a separate compute environment: exchange artifact manifests through the DLE, not direct interactive Colab runtime coupling.

Stop on unresolved first T4 Windows-origin run `ERROR` (private DLE has FAIL receipt, root cause UNKNOWN), ambiguous native version/ownership, failed hardware probe, missing quota, restricted data, or absent authorization. No Cloudflare Tunnel, open inference server, new scheduler or automatic quota-draining retries is part of this candidate.
