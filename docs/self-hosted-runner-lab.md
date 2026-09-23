# Portable self-hosted Actions runner lab

Authority: private experiment `SemperSupra/agent-dispatch-private#278`.

This public directory contains only the public-safe execution half of the experiment. It is intended to answer one narrow question: can a generic self-hosted GitHub Actions runner lifecycle be developed against disposable hosted KVM surrogate hardware and later transplanted to sovereign compute without rewriting runner-management logic?

## Responsibility seam

- **Agent Dispatch/control side:** placement intent, authority bounds, dispatch/reconciliation, independent verification.
- **Host provider:** acquire/release a generic machine and provide network/storage/opaque-input transport.
- **Runner kit:** prepare a generic Linux host, install/configure the official runner from pinned inputs, run it, expose diagnostics, and sanitize experiment-owned state.
- **GitHub:** job scheduling and the runner protocol.

The runner kit must remain provider-neutral. GHA-specific details belong only in the `gha-kvm` host provider/workflow.

## Current public entrypoints

`scripts/self_hosted_runner_kit.sh`
: Provider-neutral contract/preflight/plan and safe opaque-input consumption/sanitization. It does **not** acquire runner-registration authority.

`scripts/gha_kvm_surrogate.sh`
: Boots one ordinary Ubuntu 24.04 cloud image under QEMU/KVM, proves SSH nonce exchange, outbound HTTPS, generic runner-kit preflight, synthetic opaque-input handling, then destroys experiment-owned state. No GitHub runner is registered.

`.github/workflows/self-hosted-runner-surrogate.yml`
: Bounded public-safe qualification workflow. During the experiment branch it may temporarily run on branch-only pushes; before review/merge it is frozen to explicit `workflow_dispatch`.

## Local deterministic checks

```bash
python3 -m unittest -v tests/test_self_hosted_runner_lab.py
bash scripts/self_hosted_runner_kit.sh contract
bash scripts/self_hosted_runner_kit.sh preflight --work-dir "$HOME/actions-runner"
```

The QEMU surrogate requires Linux x86_64, usable `/dev/kvm` through passwordless sudo, `qemu-system-x86_64`, `qemu-img`, `cloud-localds`, SSH/SCP, curl, and Python 3.

## Security boundary

The guest never receives a PAT, GitHub App private key, or other long-lived runner-administration credential. A future JIT rep may receive only opaque one-shot JIT configuration produced by a separately authorized control-side path. If such authority is unavailable, the experiment stops at `AUTHORITY_REQUIRED`.

Do not use this lab as a public-minutes proxy for unrelated private workloads.
