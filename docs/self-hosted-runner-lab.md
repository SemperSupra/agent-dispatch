# Portable self-hosted Actions runner lab

Authority: private experiment `SemperSupra/agent-dispatch-private#278`.

This public surface contains only the public-safe execution half of the experiment. The objective is to develop a generic self-hosted GitHub Actions runner lifecycle against disposable hosted KVM surrogate hardware, then transplant the same runner-management logic to sovereign compute by changing the host-provider seam rather than redesigning the runner lifecycle.

## Responsibility seam

- **Agent Dispatch/control side:** placement intent, authority bounds, dispatch/reconciliation, independent verification.
- **Host provider:** acquire/release a generic machine and provide network/storage/opaque-input transport.
- **Runner kit:** preflight a generic Linux host, stage a checksum-pinned official runner, later consume one-run registration material, expose diagnostics, and sanitize experiment-owned state.
- **GitHub:** job scheduling and the runner protocol.

The runner kit is provider-neutral. GHA-specific details belong only in the `gha-kvm` host provider/workflow.

## Current public entrypoints

`scripts/self_hosted_runner_kit.sh`
: Provider-neutral contract, preflight, install-plan, checksum-pinned runner staging, and safe opaque-input consumption/sanitization. It does **not** acquire runner-registration authority.

`scripts/gha_kvm_surrogate.sh`
: Boots one ordinary Ubuntu 24.04 cloud image under QEMU/KVM, grows the disposable guest disk to an explicit provider capacity, proves SSH nonce exchange and outbound HTTPS, exercises the generic runner kit, optionally stages the official Actions runner, then destroys experiment-owned state. It does not register a GitHub runner.

`.github/workflows/self-hosted-runner-surrogate.yml`
: Manual-only bounded public-safe qualification workflow. It has `contents: read` permission and no repository/org runner-administration credential.

## Qualified evidence

The reference surrogate has passed on GitHub-hosted `ubuntu-24.04` x64 with:

- ordinary Ubuntu 24.04.5 LTS x86_64 guest boot under QEMU/KVM;
- SSH reachability and host/guest nonce exchange;
- guest outbound HTTPS;
- normal systemd availability;
- provider-neutral runner-kit preflight with no missing prerequisites;
- synthetic owner-only opaque-input consumption without disclosure and explicit sanitization;
- explicit 12 GiB guest disk sizing after the initial cloud-image filesystem proved too small for runner extraction;
- official GitHub Actions runner Linux x64 v2.337.0 staged from a checksum-pinned release asset;
- SHA-256 `70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613` verified before extraction;
- actual `Runner.Listener --version` oracle returning `2.337.0`;
- experiment-owned VM/state teardown.

Accepted package-stage evidence is from public workflow run `35821026584` at head `d1d005987bdd20e4d3008554ecf032cebcc8a083`.

Preserved failed reps are part of the evidence. They exposed and corrected: incompatible daemonized QEMU display flags, SSH metadata quoting, guest disk-capacity assumptions, and scope-sensitive staging cleanup. Those failures are not rewritten as environment negatives.

## Current frontier: JIT control-plane bootstrap

The next live slice is one-shot GitHub JIT registration and one bounded public-safe job. The guest must receive only opaque one-shot JIT configuration; it must never receive a PAT, GitHub App private key, or other long-lived runner-administration credential.

The intended control flow is:

```text
authorized control side
  -> generate one-shot JIT configuration
  -> opaque provider transport
  -> generic runner kit in guest
  -> official runner accepts exactly one job
  -> reconcile GitHub + host evidence
  -> sanitize and destroy guest
```

The current connected GitHub control surface used by this experiment does not expose JIT-configuration generation, so live JIT execution remains `AUTHORITY_REQUIRED`. Do not widen repository/org permissions or introduce a broad PAT merely to pass the experiment.

## Local deterministic checks

```bash
python3 -m unittest -v tests/test_self_hosted_runner_lab.py
bash scripts/self_hosted_runner_kit.sh contract
bash scripts/self_hosted_runner_kit.sh preflight --work-dir "$HOME/actions-runner"
```

The QEMU surrogate requires Linux x86_64, usable `/dev/kvm` through passwordless sudo, `qemu-system-x86_64`, `qemu-img`, `cloud-localds`, SSH/SCP, curl, and Python 3.

## Security and scope boundary

- No pull-request/fork event launches this experiment.
- No live self-hosted runner is currently registered.
- No private workload value is projected into the public repository.
- Do not use this lab as a public-minutes proxy for unrelated private workloads.
- Firecracker-specific RDTE remains under private sibling authority `SemperSupra/agent-dispatch-private#277`; this experiment consumes that evidence later only if it earns integration.
- Final transplant readiness is withheld until the same runner-kit contract passes one sovereign-host canary.
