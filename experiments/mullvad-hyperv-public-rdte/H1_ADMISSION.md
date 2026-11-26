# H1 fixed Alpine nested Hyper-V — admission and execution capsule (PUBLIC)

This file is a **public-safe handoff spec**, not a new executor, scheduler,
admission record, or authorization to boot a guest. The existing public
`agent-dispatch` control plane and separately governed typed assignment must
own the actual H1 launch. Do not manufacture authorization with environment
variables, GitHub rerun endpoints, or commits to a privileged workflow.

## Existing source and evidence

- [Public RDTE PR #412](https://github.com/SemperSupra/agent-dispatch/pull/412):
  `tools/h1_alpine_nested_hyperv.ps1` — fixed candidate source, Windows
  2025 **Preflight** and deliberately rejected `Execute` on PR events.
- Linux source-independent packet-path fixture:
  `tools/netns_packet_witness.sh` + `tools/netns_udp_witness.py`;
  actual public kernel IPv4/IPv6 positive, default-drop, scope-allow,
  revoke, no-residue receipt. **NOT** a nested Hyper-V guest witness.
- Public pinned ISO:
  `alpine-virt-3.24.2-x86_64.iso`; exact
  SHA256 `3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b`;
  69,206,016 bytes; official detached GPG verification on hosted Linux.
  Source fixed to `https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/`.
  No custom ISO, real VPN keys or private guest configuration.

## Distinct, separately admitted mission

The **smallest acceptable** binding by Agent Dispatch must include:
1. Canonical workset identity, admitted delegation/caller, **fresh assignment ID**,
   exact reviewed PR SHA/source path, run budget and capability catalogue.
2. A **fixed, reviewed Windows 2025 job** with no arbitrary script, URL, repo,
   runner, branch or payload inputs. The candidate file is not an arbitrary
   command runner.
3. `workflow_dispatch` only after above authority checks; public PR
   `pull_request` always invokes **Preflight** and refusal negatives only.
4. Run-owned resource identity and exclusive capacity: 1 Gen2 VM, fixed
   512 MiB RAM, 2 vCPU, dynamic blank 1 GiB VHDX, signed/hash-pinned
   Alpine ISO, exactly one **Private** vSwitch (no host/physical uplink).
5. No host network route, physical NIC, management vSwitch, registry,
   Windows feature enablement, reboot, private code, real Mullvad account
   or provider API mutation.
6. Always/finally teardown: exact VM/switch/temp storage only; cleanup
   readback, including partially-created resources, is mandatory.
7. Public report only fixed classification, SHA, case ID, cleanup and
   sanitized error class; retain raw log only if proven public-safe.
8. Actual H1 success requires **guest OS identity**, not just VM
   `Running`, ISO attachment, or integration Heartbeat. Current source
   produces `H1_HEARTBEAT_ONLY_NEEDS_OS_IDENTITY` when that partial
   milestone is observed; cannot label full H1 qualified.
9. All source changes and runner attempts are reconciled back to the public
   PR; native execution status and workset authority remain with Agent
   Dispatch. Full private gateway validation remains a separate product
   decision.

## Explicit negative/interview fixtures

- Wrong SHA/size, unsigned ISO, unexpected redirect: no VM launch.
- Existing VM/switch/path identity collision: no deletion of foreign state.
- Preflight on PR or missing typed permission: `Execute` denied, no VM/switch.
- Unsupported Hyper-V feature, RAM/CPU/disk cap: classify ENVIRONMENT.
- Private/external switch or extra NIC: ORACLE failure, teardown.
- VM reports Running but no heartbeat: not a guest-boot success.
- Heartbeat observed but Alpine OS identity absent: retain partial
  classification; **do not** claim H1 full success.
- Failure at any creation/attachment step: cleanup only uniquely owned
  resources, verify no residual VHDX/ISO/switch/VM.
- No admitted executor/assignment: `BLOCKED_ADMISSION`, not a workflow
  authored or triggered merely to consume cloud resources.

## Status boundary

`H0_WINDOWS_PREFLIGHT_SOURCE_EXECUTABLE`: verified read-only cloud runner.
`ISOLATED_KERNEL_IPV4_IPV6_PACKET_WITNESS`: verified native Linux namespaces.
`H1_GUEST_IMAGE_SHA256_GPG_VERIFIED`: verified official public artifact.
`H1_PRIVILEGED_EXECUTOR`: **NOT ADMITTED**.
`H1_GUEST_BOOT / OS_IDENTITY`: **NOT RUN**.
`H2_GUEST_OUTSIDE_WAN`: **NOT RUN**.
`PRIVATE_GATEWAY_PRODUCT`: **NOT QUALIFIED**.

No side effect from posting or reviewing this file creates an assignment.
