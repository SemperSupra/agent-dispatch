# Public synthetic RDTE: Mullvad/Linux VPN gateway primitives

**Status:** public **reference contract and executable synthetic oracles**, not an implementation or certification of a VPN. This is a public-safe, bounded consumer of the existing Agent Dispatch public execution surface. Do not put any private gateway source, identity, topology, Mullvad account, credentials, personal details, or output artifacts here.

## Scope and source provenance (2026-10-13)

- Mullvad open-source app: [pinned commit `c70ce25bfdf500c2da2c68786336213202f1e6d5`](https://github.com/mullvad/mullvadvpn-app/tree/c70ce25bfdf500c2da2c68786336213202f1e6d5). Review `docs/security.md`, `talpid-core/src/firewall/linux.rs`, `talpid-core/src/tunnel_state_machine/mod.rs`, `talpid-wireguard/src/lib.rs`, `mullvad-api/src/device.rs`, `docs/relay-selector.md`, `docs/known-issues.md`.
- Alpine: `alpinelinux/aports@3.24-stable`, `main/linux-lts/virt.x86_64.config`, reviewed Git blob `e9e12c691dccb4147078d68c13b113bc964ffe32`. Availability of Hyper-V NetVSC, WireGuard, nftables, VSOCK modules on that published configuration does **not** prove the target guest image includes/loads them.
- Linux Hyper-V NetVSC: `gregkh/linux@v6.18.56:drivers/net/hyperv/netvsc_drv.c` (Git blob `25a358524a096e128d6cd384a9b925c386a3ec2c`). WireGuard `drivers/net/wireguard`; nftables `net/netfilter`.

Sources are for design comparison. This package contains **no copied Mullvad product source**; its Python oracles are original, public, synthetic contracts.

## Independent public work cells

| Cell | Oracles | Evidence type | Actual target proof? |
| --- | --- | --- | --- |
| S: policy and state | Dual-stack policy-epoch gating, fail-closed boot/change/revoke, relay exception scope, stale receipt mutants | Pure Python property/negative tests | **No**, model contract only |
| P: provider and privacy | Strict geographical selection, explicit fallback, precise destructive device authorization, transport privacy requirements | Synthetic in-memory responses | **No**, no provider API calls |
| N: Linux capabilities | Read-only network/kernel feature inventory and classified unavailable capabilities | Public Ubuntu hosted runner | **No**, generic Ubuntu isn't a Hyper-V guest |
| K: Actual Linux kernel datapath | Run-owned namespace LAN → gateway → WAN; real nftables default-DROP, scoped-allow, revoke, IPv4/IPv6 outside-observer positive controls; teardown | Public Ubuntu hosted runner, `sudo` restricted to ephemeral test-owned namespaces/veth | **Only native synthetic kernel forwarding**, no VPN tunnel or Windows host protection |
| H: Windows/Hyper-V | Read-only Hyper-V command/feature census on public Windows runner | Windows 2025 runner only | **No**, until separately admitted guest boot and packet-path fixture |

Public GHA workflow uses isolated jobs, `contents: read`, pinned checkout, timeouts, no secrets or provider API. The **Linux synthetic-kernel** lane deliberately uses `sudo` to create and delete only its own disposable `ip netns` and `veth` resources, mutate networking **inside** those namespaces, and observe in-namespace packet replies. It never modifies the host firewall, DNS, default/physical NIC, or host routes. This scoped native privilege is **not** authorization to create a Hyper-V VM, modify a Windows vSwitch, import a private image, or launch a real product. The latter requires an admitted fixed H1 mission. No `pull_request_target`; do not run untrusted code with secrets. A failing negative control or cleanup makes its job FAIL.

## Public-to-private requirements (not implementation instructions or disclosures)

1. **Mandatory constraints:** unsatisfied requested location/exits must yield `BLOCKED`, never an arbitrary active server. Explicitly approved fallback must be from an eligible allowlist.
2. **Policy authority:** deny plaintext outside a narrowly scoped authorized first-hop control flow through boot, changes, crash and revocation, for both IP families.
3. **Fresh admission:** activating user egress requires verified current policy, tunnel, route and outside-observer receipts tied to the same epoch; booleans and hashes supplied by the candidate itself are not trustworthy evidence.
4. **Non-atomic domains:** nftables batch ACK protects only that netfilter transaction. Routes, DNS, WireGuard and Hyper-V vSwitch state are *not* committed atomically with it. Test transitions using external packet witnesses.
5. **Provider privacy:** never log account IDs, bearer tokens, WireGuard keys, API responses containing secrets, or private routing context. No remote account/device mutations in synthetic RDTE.
6. **Account/device preservation:** no automatic revoke or replacement based on reaching a device-count threshold; precise device identity + explicit narrow authorization for destructive actions.
7. **Performance:** the cheapest safe optimization wins; no NetVSC XDP, flowtable, GRO/GSO or IRQ tuning adoption until baseline and independently verified dual-stack safety under change/failure.
8. **Source membrane:** public payload only contains public upstream refs and synthetic data. Private consumer code and its acceptance are governed elsewhere.

## Decision rubric

Per finding: `ADOPT_CONCEPT`, `EXPERIMENT`, `DEFER`, or `REJECT` with the pinned source, precise behavior, cost/attack surface, testable property, public receipt and smallest independently qualified downstream acceptance. **Do not equate public model checks to production safety.**

## Running

```sh
python3 -m unittest discover -s experiments/mullvad-hyperv-public-rdte/tests -p 'test_*.py' -v
python3 experiments/mullvad-hyperv-public-rdte/tools/capabilities.py
```

Tests use only the Python standard library. No cloud services or Mullvad endpoints are accessed. Public hosted Actions runs must be explicitly observed via run ID, exact SHA, step exit codes and runner labels; source-only review is `NOT_RUN`.

## Immediate research dispositions

| Research observation | Decision | Rationale / acceptance |
| --- | --- | --- |
| Mullvad Linux uses owned `inet` nftables policy and netlink batch processing | `ADOPT_CONCEPT` | Keep owned table, ACK/readback; outside witnesses still needed for routes and WireGuard |
| Mullvad security policy limits tunnel-state exceptions | `ADOPT_CONCEPT` | Translate endpoint assumptions to forwarded-zone gateway traffic before adopting |
| Provider relay selection must honor mandatory constraints | `ADOPT_CONCEPT` | Synthetic fallback mutants; target integration independently gated |
| Provider key rotation API may preserve device identity | `EXPERIMENT` | Compare to revoke/recreate; no real provider mutation |
| TLS transport hardening / API bypass semantics | `EXPERIMENT` | Verify public API contract; prohibit tokens or secrets in public logs |
| Hyper-V guest NetVSC / VSOCK, GRO/GSO, XDP | `EXPERIMENT` | Capability inventory first, compare actual pinned Linux guest in admitted nested Hyper-V |
| nftables flowtable shortcut / full Mullvad daemon embed | `DEFER` | Forwarding-policy bypass risk / unnecessary footprint until measurable requirement |

## Qualification classes

- `SOURCE_REVIEWED`: pinned upstream inspection, no executable proof.
- `SYNTHETIC_ORACLE_PASS`: actual public runner executed unit/property/mutant checks.
- `PLATFORM_READBACK`: actual runner reported read-only capabilities; no packet assurance.
- `HIL_PACKET_WITNESS`: separate authorized disposable guest + outside observer, intentionally leaky positive controls, dual-stack negative tests.
- `PRODUCT_QUALIFIED`: **never inferred by this public repository**.

Nested HIL must reuse admitted Agent Dispatch fixed missions and independent run-owned cleanup. No new general scheduler or arbitrary-command executor belongs in this experiment.
