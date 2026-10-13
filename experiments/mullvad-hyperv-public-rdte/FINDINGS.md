# Pinned public source comparative findings (2026-10-13)

This is a public-source assessment only. It does not disclose or assess any private consumer implementation and is not an independent live packet-safety certificate.

| ID | Exact public source | Mechanism / gap to qualify | Decision | Consumer-independent acceptance |
| --- | --- | --- | --- | --- |
| S1 | [Mullvad security model](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/docs/security.md) | Blocking, connecting, connected, error and deliberate-disconnect states have distinct traffic permissions; transient failure should not open ordinary egress. | ADOPT_CONCEPT | State machine preserves both-family default-deny through boot, error and relay switching; observe from outside WAN |
| S2 | [Mullvad Linux firewall](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/talpid-core/src/firewall/linux.rs) `apply_policy`, `send_and_process`, `verify_tables` | Owned `inet` nftables table and netlink batch ACK/readback provide a useful control pattern; a table-exists readback is not an exact installed-rules/packet proof. | ADOPT_CONCEPT | Verify exact generation, kernel ACK and full policy semantics; cross-domain route/WireGuard/DNS observations and a stale-receipt mutant |
| S3 | [Mullvad Linux firewall](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/talpid-core/src/firewall/linux.rs) `fwmark`, `cgroup2` | Restricting a direct WAN allowance to an intended privileged socket/process avoids a broad peer-IP exception; running as root can weaken process separation. | EXPERIMENT | Test unprivileged UDP to allowlisted relay and mark/cgroup spoofing negatives on a disposable Linux kernel |
| S4 | [Mullvad security model](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/docs/security.md) `Mullvad API` and `Connecting` | Before a tunnel is connected, API reachability may require a narrowly authorized outside path. TLS trust, TLS sessions, account metadata and failures are privacy-relevant. | EXPERIMENT | Provider test double; classify cryptographic compatibility, no secret logs, no unrestricted API IP bypass |
| S5 | [Mullvad Linux firewall](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/talpid-core/src/firewall/linux.rs) `apply_kernel_config` | The source logs some sysctl failures without making them fatal. A downstream gateway must decide which kernel configurations are essential vs optional and verify readback. | ADOPT_CONCEPT | Explicit required/optional sysctl classes, negative sysctl write/readback fixture, no false healthy state |
| P1 | [Mullvad relay selector docs](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/docs/relay-selector.md) | Selection constraints and user intent should be distinct from preferences and opt-in alternatives. | ADOPT_CONCEPT | No unsanctioned region/city fallback; negative empty/stale/inactive/mislocated synthetic relay responses |
| P2 | [Mullvad device API](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/mullvad-api/src/device.rs) `replace_wg_key` | Public client implements a key-replacement API, suggesting potentially less disruptive authorized rotation than delete/re-create. Endpoint semantics must be verified separately. | EXPERIMENT | Exact device identity, no unintended revocation, recoverable interrupted rotation; no real provider mutation |
| N1 | [WireGuard monitor](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/talpid-wireguard/src/lib.rs) `automatic_mtu_correction` | Automatic MTU correction exists, but a forwarded multi-zone gateway faces distinct MTU/PMTUD paths. | EXPERIMENT | Real IPv4/IPv6 MTU blackhole and fragment-path fixtures across synthetic WireGuard peers |
| N2 | [Alpine virt kernel](https://github.com/alpinelinux/aports/blob/3.24-stable/main/linux-lts/virt.x86_64.config) | Module settings enable a research path for NetVSC, VSOCK, nftables, WireGuard and BPF; package config is not an image or runtime proof. | EXPERIMENT | Guest digest + `ethtool -i/-k/-l`/module readback in admitted nested Hyper-V |
| H1 | [Mullvad known issues](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/docs/known-issues.md) | Windows Sandbox/Hyper-V can expose limitations of host WFP interception. The security boundary must include host processes outside the gateway vSwitch. | EXPERIMENT | Independent host-side and guest-side bypass probes in isolated nested Hyper-V; no production host alteration |

## Negative spaces and exclusions

- Do **not** assume a Mullvad endpoint client's policy authorizes the same forwarding that a multi-zone virtual router requires.
- Do **not** equate successful `nft` commit with atomic route, DNS and WireGuard update.
- Do **not** count a source-only `witness=True` flag as independent evidence.
- Do **not** assume kernel modules listed in Alpine's recipe are present or configured in a booted appliance.
- Do **not** treat a public Azure-hosted Linux runner with Hyper-V modules as proof of an isolated Alpine Hyper-V guest, though it can supply *read-only* NetVSC probes.
- Do **not** import Mullvad's entire Rust daemon or GPL-licensed implementation merely to use these proven concepts.
- Do **not** implement TLS interception, DPI, SR-IOV, or flowtable fast paths in the present security-critical baseline.

## Synthesis: smallest productive order

(1) Fail-closed state/epoch correctness and controlled first-hop; (2) strict relay and device-operation contracts; (3) actual kernel NetVSC/MTU/CPU measurements; (4) optional HV Socket/KVP control only if evidence justifies it. Use existing authority for privileged HIL. Public static analysis and pure oracles are admissible here; private source and private execution are not.
