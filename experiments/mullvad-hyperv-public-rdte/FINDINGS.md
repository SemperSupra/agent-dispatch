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


## Follow-on red/blue findings — October 13

### S6: Separate authorized first-hop bootstrap from user-egress admission — ADOPT_CONCEPT

Mullvad's pinned [connecting-state policy](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/docs/security.md) authorizes the exact UDP first-hop endpoint during tunnel establishment, while arbitrary user traffic stays blocked. The original *public model* incorrectly required final user-egress admission before its first-hop handshake, creating a modeled bootstrap deadlock. Corrected public `oracles/policy.py` now requires independently scoped first-hop control permission tied to current policy/control epochs but does **not** require final user-egress admission; any transition invalidates stale control permission. Rejects mismatched host, port, protocol, process identity and packet mark in model inputs. **Qualification debt:** actual Linux `fwmark`/origin enforcement, policy epochs and external v4/v6 observers are NOT_RUN. Synthetic caller identity is forgeable; do not promote to production on this model.

### S7: Interface-role control packets, DNS and rogue RA — ADOPT_CONCEPT; literal policy DEFER

Mullvad [security.md](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/docs/security.md) treats limited DHCPv4/6, NDP and DNS as deliberately scoped exceptions. A **multi-interface gateway** must distinguish WAN DHCP client from LAN DHCP server, permitted router advertisements, on-link NDP from forwarded traffic, and upstream DNS inside the tunnel. A new synthetic gateway-role oracle tests these boundaries, including deliberately wrong protocol families, rogue inbound LAN RA, global-address spoofing, forward-of-link-local, missing feature enablement, and plaintext port-53 WAN DNS.

**Known limitations:** This simplified packet tuple lacks L2 authentication, IPv6 hop limit, DHCP trust, per-vNIC interface binding, RA prefix acceptance logic, source address ownership and conntrack semantics. It is not a complete RFC 4861/8415 implementation and cannot replace native Linux firewall rules. It explicitly does **not** prove that DoH/DoQ traffic is detected (443/853 can be within TLS/QUIC); destination-53 confinement only is not a comprehensive DNS policy. Native DHCP relay/renewal, PMTUD, essential ICMPv6 and multi-zone cases remain QUALIFICATION_DEBT.

### H2: Hyper-V virtual networking bypass boundary — HIGH-PRIORITY EXPERIMENT

Mullvad's pinned [Hyper-V known issues](https://github.com/mullvad/mullvadvpn-app/blob/c70ce25bfdf500c2da2c68786336213202f1e6d5/docs/known-issues.md) explicitly reports that some Hyper-V forwarded/NAT traffic bypasses normal Windows WFP inspection paths. It describes Hyper-V firewall mitigation on supported Windows versions and limitations for Windows Sandbox/WSL2 and other virtualized traffic. **This is upstream prior art, not proof of a defect in a particular VPN consumer.**

The downstream requirement is a dual-boundary HIL matrix: host-originated TCP/UDP/DNS + guest-forwarded packets; IPv4/IPv6; direct physical path; Hyper-V switch/ACL path; tunnel gateway path; lost tunnel/VM, rule change, restart and source-independent outside observer. Compare native Hyper-V firewall profile/ACL capabilities before deciding whether built-in primitives suffice. Do not infer a WFP rule protects guest-forwarded frames, and do not assume every Hyper-V firewall feature works on every Windows build or nested cloud runner. No driver signature or custom filter needed for the read-only census.

### N3: Public cloud native NetVSC readback — MEASURED PLATFORM CAPABILITY ONLY

Read-only Azure-hosted Ubuntu runner has reported an actual NetVSC-driven NIC with GRO/GSO/TCP checksum/TSO enabled. Follow-on controlled `ethtool -l` parses **current** channel settings separately from pre-set maxima. Hosted runner hardware resource and queue counts are *not* representative of a 256/512 MiB Alpine gateway; use as a capability probe and benchmark design input only. No XDP fast-path or offload adoption is authorized by static presence alone.

### Minimal next qualifications

- Preserve H1/H2 privileged, isolated nested Hyper-V guest/packet experiment behind separate typed admission and run-owned teardown; the current public workflow does **read-only** Windows H0 only.
- Verify transport first-hop scope with an outside-WAN witness intentionally capable of detecting a deliberate cleartext packet before and after guard installation.
- Independently verify DNS, DHCP/NDP, MTU and route constraints across epoch changes and restarts, not only the currently modelled packet-field predicates.
- Adopt only changes satisfying both performance objectives and independent packet-safety evidence; keep the public/private source separation.
