# USB Fabric Network N1 — network policy and qualification
Authority: [private DLE #471](https://github.com/mark-e-deyoung/infrastructure-as-code-private/issues/471); parents #369/#392/#432. **This branch is experimental, NOT a deployed firewall or USB broker.**

## Source provenance and reuse
- Linux USB/IP userspace `tools/usb/usbip/src/usbip_network.c` and `usbipd.c`: TCP socket/control; raw TCP/3240 has no per-lease authority. https://github.com/torvalds/linux/tree/master/tools/usb/usbip/src
- Linux `net/sched/sch_netem.c` and iproute2 `tc/q_netem.c`: deterministic impairment without writing bespoke network emulators. https://github.com/iproute2/iproute2
- nftables/libnftables: prefer atomic native ruleset transactions and JSON API, never string-concatenate privileged shell commands. https://netfilter.org/projects/nftables/
- WireGuard namespaces/routing: existing Linux tunnel primitives, no new crypto. https://www.wireguard.com/netns/
- In-house: Pi two-guest actual USB/IP HID Ethernet PR #803 (private DLE #441), same-guest transport #800 (#439), USB Fabric control/journal #429. Do not duplicate their test harness or broker.
No upstream source has been copied.

## Current implemented scope
Package `usbnetpolicy` is a **pure Go decision primitive**, using standard-library `net/netip` and deterministic negative unit tests. It requires: authenticated principal, authenticated path, same device+principal in active lease, nonzero identical epoch, configured transport/port, explicit source/destination CIDR membership. It cannot create, grant, commit, revoke, or recover leases; it cannot configure a firewall. It MUST NOT be wired in as a replacement for broker validation. G1 static evaluation only.

## Deployment profiles
A. Same-host/same-LAN, direct transport but explicit host policy.
B. USB VLAN/subnet, routed through firewall with per-endpoint allowlists. Example only: 10.77.20.0/24 provider and 10.77.30.0/24 consumers; verify CIDR conflicts before deployment.
C. Remote encrypted overlay with peer identity; no public raw USB/IP port.

## Independent workcells (do not modify sibling source paths)
- N1: disposable netns/veth + VLAN and L3 isolation, IPv4/IPv6 controls, signed results.
- N2: nftables atomic deny policy; conntrack/revoke negative test, live socket termination; fail closed when enforcer unavailable.
- N3: tc netem/qdisc and congestion paired HID/bulk comparison, 5+ repetitions, p50/p95/p99 and CPU.
- N4: WireGuard remote path + identity, route changes/NAT/partition, no secrets on public runners.
- N5: reuse PR #803 two separate QEMU guests, actual USB/IP URB and evdev; contrast usbredir. No mock proof substitution.
- N6: bind network admission to sole Go broker, durable lease epoch and journal; prove live revocation and re-admission after crash.
Concurrency: each independent branch/path; integration consumes immutable SHA evidence and no overlapping source editors.

## Build / deploy / O&M
Source-only: `cd experiments/usb-fabric-network-n1 && go test ./...` on hosted public Linux free runner. Production deployment NOT authorized. G2 must execute netns/firewall inside disposable **isolated guest** if required privileges unavailable to runner; never modify host network. G3 integrates PR #803 exact head only when verified, G4 broker journal; G5 physical Pi/Wyse HIL requires separate approval. 
Before any eventual rollout: preflight subnet overlap, IPv6 escape, IPv4-mapped IP handling, policy diff, dry-run JSON transaction, take rollback snapshot, confirm administrative access and in-band/management separation. During O&M: reconcile desired vs observed routes/rules/conntrack and principal/device epochs, alert on unauthorized traffic and p95/p99 drift, expire leases fail closed, preserve captures metadata without payloads. Shutdown/rollback: stop new admissions, revoke and drain USB attachments, confirm release with guest evidence, then restore last qualified ruleset only through owner-approved controlled process.

## Acceptance / evidence
G0 local/upstream source mapped; G1 pure Go tests; G2 actual netns traffic enforcement; G3 two-guest USB/IP URB+guest observation; G4 live broker revoke and durable re-admission; G5 HIL. `go test` success NEVER implies G2-G5. Store exact commit SHA, upstream versions, workflow run ID, test environment and RED negative receipts in DLE. No private Actions minutes, privileged host changes, secrets or production routing.
