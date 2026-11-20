# R27-H18 — Post-crash signed recovery binding (synthetic contract)

Authority: private USB Fabric DLE #369 / #443 / #470. This contract is deliberately isolated from the production actuator and guest implementation. It does **not** lift release holds.

## Source-derived blocker

The current `guestwire/cmd/runtimeguest/main.go` accepts a new bind at startup and after a complete observed EV_KEY UP; the `runtimeproof.Authority` requires an observed signed DOWN under the currently active random challenge before accepting a signed UP. A host crash while KEY_A is HELD destroys the in-memory verifier/challenge. Merely reissuing QMP key-up (H14/H16/H17) cannot prove it reached the guest and must never clear the durable HELD journal. Existing guest code cannot accept a new binding while waiting for evdev key-up.

## Proposed recovery protocol and control ownership

1. Host durable journal indicates HELD=true; controller proves sole identity of the surviving QEMU process and authenticates the provisioned guest signing public key independently of the guest control channel. Stale source, alternative monitor and same-UID compromised actor remain explicit threats.
2. The host generates a **new cryptographically random recovery challenge** and binds it to the original VM/host/guest/lease epochs, generation, and release sequence. Neither the guest nor client supplies trust identity.
3. An enhanced guest sensor accepts a recovery-specific rebind while HELD and samples **actual kernel evdev current-key state**, e.g. via EVIOCGKEY. It must not sign a cached host boolean, a raw QMP ACK or a synthetic unobserved key-down. The sensor signs a domain-separated held snapshot with increasing sequence.
4. Only after verifying held snapshot may the host issue emergency QMP key-up. The host records actual ACK, but HELD stays true.
5. The guest sensor signs the independently *observed* EV_KEY UP under the new recovery challenge and strictly increasing sequence. The host verifies signature, key pin, source, challenge, scope and order.
6. The host still requires device/topology and exclusive management ownership reconciliation and an fsynced journal transition before admitting a new lease, following H15. A signed UP alone is not admission.

## Code and evidence

`recoveryproof/recovery.go` implements the separate canonical Ed25519 domain and monotonic verification state machine; its tests reject wrong signing keys, old challenges, scope changes, stale/replayed snapshots, QMP-only evidence, and missing guest UP.

**Not implemented / NOT_TESTED:** EVIOCGKEY guest snapshot support; concurrent control binding while the Linux guest is waiting in evdev; durable recovery challenge/host epoch provenance; wiring into actuator runtime, journal and topology; actual post-crash signed guest UP and safe readmission; physical/production guest attestation. The synthetic initramfs private key remains extractable.

## Acceptance and rollback

A later workcell must qualify both positive and negative controls in one disposable real-QEMU run with actual guest state, controlled QMP isolation and job logs. Until then these transitions are protocol specification plus offline executable cryptographic tests. Rollback: discard the H18 draft branch. No mainline merge, host secret, physical HIL, or paid private CI runner.
