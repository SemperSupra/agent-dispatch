# R50-C — mobile capability receipt trust boundary

This standalone **Go stdlib verifier** sits between a consenting Android/iOS/iPadOS companion app and the existing private Go fleet controller. It creates no enrollment, trust anchor, global account or persistent database and cannot contact a device.

The client emits a canonical JSON claim and an Ed25519 signature. The controller MUST supply an independently authenticated, device-paired public key and authoritative local records for consent generation, enrollment generation, allowed scope, substrate, actual physical attestation state and durable nonce consumption. The payload's `substrate=physical` is **not physical attestation**. The boolean `RealDeviceAttested` in synthetic tests is only a mock of a future controller-verified physical HIL admission. An attacker must not supply the Enrollment record or Replay ledger over any remote API.

Admission refuses noncanonical/duplicated JSON, extra fields, invalid signatures, wrong/malformed platform and opaque IDs, unapproved scopes, revoked consent, stale generation, old/future/overlong TTL, replay and emulator-to-physical role escalation. Emulators may issue only `simulator_ui_oracle` receipts and are always classified `SIMULATED_TEST_RECEIPT_NOT_FLEET_PLACEMENT`. Real-device app assertions, if the trusted register attests identity, are classified `REGISTERED_PHYSICAL_APP_ASSERTION_NEEDS_RUNTIME_ADMISSION` — **not** permission for arbitrary host or background execution. The existing Agent Dispatch scheduler and separate OS battery/thermal/permission policy still decide placement.

The tenant projection includes only specifically assigned opaque virtual task handles, not device identity, mobile hardware inventory/capability, type/count of unused devices or host PCI/USB information. Keep the full private registry, signatures, versioned consent proofs and logs out of public GHA and ordinary guest views.

Public workflow runs native offline Go tests on standard free AMD64 and ARM64 GitHub runners. Neither test runs an app or observes a physical phone. The signed test keys are generated in volatile test memory, with no production signing keys.
