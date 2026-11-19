# R21-B real evdev provenance — DLE #468

Independent P0 workcell stacked on R20-B exact head `9a3e2de9d12873a51553c5ad3332940f32e6a7f5`. Existing R20-B only proves TEST-ONLY verifier-contract behavior, with simulated QMP acknowledgment.

Acceptance experiment: witness actual Linux guest kernel evdev KEY_A DOWN and UP (not merely a host generated JSON fixture), cryptographically bind the precise event sequence to guest/device/host+guest+lease epoch/generation/release sequence and fresh challenge, verify through the existing `heldledger.Store` without cloning manager. For each wrong-key/guest/generation/challenge, stale DOWN, lost UP, native USB/IP detach-only, and replay across a new lease, require byte-identical durable HELD and B blocked. One valid release may clear exactly one held lease; a *second independent real* evdev sequence must be needed for the new lease.

Ephemeral public CI signing keys and UART event observation are not production trust roots. Guest-held protected keys, provisioning, attestation and real QMP ACK remain unqualified. Reuse Go stdlib crypto/ed25519 and inherited test suite, do not create a second broker. Retain failing receipts, exact SHA/Actions IDs and final no-taint proof before DLE changes. Draft only, public/free CI, no host modules/secrets/physical hardware/production/merge.
