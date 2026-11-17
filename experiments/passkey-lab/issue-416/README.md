# Passkey Lab R0: controllable WebAuthn / Android Credential Provider RDTE

Owner-private authority: [infrastructure-as-code-private #415](https://github.com/mark-e-deyoung/infrastructure-as-code-private/issues/415), P0 [#416](https://github.com/mark-e-deyoung/infrastructure-as-code-private/issues/416), Android P1 [#417](https://github.com/mark-e-deyoung/infrastructure-as-code-private/issues/417). Separate from USB Fabric #369; existing Agent Dispatch/sovereign scheduling and #179 owner-secret broker remain authorities. This public worktree contains **only synthetic browser test data**, not production identities.

## Verified upstream source inventory (2026-11-17)

- [Android MyVault](https://github.com/android/identity-samples/tree/main/CredentialProvider/MyVault): credential provider service, credential repository/Room, user selection, create/get and biometric prompt. Apache-2.0 educational sample; README expressly says its FIDO parser is demonstrative only. Requires Android >=14 and an appropriately configured provider.
- [Android AOSP CredentialProviderService](https://android.googlesource.com/platform/frameworks/base/+/main/core/java/android/service/credentials/CredentialProviderService.java), native platform interface.
- [AOSP fingerprint virtual AIDL HAL](https://android.googlesource.com/platform/hardware/interfaces/+/main/biometrics/fingerprint/aidl/default/): test-only enrollment, acquired/error/latency, permanent/timed lockout; depends on selected emulator image exposing this HAL. Stock AVD also supports [finger touch](https://developer.android.com/studio/run/emulator-console) via emulator console.
- [Chromium Chrome DevTools Protocol WebAuthn](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/): enable, addVirtualAuthenticator, setUserVerified, setAutomaticPresenceSimulation and credential lifecycle.
- [Chromium Android WebAuthn routing](https://chromium.googlesource.com/chromium/src/+/HEAD/components/webauthn/android/): Java and JNI route to Android 14+ Credential Manager or Google Play FIDO2; not all browser/Android modes share same backend.
- [Firefox authenticator-rs](https://github.com/mozilla/authenticator-rs), [Firefox WebAuthnHandler](https://github.com/mozilla-firefox/firefox/blob/main/dom/webauthn/WebAuthnHandler.cpp), [Bitwarden Android](https://github.com/bitwarden/android): interoperability/source review candidates.
- [Google OpenSK](https://github.com/google/OpenSK), [1Password passkey-rs](https://github.com/1Password/passkey-rs): optional CTAP2 protocol comparisons, not mandatory deployed Rust.
- [WebAuthn W3C](https://www.w3.org/TR/webauthn/) and [Google RP verification](https://developers.google.com/identity/passkeys/developer-guides/server-authentication): independent verifier requirements.

## Test architecture
```
public GHA sealed synthetic workcell
  Chrome headless + localhost RP page
  Chrome DevTools Protocol virtual authenticator
  navigator.credentials.create/get => actual browser WebAuthn ceremony
  separate Node crypto verifier: RP hash, exact origin/challenge/type,
       UP/UV policy, ES256 signature; rejects replay/tamper
  destroy virtual authenticator + browser profile on exit
```

Test deliberately distinguishes **synthetic virtual UV bit** from real biometric assertion, and is NOT proof of an Android passkey provider, hardware-backed user verification, Chrome-to-Android bridge, synced passkey export, live account or genuine FIDO physical token.

No credentials are connected to external servers. No owner Recovery Vault, OpenBao root material, personal PIN, device fingerprint, hardware security key or auth cookies. RDTE requires separate human approval for any actual owner credential ceremony.

## Planned Android test matrix
- Credential provider install/select as Android 14+ third-party service, create/get test credential, RP origin/package-binding, app/process kill and restart, credential delete.
- On stock AVD, enrolled versus unknown fingerprint via `adb emu finger touch ID`; prompt cancel/timeout/PIN fallback; on AOSP virtual HAL image, test success/failure/error/latency/lockout by the official virtual HAL controls. **No ad hoc biometric bypass on an actual phone.**
- Guest/CI matrix API34/35/36 as available; AOSP versus Play Services images (MyVault requires GMS); explicit KVM versus TCG resource measurement before declaring runner suitability.
- Expose human UI, automation CLI and agent-facing typed API with explicit test-only eligibility; keep owner approval gates out of automation.

## Hygiene and DLE
Source-only public draft PR and public standard GitHub Actions. `node --check`, headless Chrome and no new modules/network downloads. Fail closed if Chrome, Node22, or CDP cannot run; preserve RED. Exact commit/job evidence to private #416/#415. No physical/HIL, private Actions minutes, real authentication, production, merge or local-only durable state.
