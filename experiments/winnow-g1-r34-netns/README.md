# Winnow G1 R34 — ephemeral public-runner OS network isolation canary

**Purpose:** Answer one bounded infrastructure question: *can standard public GitHub-hosted Ubuntu AMD64 and ARM64 runners create a separate, route-less Linux network namespace and execute an unprivileged test process whose attempted outbound TCP connections are denied by the kernel?* This is distinct from R32's Python socket-method interception.

**Privacy:** Everything here is public-safe synthetic code. No private Winnow repository code, user files, personal URLs, credentials, real Instagram media, or third-party proprietary source. The only connection attempts target RFC 5737 TEST-NET-1 `192.0.2.1` and RFC 3849 documentation `2001:db8::1`, and are made *inside* an isolated network namespace. No request to Instagram. The `sudo` invocation is scoped to creating an ephemeral namespace in a disposable GHA runner; no production or personal host changes.

## Acceptance

1. The host network namespace ID is recorded before creating the child namespace.
2. `sudo -n unshare --net` succeeds; `setpriv` drops the child to uid/gid 65534 and clears supplemental groups.
3. Child reports an **independent** namespace and **zero effective Linux capabilities**.
4. Child has neither a default IPv4 nor default IPv6 route.
5. The IPv4/IPv6 documentation-only TCP connection canaries fail immediately with network unreachable, host unreachable, access denied or unavailable address-family conditions.
6. The test logs include exact Git source SHA, architecture, raw canary denial errno classes, and a single explicit verdict.

If the runner denies `sudo unshare` (or a requirement is missing), classify **R34_SETUP_BLOCKED**, not `OS_EGRESS_PASS`. Do not fall back to an ordinary Python monkeypatch or perform tests on a personal machine. If unavailable, separately qualify a disposable `docker run --network none` container as a **different** sandbox candidate.

## Evidence boundaries

A passing R34 run would show **capability of this disposable GHA environment**, not production confinement of gallery-dl or parth-dl, inherited subprocess credentials, DNS/redirect safety, source rights, final selected-image bytes, cross-workflow portability, or permission to change a TrueNAS/BigMac host. Actual extractor execution inside a hardened network-denied sandbox needs separately bounded integration and failure-handling tests.

This work is an independent public PR/branch from frozen initial G1 bakeoff commit `6c371b2f5112620a91a09b439339f87ebb37b752`. It does not modify the local actor's ongoing G1 public branch, public R32 PR #580, or private Winnow code. Owner DLE #1 remains authority; G1 live Instagram and release gates remain HOLD.
