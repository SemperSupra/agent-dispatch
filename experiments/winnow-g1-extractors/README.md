# Winnow G1 — public-safe no-login tool packaging and security bakeoff

**Project authority:** private [SemperSupra/winnow-private #1](https://github.com/SemperSupra/winnow-private/issues/1), G1. This directory is an **independently authored public-only RDTE projection**, NOT private Winnow source. It contains no real social post, token, cookie, acquired media, proprietary code or confidential search query. The baseline two candidates match the existing G1 survey, rather than widening product scope.

## What these public GHA jobs actually test

- Native public GitHub Actions Ubuntu 24.04 on `amd64` and `arm64`, one candidate per isolated job.
- Exact PyPI wheels, immutable SHA256 known from public PyPI metadata; public PyPI network for wheel download **only**. Offline subsequent installation (`--no-index --no-deps`), clean HOME/XDG, native import and CLI help/version.
- Capability flags for current public packages; 15 repeated CLI `--version` timings (process startup only, not extraction).
- Offline synthetic URL dispatch (gallery-dl) and parth-dl strict-origin/redirection prerequisites. Red negative cases are **findings**, not a blanket product PASS. JSON results enumerate each test and fault.
- Installed version and dependency metadata. Shell scripts run only on disposable public Actions hosts with read-only GitHub token, and persist **sanitized** numerical/boolean receipts.

## Explicit no-login qualification limitation

**Credential-free CLI startup is not proof of login-free live Instagram acquisition.** Both projects can use anonymous cookies/headers, and Instagram may require login for a nominally public post. These public jobs **do not call Instagram, download original/preview image bytes, submit usernames/URLs, access Meta OAuth, or perform automated login/bypass.** No private Winnow repo checkout in public Actions.

A source-backed permitted single image and independently selected carousel child, actual bytes and hash, and platform-terms/rights authorization are still required by Winnow #1. A public-domain Wikimedia image can test independent Go transport/storage but is **not an Instagram proof**.

## Current candidates / package pins

| Tool | Pin | Wheel SHA256 | License | Status |
|---|---|---|---|---|
| gallery-dl | 1.32.19 | `f6b1eb5e9a7409a988b754335d99dbb1873e130d133ed5d164d32e5e645d1c50` | GPL-2.0 | Current provisional Go external CLI adapter; source viable only if permitted real selected bytes qualify |
| parth-dl | 1.2.1 | `3117e4c7bd6fe7c6f1b668d05c40c303e54fc3992019bf6a40ab13b98434ebff` | MIT | Challenger: no runtime package deps, JSON and carousel entries; direct per-child download interface unverified |

Source/provenance: https://pypi.org/project/gallery-dl/1.32.19/ and https://pypi.org/project/parth-dl/1.2.1/ , https://github.com/mikf/gallery-dl , https://github.com/parthmax2/parth-dl . Neither pinned PyPI wheel has published provenance attestation. Inspect upstream file behavior, not just README; no proof the PyPI artifact was reproducibly built from the GitHub source.

## Important upstream code risks requiring Go wrapper isolation

- parth-dl `parth_dl/extractors.py` configures `http.cookiejar.CookieJar`, fake browser request headers, `X-IG-App-ID` and a logged-out query doc ID. This may make HTTP requests without owner credentials, but is not platform-authorized anonymous access.
- parth-dl input validation accepts `http://instagram.com` and media validation may accept userinfo or an unexpected port; validate URL *at Winnow's Go boundary and on redirects*, fail closed on private DNS/IP and userinfo. Upstream reads metadata responses without an obvious explicit bound; externalize CPU, memory, body, time and output limits.
- parth-dl's `download` iterates all entries; JSON `entries` is not independently verified selected-child-only acquisition.
- gallery-dl `--range` represents an extraction ordinal, not necessarily a stable carousel child ID across separate requests. A changed child list or signed CDN URL could corrupt identity/provenance. Always compare selection and final receipt to immutable source evidence.
- Review GPL distribution implications if bundling gallery-dl in a redistributable OCI image. Direct executable use does not itself prove a specific licensing outcome.

## Excluded or second-tier sources

Instaloader and yt-dlp are legitimate alternatives worth a brief source/maintenance comparison but not needed for an initial two-tool live feasibility gate. Both have Instagram extractors and may encounter login walls. An unverified `instagramrobot` repository or anonymous third-party download API is **not automatically a qualifying source**. The official professional-account Meta API is a distinct separately authorized own-content integration, not a public anonymous downloader.

## Interpretation

A successful Actions workflow means **this exact offline test harness ran**, not `SOURCE_PASS`, `NO_LOGIN_CONFIRMED`, `CAROUSEL_CHILD_VERIFIED`, `IMAGE_BYTES_ACQUIRED` or `RELEASE_READY`. A security negative is reported as `HOLD` and must not be suppressed to make CI green. Do not merge private Winnow or grant Meta account/host access as a result.

Next acceptance tests remain *private* owner-approved sources for single-image and two-child carousel, no bypass, immutable slide ID/selected-byte digest, input/redirect/SSRF and output limits, atomic writes/receipts, exact source and binary.
