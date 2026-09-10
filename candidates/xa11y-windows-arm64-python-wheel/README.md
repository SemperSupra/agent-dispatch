# xa11y Windows ARM64 Python wheel candidate

Public candidate experiment for upstream `xa11y/xa11y` release 0.14.0.

## Publicly reconstructable problem

`xa11y` publishes Python wheels for Linux x86_64/aarch64 and macOS x86_64/aarch64, but its Windows Python-wheel job targets x86_64 only. The same public release workflow already builds the JavaScript native binding for `aarch64-pc-windows-msvc`. A native Windows ARM64 GitHub-hosted runner cannot obtain `xa11y==0.14.0` with binary-only pip installation.

## Candidate

Extend the Windows Python-wheel build to include a native Windows ARM64 runner and `aarch64` maturin target while preserving the existing x86_64 build.

The adjacent `publish.patch` is the intended minimal upstream-shaped change.

## Public qualification

The successful candidate run used exact public release-synchronized upstream commit `44594a9705a3f3213a9b58bc205f4e6335c9606b` on native `windows-11-arm` with ARM64 CPython 3.12.10 and the same `PyO3/maturin-action@v1` build mechanism used upstream.

It produced:

`xa11y-0.14.0-cp39-abi3-win_arm64.whl`

The job then installed exactly that locally generated wheel with pip using `--no-index --only-binary=:all:`, imported `xa11y`, confirmed `App.by_name`, and verified a missing-application negative control surfaced as `SelectorNotMatchedError`, an `XA11yError`.

The retained Actions artifact is `xa11y-0.14.0-windows-arm64-candidate` from candidate workflow run 34433964860.

An earlier control against annotated tag target `7e623f3d4d24264dd9a56399090a8099020b46ea` successfully built a native ARM64 wheel but exposed an important release-process detail: that tagged commit still carried Python binding version 0.13.0. Upstream's subsequent release-synchronization commits advance the Python package to 0.14.0. The successful qualification therefore pins the exact release-synchronized public source state rather than silently overriding package metadata.

## Claim boundary

This proves the missing Python wheel can be built, installed, imported, and exercised on native Windows ARM64. It does not claim interactive desktop accessibility behavior; that remains a separate physical dogfood tier.

No private source, fixtures, endpoints, rationale, or credentials are used.