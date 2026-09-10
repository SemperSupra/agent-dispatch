# xa11y Windows ARM64 Python wheel candidate

Public candidate experiment against upstream `xa11y/xa11y` release `v0.14.0`, commit `7e623f3d4d24264dd9a56399090a8099020b46ea`.

## Publicly reconstructable problem

`xa11y` publishes Python wheels for Linux x86_64/aarch64 and macOS x86_64/aarch64, but its Windows Python-wheel job targets x86_64 only. The same public release workflow already builds the JavaScript native binding for `aarch64-pc-windows-msvc`. A native Windows ARM64 GitHub-hosted runner cannot obtain `xa11y==0.14.0` with binary-only pip installation.

## Candidate

Extend the Windows Python-wheel build to include a native Windows ARM64 runner and `aarch64` maturin target while preserving the existing x86_64 build.

The adjacent `publish.patch` is the intended minimal upstream-shaped change. The lab workflow builds from the exact unmodified upstream release commit, using the additional target/runner implied by that patch, then installs and probes the exact generated wheel on native Windows ARM64.

## Qualification claim

A passing lab proves only that the missing Python wheel can be built, installed, imported, and exercised on the native Windows ARM64 hosted runner. It does not prove interactive desktop accessibility behavior; that remains a separate physical dogfood tier.

No private source, fixtures, endpoints, rationale, or credentials are used.