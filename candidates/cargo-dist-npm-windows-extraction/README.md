# cargo-dist Windows npm extraction/error candidate

Public candidate experiment against `axodotdev/cargo-dist` issue #2437 and public `main` commit `c65a1a932e2661e05d6640716850d36b0f47efd7`.

## Publicly reconstructable problem

The generated npm binary installer invokes Windows PowerShell `Expand-Archive` without an execution-policy override and treats process exit status `0` as extraction success. Under a Restricted PowerShell policy the Archive module can fail to load, and failures inside the command block are not guaranteed to produce a trustworthy non-zero process result. The installer may therefore claim success while no binary was extracted.

Upstream issue: `axodotdev/cargo-dist#2437`.

## Candidate hypothesis

Keep the existing Windows PowerShell extraction path, but:

1. invoke it with `-ExecutionPolicy Bypass` so a Restricted local policy does not prevent the built-in archive operation;
2. make `Expand-Archive` failure terminating with `-ErrorAction Stop`;
3. catch the failure and explicitly `exit 1`, preserving the existing Node-side non-zero rejection path.

The adjacent patch is intentionally limited to `cargo-dist/templates/installer/npm/binary-install.js`.

## Qualification

The public lab should establish separately that:

- the unmodified upstream shape fails or misreports under a simulated Restricted policy;
- the candidate extracts a valid Windows zip under the same policy;
- a genuinely invalid zip returns non-zero under the candidate rather than being reported as successful;
- no private fixtures, credentials, or rationale are required.

This is candidate evidence only. It is not an upstream PR and does not imply maintainer acceptance.
