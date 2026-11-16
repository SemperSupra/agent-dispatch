# M1 zero-taint preferred execution-cell empirical proof

This is an **empirical, narrow hardening test** for the *preferred* toolchain installation mode. It installs a digest-resolved Go builder into a fully expendable, one-job public GitHub Actions runner, then compiles and executes a fixture inside a separate unprivileged, network-disabled, read-only-root OCI cell with tmpfs-only tool/cache/binary locations.

The harness checks that writes to the read-only fixture and container root fail, baseline selected runner HOME/project subtrees are unchanged, the source is not altered, and a second clean execution cell has no first-cell cache/output. The entire public hosted runner is then discarded.

**Important distinction:** The owner explicitly permits user `~/.local` and project `.local` as disposable tooling-installation fallbacks, even on a reused machine. Those locations are allowed but less preferred than disposable containers, VMs and free public GHA. This strict workcell tests only the *preferred no-host-write* mode. The policy oracle in [draft PR #610](https://github.com/SemperSupra/agent-dispatch/pull/610) separately checks an allowed, scoped `.local` fallback without treating it as a violation.

Neither this test nor PR #610 proves a persistent application runtime may execute on a reused host. Service deployments must remain disposable and stateless; database/secret/audit state requiring durability must exist outside the entire runtime-node disposal boundary.

Failure classification: a source write or unexpected host-file change is **FAIL** for this strict profile; a green assertion demonstrates its exact OCI fixture only. No model, live provider OAuth, private data, paid GHA minutes, or production service.
