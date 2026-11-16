# Disposable fencing counterexample fixtures (R60)

This folder preserves portable, **public-safe** source for three independently bounded qualification lanes. It is a test fixture only: NOT a coordinator, lock authority, credential manager, sidecar integration, or production release artifact.

Reproduce from a disposable Linux environment with Git, Python 3 + stdlib SQLite and Go >=1.23 with a race-capable toolchain:

```sh
sh run_batch.sh
```

- `cell-git-cas/git_cas_probe.py`: real **local native Git** update-ref collision semantics. It does NOT exercise hosted GitHub GraphQL, a real GitHub App, or cross-host authentication. Unrestricted ref reset reproduces ABA.
- `cell-sink/sink_test.go`: in-memory Go semantic negative/positive oracle for commit-time fencing, UNKNOWN reservation, idempotency and partition fail-closed; preflight-only authorization admits a stale late effect in the expected-RED control.
- `cell-sql-restore/sqlite_restore_probe.py`: real **local SQLite** transactions; restoring a stale old snapshot erases an UNKNOWN liability and permits new admission. The simulated independent receipt detects divergence. This is NOT Cloudflare PITR qualification.

The tests are intentionally non-effectful and use temp files only. They do not create cloud resources, send provider requests, require credentials, or install dependencies. Do not publish the private application source, worksets or tokens alongside the fixtures. The original local R60 fixture archive SHA256 was `7eede53d9eca71ac120deb6a415cb6bfa78c813e4a7213bba1eb3aa1f9cc5267`; this Git tree retains **source fixtures**, not the original archive or its per-run log receipts.

**Provider acceptance remains UNKNOWN:** GitHub atomic beforeOid/force/delete protections, Cloudflare DO transactions/PITR/quota, etcd cluster/revision/rollback, and the real downstream executor's fencing/idempotency. Use separate, authorized, provider-backed disposable testing. No source-level fixture is evidence of live OCI primary or a released production coordination mechanism.
