# R62 real etcd stale-snapshot recovery negative (public safe)

This is an **independent native provider** counterexample, not protected production restore.

Using the official SHA256-pinned etcd 3.6.16 Linux-amd64 upstream tarball, the disposable public runner:
1. Starts a real one-member etcd only as a **restore oracle**, not HA.
2. Writes epoch=7 and remaining-budget=1, and takes a verified native snapshot.
3. Commits epoch=8, remaining-budget=0 and an UNKNOWN effect record.
4. Stops etcd and runs `etcdutl snapshot restore --bump-revision 100000 --mark-compacted`.
5. Restarts the restored cluster and verifies that the older epoch, unspent budget and missing UNKNOWN survived **despite the revision bump**. A real etcd conditional transaction then accepts an additional effect claim against the restored stale budget (EXPECTED RED).
6. Compares to a test-only receipt preserved *outside the restored data directory*, detecting missing liability.

Reproduction: `bash experiments/fencing/restore-r62/run.sh` on disposable Linux amd64 with curl/sha256sum/tar/Python3.

No private source, credentials, production host, shared backup path or effectful external service is touched. All resources are ephemeral and cleaned. The comparison receipt is **not independently durable/authenticated** across actual host failures. This proves why a protected external high-water/UNKNOWN reconciliation protocol is required and why etcd's revision bump alone is insufficient. Production restore remains HOLD.

## R63 fail-closed preflight (not a production guard)

The separate `guard.py` compares readback against a test-only receipt outside the restored data directory. A genuine native old restore must produce **exit 42/HOLD** before any new effect; the original script then intentionally bypasses it to reproduce the existing expected-RED capacity overclaim. Missing/malformed witness exits 43. This fixture lacks authenticated or separately durable signer/custody; it **does not** solve `HOLD_PROTECTED_RESTORE`.
