# R2-PostgreSQL 18 — actual SQL prior-art temporal qualification

Product authority: [Mail Evidence temporal #4](https://github.com/SupraShellScripts/mail-evidence-private/issues/4), experiment owner [#39](https://github.com/SupraShellScripts/mail-evidence-private/issues/39). The installed SQLite temporal R1 is only an explicit bitemporal *projection*, not native PostgreSQL `WITHOUT OVERLAPS` semantics.

## Original engine, rights, and controlled deployment

Native PostgreSQL 18.7 official Docker image `postgres:18.7-trixie@sha256:e754b839f447639b7004895f4d8a4bfcb4e9dbe3a1bc035f27f646562a16fd61` is pulled by immutable manifest digest from Docker Hub, then run in a disposable GitHub-hosted standard `ubuntu-24.04` public runner, using the already-authorized fixed typed public CPU workflow. No image is built, published, retagged, or pushed. Original PostgreSQL license terms apply; do not represent this as an audited image SBOM or verified upstream signature.

A new Docker local volume stores PostgreSQL 18’s versioned data directory, no host ports, `--network none`, memory limit 1024 MiB, CPU 2, pids 256, one container and 235-second parent workload timeout. `POSTGRES_HOST_AUTH_METHOD=trust` is intentionally permitted **only inside the network-disabled disposable research container**, accessed exclusively through local `docker exec psql`. It would be prohibited for any real deployment; no persistent credentials or private data exist. The volume and container are forcibly removed at exit even after error. No private GitHub Actions minutes, paid API or model inference.

## Actual temporal SQL and original source test corpus

The corpus is directly imported from the **same frozen public SQLite fixture** already qualified under R1: six exact fictional source occurrences and six claims with duplicate Internet Message-ID, repeated acquisition lineage, beta tenant decoy, late historical approval, separate authored and acquired timestamp, explicit planned vs actual, and exact source-content SHA256.

Unlike SQLite, the actual PostgreSQL 18 query runs inside the server using `timestamptz` values, indexed source/claim joins, and explicit **valid-at**/**known-at** cutoffs. Same eight source-time/time-of-knowledge oracle cases must agree with earlier SQLite status and source counts, while the full claim set remains preserved. Four-valued results are *evidence support*, never objective truth; this is an explicit query projection, not raw PostgreSQL `FOR SYSTEM_TIME AS OF` or a proven full bitemporal DB.

Additional **genuine PostgreSQL 18** feature: a declared `PRIMARY KEY (source_id, valid_window WITHOUT OVERLAPS)` permits adjacent valid ranges for the same *source*, refuses overlapping ranges from the same source, and permits conflicting intervals from *different source IDs*. It must **not** introduce a global exclusive-value constraint that silently deletes cross-source disagreements. The original implementation uses built-in PostgreSQL GiST/btree_gist to test this feature.

Source and assessment UPDATE/DELETE operations are prohibited by SQL triggers. Cross-tenant source-claim linkage is denied by a SQL trigger. An earlier knowledge-as-of assessment is inserted and retained across a complete PostgreSQL container restart using the same volume; then retrieved unchanged even after new source knowledge is available. Observed timestamp and SQL-state source integrity are independent from untrusted email text.

## Build/operate/maintain and explicit gaps

- Runtime code: `scripts/qualify_temporal_postgres18.py`, Python 3 stdlib only as fixed launcher/SQL driver, not a production Python service; actual SQL is run by original `psql` against original PostgreSQL server. Fixed checked source/image/request, no user-controlled URL/SQL/argv or shell.
- One native receipt: server patch version 18.7, pinned OCI digest, eight exact gold scenarios, overlap constraint, same-source refusal, original source/tenant guard, disk-backed restart, clean resource teardown. Independent original GitHub run SHA/digest/runner verifier must PASS.
- Workflow: existing `gha-typed-public-cpu.yml`, one additional temporary fixed x64 matrix profile with `max_cost_usd=0` and one attempt. After an exact-head native first receipt, move this expensive Docker pull profile to **on-demand** only; retain typed manifest/executor/verifier and original hosted evidence for future R2 source pin or license rechecks.
- Does **not** establish: native PST extraction, calendar recurring objects, heterogeneous source ambiguity, UTF-8 original byte-span citation parity, SQL query user APIs, a SQL database migration, 24x7 operations, encrypted runtime, full model semantic QA, HA failover or performance viability in a free cloud service.
- Follow-ups: compare XTDB v2 official version-pinned Docker with same disjoint valid/known Oracle and explicit open/late retrospective evidence; measure cold-start, memory, resource ceiling, transaction/restart and rights. Do not accept XTDB data model or graph side effects until source/claim preservation and independent provider attestations PASS.
