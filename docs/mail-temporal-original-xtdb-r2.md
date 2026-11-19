# XTDB native temporal source-first R2 — bounded original-runtime qualification

Authority: [Mail Evidence #4](https://github.com/SupraShellScripts/mail-evidence-private/issues/4); [DOE #39](https://github.com/SupraShellScripts/mail-evidence-private/issues/39). This public synthetic experiment is a **distinct** XTDB source/operations lane, not a completed eight-case parity test with SQLite/PostgreSQL.

## Original source and rights

XTDB is MPL-2.0, as verified against upstream `xtdb/xtdb` repository LICENSE. Chosen public `linux/amd64` GHCR original XTDB image `ghcr.io/xtdb/xtdb@sha256:aa7483e48674446a4892e0ea56a0953502fa5ccb9c4c803a9fb569ea5f0c28fe` was published with upstream `g6cd79ee` source snapshot. This is a **snapshot**, **NOT** the later v2.2.0 release, so code/behavior observed at this digest cannot be advertised as current release compatibility. Its PostgreSQL-wire client is the previously qualified official `postgres:18.7-trixie@sha256:e754b839f447639b7004895f4d8a4bfcb4e9dbe3a1bc035f27f646562a16fd61` image, itself SHA-pinned.

Upstream docs:
- https://docs.xtdb.com/intro/installation-via-docker.html
- https://docs.xtdb.com/reference/main/sql/txs.html
- https://docs.xtdb.com/reference/main/sql/queries.html
- https://docs.xtdb.com/quickstart/sql-overview.html

## Specific original engine operations

Fixed `requests/gha/mail-temporal-xtdb-r2.json` admits one public synthetic Ubuntu x64 standard GitHub Actions workcell, one attempt, max $0, 235-second internal limit, 8-minute parent job cap. `scripts/qualify_temporal_xtdb.py` downloads **only** the original fixed image digests, creates a disposable `--internal` Docker bridge and named data volume, then starts XTDB with two CPUs, 3GiB RAM and 256 PID cap and no public port mapping. All PostgreSQL-wire queries run through the original PG client image on the same internal bridge; no private mail/credentials, paid model API or general shell request. Persistent data volume and network are forcibly removed even after failure.

The first narrowly scoped acceptance test:
1. Original server starts and accepts PostgreSQL-wire `SELECT 1` from the isolated original client.
2. Three fictional source **occurrence** IDs, including two unrelated accounts with same Message-ID, remain distinct; a tenant-filtered query returns only the two alpha rows. Merely storing a tenant text property is not a database-enforced row-level ACL; production authorization remains separate.
3. Two `INSERT` versions under **one derived assessment ID** exercise XTDB's actual default **valid-time upsert** and historical `FOR VALID_TIME AS OF` queries. The old effective-time result remains queryable; a later effective-time result is different.
4. `FOR VALID_TIME ALL FOR SYSTEM_TIME ALL` must show at least two historical assessment records instead of losing original versions.
5. A complete stop/start against the same named volume must preserve original source row count and old effective-time query. No authenticated service, model or PST parsing.
6. Receipt explicitly `source_upsert_is_application_risk=true` and `same_eight_case_oracle_qualified=false`: this **does not** prove full calendar/valid+knowledge-time parity against SQLite/PostgreSQL, precise acquired_at historical import, source immutability by XTDB itself, or global contradiction rules.

## Promotion/maintenance gates

Do not use an original PST source occurrence ID as a mutable document key without an append-only adapter discipline. A default XTDB upsert over the same `_id` can change the **derived state**; only our separate immutable source namespace and native archive locators remain forensic authority. A later retrospective claim may rewrite an inferred value but must never erase a source observation or turn planned intent into completed truth. In built-in XTDB, `_system_from` records database transaction time; it is **not the original Outlook acquisition time** unless a separately qualified historical import/override policy makes them correspond.

The first test is purposefully bounded to source/valid-time/native system-history, no third-party Python packages or xtdb java package build. Snapshot image requires a fresh rights/registry/security evaluation before any production scenario. Future bakeoffs need full same eight-case temporal gold and actual model-independent source-citation oracle, E2E auth, restart/checkpoint performance and multiple account tenancy enforcement. Do not infer a source-operation permission or Pandora workset admission from passing a public GHA runtime.

Routine matrix hygiene: after native first qualification, remove this expensive two-image pull from *every* PR matrix, retaining fixed reviewed manifest and independent receipt only through explicit reviewed on-demand workflow_dispatch/workflow_call. No new workflow, scheduler, public daemon or consumer-accessible database created.
