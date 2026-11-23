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

## Current first-failure trail and verified original XTDB native witness (2026-11-24)

- Initial source head `54ceaf56eb911e19138d80503949d0969ae597d8`: [public GHA #45291107064](https://github.com/SemperSupra/agent-dispatch/actions/runs/45291107064) FAILED native XTDB job `138099848086`, receipt `GHA_REQUEST_QUALIFIED=false`; first-failure code `NATIVE_XTDB_IO`. The source's psql wrapper assumed a successful SQL command always emitted one result line; a zero-row `INSERT` can emit no result, causing `IndexError`. This is a diagnosed likely cause, not a proven stack trace (stderr intentionally suppressed); source code was subsequently corrected to return the empty string.
- Intermediate source head `f9de5a97541442d7fe3355eb3d1430df8911761e`: [public GHA #45291389818](https://github.com/SemperSupra/agent-dispatch/actions/runs/45291389818) FAILED the offline contract test, because the newly added unit test itself passed literal backslash-n, not actual LF bytes. The production parser correction remained; changed the synthetic test to `chr(10)` so the expected newline is unambiguous. Do not erase the negative receipt.
- **First real native PASS:** source head `25c7103d2d673fff4aaf12c8dfe099dae9bda732`, [public GHA #45291589311](https://github.com/SemperSupra/agent-dispatch/actions/runs/45291589311) completed SUCCESS. Original XTDB job `138101494985`: `GHA_REQUEST_QUALIFIED=true`, independent provider-attested `GHA_RECEIPT_INDEPENDENT_VERDICT=PASS`; original GitHub artifact `14874875804`, uploaded ZIP SHA256 `6e760a743918d309a3d7464e6304ac344509555641f479e35cc02e90ddaa4cf6`; receipt SHA256 `64fbb26ee83e88aa70fab98f05d4af7bb06afdffa6d1d72706673434b6501e7b`. Actual original engine executed with three distinct fictional source occurrences, two valid-time queries, system-history and volume restart.
- **Post-qualification CI hygiene:** remove this now-observed expensive two-OCI-image-pull XTDB job from the standard four-core on-PR CPU matrix. Preserve the exact immutable XTDB image, Postgres client image, source/test, reviewed typed request and separate provider-bound verifier for explicit on-demand `workflow_dispatch/workflow_call` on main. A source-contract test ensures the fixed profile exists but cannot creep back into unrelated default PR CI. The existing source-only contract and four routine native jobs must PASS again on the final head before merge.
- **Acceptance boundary:** This native PASS qualifies only the specified XTDB snapshot/runtime behavior. It is not a v2.2.0 release proof; the fixture is *not* the exact six-source/eight-case SQLite/Postgres gold; XTDB default upsert semantics remain an unmitigated source-occurrence write risk if application keys collide. Never bind user archive evidence directly to mutable logical entity keys, and do not claim native PST, true belief revision, model-generated fact accuracy, full O&M, security isolation, image signature/SBOM or release promotion.
