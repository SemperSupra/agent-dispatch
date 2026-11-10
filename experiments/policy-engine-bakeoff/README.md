# Native Podman Quadlet authorization-engine bakeoff

**Synthetic/public-safe RDTE, 10 November 2026.** Actual successful [public GitHub Actions workflow run #42849956715](https://github.com/SemperSupra/agent-dispatch/actions/runs/42849956715) at source SHA `97baabb07cd45f8c444d5f1ce862e88835eff522` on Ubuntu 24.04 GitHub-hosted `amd64` and `arm64` runners. **10/10 jobs PASS.** This is not a production admission or release gate.

## Tested deployment and measurement

Every job installs native **Podman 4.9.3** and uses **systemd 255** to generate and start the repository's real `.container` / `.network` Quadlet files. Services bind HTTP to loopback; there is no protected code, Pandora access, real credential or private GitHub repository. The published workflow is intentionally scoped to its named public RDTE branch, with `contents: read` and no GHA write or deploy privileges.

Same synthetic `principal=worker-a`, `resource=workset-a`, `action=observe` semantics: permit correct tuple; deny wrong principal; 12 warmups; 160 serial HTTP request/response decisions; 160 8-worker HTTP decisions; revoke; verify denial. All HTTP timings use new connections per request via Python standard library, not an embedded-code microbenchmark. For OPAL the decision service is its inline OPA, **not** a measurement of Git-to-OPA propagation.

| Candidate | Arch | Quadlet systemd start ms | p50 HTTP ms | p95 HTTP ms | 8-worker req/s | memory snapshot MB | uncompressed image MB |
|---|---|---:|---:|---:|---:|---:|---:|
| OPA | amd64 | 1465 | 0.475 | 0.551 | 2259.9 | 13.3 | 66.5 |
| OPA | arm64 | 847 | 0.825 | 0.984 | 1547.4 | 13.6 | 62.7 |
| OpenFGA | amd64 | 1326 | 0.557 | 0.643 | 2738.1 | 20.3 | 83.4 |
| OpenFGA | arm64 | 832 | 1.056 | 1.172 | 1771.9 | 20.6 | 78.3 |
| SpiceDB | amd64 | 2259 | 0.880 | 0.994 | 1695.0 | 40.7 | 102.8 |
| SpiceDB | arm64 | 798 | 1.071 | 1.143 | 1727.7 | 42.8 | 97.1 |
| Casbin v3 | amd64 | 1578 | 0.365 | 0.411 | 2659.6 | 4.1 | 9.0 |
| Casbin v3 | arm64 | 756 | 0.505 | 0.564 | 1853.8 | 4.1 | 8.3 |
| OPAL + OPA | amd64 | 2801 | 0.513 | 0.591 | 1999.3 | 195.1 | 1192.0 |
| OPAL + OPA | arm64 | 3060 | 0.576 | 0.678 | 1964.0 | 200.5 | 1233.8 |

Image size sums Podman's architecture-specific image sizes, not unique shared-layer storage or registry download bytes. Memory is a **single post-benchmark podman-stats reading**, not idle/peak RSS. Quadlet start **excludes apt installation, image pulls and compilation**. Separate ephemeral VM runs are not CPU-controlled comparisons. Test models/storage are in-memory and will not survive service destruction.

## Actual source-code and dependency analysis

| Engine | Source inspected | Core dependencies and footprint | Dependencies required in a durable deployment |
|---|---|---|---|
| **OPA** | [Go manifest](https://github.com/open-policy-agent/opa/blob/main/go.mod) inspected blob `24078a4b7e9d9a04db38289261f6d8fa3a1ba9de`; [bundle plugin](https://github.com/open-policy-agent/opa/blob/main/v1/plugins/bundle/plugin.go), [downloader](https://github.com/open-policy-agent/opa/blob/main/v1/download/download.go) | Current upstream source Go 1.26.0; 52 direct entries in first Go `require` block (includes test/build use): JWX, OCI/ORAS, Badger, OTel, Prometheus, gRPC. **No separate running database required.** | Signed HTTP/OCI bundle publisher or registry, read credentials, mandatory signing config, persistent bundle directory if required; proof of expiration, revocation and rollback constraints. The benchmark used the REST policy API instead of signed bundles. |
| **OPAL + OPA** | [Python server source](https://github.com/permitio/opal/blob/master/packages/opal-server/opal_server/git_fetcher.py), blob `0605c91e88d1a7cf2929a8505ff40383d68acb17`; [server/client/common requirements](https://github.com/permitio/opal/tree/master/packages) and upstream compose example | Python FastAPI, Pydantic, uvicorn, websockets, PyJWT, pygit2, GitPython, aiohttp, ddtrace; **server** source requires Python >=3.11,<3.13; client allows <3.14. Git operations protected by live in-flight scope guard. | **Tested published-style topology:** PostgreSQL broadcaster + OPAL server + OPAL client with inline OPA. Redis/Kafka are alternative broadcast transports; authenticated WebSocket subscription and policy Git access still required. Three services, roughly 195–200 MB measured snapshot and 1.19–1.23 GB uncompressed image total. |
| **OpenFGA** | [Go manifest](https://github.com/openfga/openfga/blob/main/go.mod) blob `845aa96c2782e6ef83686f91888de31e58b48af1`, [config schema](https://github.com/openfga/openfga/blob/main/.config-schema.json), storage API | Current upstream Go 1.26 / toolchain 1.27.3; 53 first-group direct Go modules: CEL, JWT, gRPC, pgx/Postgres, MySQL and SQLite drivers. | In-memory adapter is **development only**. Persistent options: PostgreSQL 14+, MySQL 8; SQLite is **beta**. Model and tuple provisioning from authoritative Git/worksets need an additional adapter and migrations. |
| **SpiceDB** | [Go manifest](https://github.com/authzed/spicedb/blob/main/go.mod) blob `55f2bd2b2dc99ae8794db658de6c8df24f8fa2e5`; datastore implementations in `internal/datastore` | Current upstream source Go 1.26.10, 114 first-group direct Go modules: gRPC, CEL, OTel, DB drivers. | In-memory engine is **development only**. Production requires persistent datastore and migrations, e.g. PostgreSQL, MySQL, CockroachDB or Spanner, plus schema/relationship sync, consistency and secret management. |
| **Casbin v3** | [Apache Casbin Go manifest](https://github.com/apache/casbin/blob/master/go.mod), blob `b3ef4db15d8483a48bed566695919399d8b045f8`; resolved in-run `github.com/casbin/casbin/v3 v3.11.0` | **Three direct Go modules:** `doublestar/v4`, `casbin/govaluate`, `google/uuid`. It is an **in-process library** (not a shipped authorization HTTP service). The benchmark builds our tiny Go HTTP wrapper in a scratch image on each native runner. | No separate DB needed for embedded static policy. Must implement or select trusted Git-policy acquisition, update watching, source signature/provenance, persistence/revocation, authenticated principal mapping and any HTTP service ourselves. Casbin does not authenticate users. |

Manifest counts reflect **current upstream source manifests** inspected during this session, not exact runtime dependency counts or an SBOM of the image tags. The upstream main branch is not necessarily the source revision behind an image. Actual image digests and effective Casbin Go modules are preserved per-architecture in the workflow artifacts. Several images used floating `latest` for RDTE; promoting them requires version/digest locks and provenance.

## What the results do and do not tell us

1. **Go/no extra DB baseline:** OPA's native bundle loader and embedded Casbin both plausibly satisfy exact low-cardinality policy checks. OPA has much more of the necessary *policy distribution/verification/refresh* code already, while Casbin minimizes runtime dependencies but leaves more glue work.
2. **OPAL:** adding a Git-distribution service is operationally feasible on both CPUs, but the tested three-service stack is 15x OPA's sampled container RAM and >17x its image size. Its special benefit must be measured by commit-to-effective-policy latency, not the inline OPA PDP's performance.
3. **OpenFGA and SpiceDB:** relationship models and native stores work, but production means durable datastore, migration/backup, tuple sync and consistency design. Their synthetic in-memory HTTP rates are not evidence this cost is justified for Agent Dispatch exact workset grants.
4. **No statistically defensible throughput winner yet:** one pass per native runner, a small shallow policy, new HTTP connections, no saturation curve, no tail under load/GC, no real Git update path.

## Remaining mandatory qualification for actual deployment

- OPA signed-bundle publication, mandatory verification (signing block), hot update/revoke, persistence and restart, rollback/expiry, no-public-listener and private bundle source credentials.
- OPAL Git webhook/poll → client update latency and loss/reconnect/stale policy behavior; single-server alternatives to PostgreSQL; exact image digest source custody.
- OpenFGA/SpiceDB durable database Quadlets with backup/restart/consistency under resource limits if retaining them on shortlist.
- Casbin source-verified watch/load, concurrency, revocation, signature and per-request grant checks; an in-process Go option rather than the synthetic HTTP server.
- Architecture-specific signed image digests, systemd credential transfer, **rootless/non-root** Podman, target-host SELinux/cgroups and recovery; only then separate protected-host admission approvals.

**Provisional assessment:** OPA with native signed bundles is the first production-shaped candidate worth qualifying. Benchmark Casbin in-process as the lightweight fallback. Add OPAL only if measured distribution latency requires it. No automatic merge, protected-host effects or credential/grant changes are authorized by this public work.
