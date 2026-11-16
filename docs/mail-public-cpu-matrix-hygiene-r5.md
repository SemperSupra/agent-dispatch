# Public typed CPU routine matrix and on-demand prior-art probes (R5)

This change reduces unnecessary public hosted runner consumption and external source/dependency fetching on routine unrelated pull requests. It changes only the already existing public `gha-typed-public-cpu.yml` PR matrix and contract tests; the fixed typed request allowlist, immutable provenance, verification, upstream source pins, rights and earlier native receipts are not removed.

## Routine PR default (four fixed CPU jobs)

- x64 arithmetic identity/checksum proof;
- ARM64 arithmetic/shape proof;
- public fictional multilingual SQLite FTS5 baseline;
- public fictional Go evidence/temporal/attachment qualification (including source graph mutation and restart tests).

The existing contract job and reviewed mock/Azurite jobs continue unchanged. Source changes to `tools/mail-evidence-challenge/**` still trigger these tests. Maximum parallel CPU proofs remains 2.

## On-demand only (fixed reviewed profiles)

These already-qualified upstream prior-art experiments are no longer repeated on **every** shared Agent Dispatch PR:
- `requests/gha/mail-openworker-policy-v1.json` — pinned original OpenWorker permission classifiers;
- `requests/gha/mail-ragmail-loss-v1.json` — negative MBOX occurrence/attachment-loss witness;
- `requests/gha/mail-openworker-headless-v1.json` — fake IMAP/headless parser and same-name attachment download negative;
- `requests/gha/mail-openworker-scripted-v1.json` — full original installed OpenWorker headless engine using its fake scripted model, approved source already tested in public GHA #43798206276.

All four still have immutable repository-controlled request manifests, distinct reviewed workload IDs, fixed runner+timeout/data class, max_attempts=1, max_cost_usd=0, and independent verifier contracts. **On-demand means existing workflow_dispatch/workflow_call after the appropriate public executor authorization**, not new cron, generic shell or unauthorized Pandora Sidecar delegation. No automatic periodic validation is claimed while those admission gates remain unresolved.

## Efficiency, risk and rollback

Old PR default: seven native CPU proof jobs. New default: four. Reduction: three short fixed upstream networked jobs per unrelated PR, plus the separately qualified full-installed upstream package is intentionally not placed into the routine matrix. No source or evidence lost; prior provider-attested first-failure and green receipts stay in GitHub source/DLE.

Tradeoff: changes in upstream dependencies or external network reachability may not be discovered until explicitly requested, so routine maintainers should trigger these profiles after a pinned-source or dependency update, as part of product release qualification, and before any promotion. Do not claim availability or safety of a third-party system from an old receipt alone. Revert only the matrix change if necessary to restore coverage, with a test and cost review. No user mail, private repository sources, paid inference or new workflow is introduced.
