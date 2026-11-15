# Public-synthetic multilingual mail benchmark (candidate v1)

This is a **public/fictional and credential-free** CPU-only research workcell. It does not open PSTs, read mailbox accounts, make LLM calls, fetch network data, train a model, deduplicate evidence, or generate natural-language answers. It qualifies only the initial lexical/SQLite FTS5 retrieval slice and its execution/receipt boundary.

## Implementation, build and run

- Requires Python 3.10+ with the standard-library `sqlite3` module compiled with FTS5; no `pip`, lockfile, database server, binary downloads or network.
- Local: `python3 -m unittest discover -s tests -p test_mail_synthetic_baseline.py -v`
- Local receipt: `python3 scripts/mail_synthetic_baseline.py --receipt /tmp/public-mail-synthetic-receipt.json`
- Public GHA typed request (once integrated/admitted): `requests/gha/mail-synthetic-baseline-v1.json` uses the existing reviewed `gha-workload-request/v1` contract, `ubuntu-24.04`, 180-second upper bound, one attempt, and `max_cost_usd: 0`.
- `scripts/gha_workload_request.py` invokes the unit suite before returning `oracle_verified=true`; the outer typed verifier checks runner/run identity, request hash, artifact digest and truthful scope booleans. **Opening a source PR triggers source-contract CI, not an independently admitted Agent Dispatch workset dispatch.**

## Source and oracle rules

The generator is deterministic and seedable. Source occurrences have separate archive digest/locator/occurrence identity, even when one attached blob digest is identical. One selected message has malicious instruction text; it is never executed. The same Internet Message-ID intentionally belongs to two unrelated synthetic topics. Separate rows demonstrate a changed attachment/document, a partial second export, and a cross-tenant decoy. Queries are labeled as development or held-out by thread family, not randomly by occurrence.

Independent Python tests check occurrence retention, same-blob/different-attachment occurrences, version conflicts, Message-ID collisions, absent-vs-deleted, access control, English/German/Thai retrieval and unsupported-answer scope. SQLite unicode61+synthetic trigrams are **not** qualified Thai linguistic segmentation. Query recall@3 is measured only for 9 easy deterministic exact-topic lookups. **Do not generalize this result to actual reasoning, learned improvements, hallucination rates, native PST conformance or production privacy controls.**

## Operations and maintenance

Workcell operates entirely in memory; no persistent service or runtime secrets. `--receipt` is an optional disposable, source-only result. Preserve Git commit + exact request SHA + public run ID + externally computed artifact SHA and independent typed verifier. Re-run from fresh disposable runner to test reproducibility; use baseline zero-dependency before heavier RAG/agent arms. Retain only minimal public synthetic artifacts under existing action retention limits. Fail closed when FTS5 is unavailable or the fixed task oracle fails; do not silently substitute another retrieval implementation or suppress negatives.

For a future Go service, treat this as a **benchmark oracle, not a mandated Python runtime**: reuse its JSON fixture/receipt semantics and replace the storage/retrieval adapter after independent byte/provenance comparison. Separate native PST and private-source tests must run in permitted owner-controlled environments.

## Hard stops

No private data or repository files, credentials, external model calls, arbitrary workflow commands, real mail sends/deletes, runtime egress, bulk artifacts, paid CI or automatic promotion. An authorized application must separately qualify real mail ingestion, source ACL propagation, full-text result citations, ranking, native data completeness, and actual self-improvement against held-out tasks.
