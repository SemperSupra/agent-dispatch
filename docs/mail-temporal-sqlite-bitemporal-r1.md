# Temporal DOE R1-A — actual native SQLite bitemporal/source evidence witness

Owner: [Mail Evidence #4](https://github.com/SupraShellScripts/mail-evidence-private/issues/4); experimental orchestration [#39](https://github.com/SupraShellScripts/mail-evidence-private/issues/39). **Research adapter only**, no production source/PST, no arbitrary SQL work submission.

## Why this primitive

Prior art already supplies stable range filtering, indexes, transactions and replay. This research witness uses **real SQLite** through Python 3 stdlib `sqlite3`; this Python test is not a deployable replacement for the project's Go adapter or the restricted PSTriage PowerShell 5.1 reader. Compare later with PostgreSQL 18 and XTDB using exactly the same immutable fictional observations and independent oracle. This lane does not claim native SQL:2011 `FOR SYSTEM_TIME` support in SQLite; knowledge/validity predicates are explicit SQL.

## Storage and evidence contract

Tables `source_occurrence`, `claim_observation`, and `assessment_history` distinguish original archived occurrence, *claim made by that occurrence*, and time-indexed derived assessment. First party source has acquisition id, native locator, source authored timestamp, acquired timestamp, exact original text SHA256, tenant and a **lineage identity** identifying reacquisition of the *same originating source*. Two archive occurrences may share Message-ID, bytes, and lineage without dropping either source row. Every claim includes tenant, proposition, polarity (+ supports or - refutes), modality (actual vs planned), valid_from/valid_to (half-open interval), system observed_at, exact quoted source, original source pointer. Four-valued state is the **support pattern in available sources**: NEITHER/SUPPORTED/REFUTED/BOTH; it is **not** objective truth.

A query explicitly accepts **two independent timestamps**, `valid_at` and `known_at`, and a tenant scope. It filters temporal availability, claim modality and source tenant *before* constructing supporting/refuting source sets. A late retrospective claim may change today's interpretation of May 3 without rewriting an earlier knowledge-as-of assessment. Conflicting claims are not silently resolved; planned future statements are never treated as accomplished facts. Repeated acquisition of the same lineage contributes two original source citations but only one independent logical support lineage.

SQLite source/claim/assessment UPDATE and DELETE triggers prevent destructive mutation; replay of an existing source ID is accepted **only if all source columns match**. New conflicting duplicate source IDs and cross-tenant claim linkage fail. An actual disk-backed SQLite file is closed and reopened with the history still intact. The query's native SQL plan must use `claim_lookup` index rather than a manually simulated scan.

## How to reproduce

From `tools/mail-evidence-challenge`, run `python3 -B temporal_sqlite/qualify.py` (outputs one bounded fictional JSON receipt) or the full existing `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test -count=2 ./...`. Go tests call the real SQLite native binding using a stripped subprocess environment, assert 8 independent temporal scenarios, evidence preservation, planned-vs-actual separation, tenant denial, lineage-deduplicated support voting, immutable SQL triggers and disk restart. The reviewed existing fixed `mail-evidence-go-v1` public CPU profile automatically exercises this through the standard existing public typed workflow. No new workflow, scheduler, dependency download, model, container or external database credentials.

## Red/blue and explicit limitations

- RED: future-acquired source used to answer an earlier knowledge query; BLUE: known_at and valid_at predicates tested independently.
- RED: copied export gives extra independent vote; BLUE: retained source rows but lineage counts deduplicated.
- RED: new mail silently deletes an old belief; BLUE: assessment history is append-only.
- RED: planned future approval mistaken for accomplished event; BLUE: fixed modality filter and unknown result.
- RED: altered replay source, SQL mutation or cross-tenant claim accepted; BLUE: exact comparison, triggers and query ACL.

**Not proved:** historical interval uncertainty, legal authority, semantic truth, matching logical entities across real PST exports, cryptographic provenance signature, full source packet, Windows PS5.1 runtime, PostgreSQL/XTDB O&M, or natural-language understanding. SQL text is fixed reviewed research code, not user-driven SQL. Only test input is fictional reserved-domain source. Errors fail native test and block merger.
