# RAG-Mail exact-upstream MBOX loss witness (negative qualification)

**Consumer:** [Mail Evidence private #39](https://github.com/SupraShellScripts/mail-evidence-private/issues/39), scoped to public-synthetic RAG/Retrieval comparative qualification. This is an explicit **RED negative oracle**. A PASS means the upstream loader *demonstrably loses canonical source occurrences* in our adversarial fixtures; it does not mean that RAG-Mail is accepted as an evidence-complete reader or that our product has those defects.

## Provenance, build and rights
- Original MIT-licensed public RAG-Mail `ManiAm/RAG-Mail@afab46bfdd83d11af8bacee8231871ff1292fced`.
- Git blob pins: `services/email_loader_mbox.py@5a9ee91a0f1b7d04439ab8808bf7b1c88df868d6`, `LICENSE@9f2503cd9335d109ad1a2e67f264bd9aa7097021`.
- Fetches only those two original exact-SHA public files via constant URLs under `raw.githubusercontent.com`, 16 KiB bound, 12-second socket timeout, verifies Git object digests before import, inspects MIT rights. No caller-derived URL or source, no private repo, secrets, persistent mail data or model access.
- Actual upstream MBOX module runs with in-memory fake database/model classes because the full upstream deployment otherwise requires Postgres and multiple attachment tools. **Do not extrapolate to full live SQLAlchemy/Postgres behavior without a separate native integration test.**
- Source-only standard-library adversarial tests: `python3 -m unittest discover -s tests -p test_qualify_ragmail_mbox_loss.py -v`; host-side negative witness: `python3 scripts/qualify_ragmail_mbox_loss.py` (fixed public source acquisition). No pip, Docker, shell subprocess, or network other than bounded public source acquisition.
- The public typed GHA `mail-ragmail-loss-v1` fixed request has one attempt, 180s budget and `max_cost_usd=0`. Existing independent provider-linked typed receipt checks the source+run IDs, fictional data scope and that `reader_qualified=false`.

## Synthetic oracle

A legal, standard-library-created MBOX carries **three separate source message occurrences**:
1. Original message `<collision@invalid.test>` with **two different attachment payloads** sharing `report.txt` as a filename;
2. Different later message with the same Internet Message-ID;
3. A message with no Internet Message-ID.

The observed original RAG-Mail source:
- `if not message_id: continue` skips occurrence 3;
- `session.query(Email).filter_by(id=message_id).first(): continue` skips occurrence 2;
- `attachments[filename] = ...` overwrites one of two attachment occurrences in 1.

Acceptance for this **negative witness**: true upstream source module parses all 3 original MBOX occurrences, stores only 1 message and 1 attachment in a disposable fake store, and its independent verifier explicitly records **2 lost message occurrences and 1 lost attachment occurrence**, while keeping reader qualification false. If any behavior differs, the witness is FAIL/NEEDS_REEXAMINATION—not a product pass and not proof the defects were fixed.

## O&M implications
Do not use this loader's unique-`Message-ID` or filename-keyed attachment tables as canonical source truth. All occurrences, attachments and raw bytes must be retained independently of any derived logical-entity/thread/revision candidates. Negative patterns are suitable regression fixtures for the separate Mail Evidence canonical packet reader, snapshot overlap model and PSTriage parity. RAG-Mail Compose published defaults also expose a fixed Postgres username/password and host-mapped port; these require production secret injection, isolated networking, review and data ownership before any deployment. This public workcell never starts that stack.

## Limitations and follow-on
The witness is **source-pinned + fake DB**, not a full RAG-Mail database/retrieval/embedding deployment or a benchmark of question-answer quality, security policy, resource cost, restart/recovery or citations. Later only an approved $0 isolated service environment with ephemeral Postgres/Qdrant, immutable synthetic mail and pinned dependency closure should qualify those claims. The product owner and data/evidence policies remain in the private Mail Evidence project; GitHub DLE governs the next workset.
