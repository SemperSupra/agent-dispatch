# Exact OpenWorker headless parser and fake IMAP qualification

Authority: Mail Evidence bakeoff issue #39, with Agent Dispatch owning the reviewed public typed CPU executor.

This workcell downloads only three publicly available source files from MIT OpenWorker at exact commit ecb445490fc054d52b8ea610d97ba947f57033d2 and checks each Git blob SHA-1 before import: headless runner.py, email_tools.py and LICENSE. No dynamic source URL is accepted. A 90 KiB bound per file, 12-second network request, exact redirect check and disposable test directory limit acquisition. Python standard library only: aisuite metadata, secrets, roots and tool-registry boundaries are explicitly stubbed; their real implementations are NOT exercised or qualified.

What the test actually executes: original headless parse_args in isolated/no-web mode (no run engine); original make_email_tools with in-process fabricated IMAP responses containing two UIDs sharing an Internet Message-ID and two attachments sharing a filename; read-only SELECT and BODY.PEEK fetches; read-tool vs write/download approval metadata; disconnected send denial; UTF-8 IMAP search criteria; invalid date rejection; no writable destination refusal. A fake SMTP factory raises immediately on any attempted SMTP use. No real accounts, passwords, model calls, email transmission, credential storage or paid API.

Source-only tests: python3 -m unittest discover -s tests -p test_qualify_openworker_headless_mail.py
Pinned-source synthetic execution: python3 scripts/qualify_openworker_headless_mail.py

The reviewed mail-openworker-headless-v1 profile executes this workcell on Ubuntu standard free public CI, maximum 180 seconds and one attempt with declared cost 0. Independent typed receipt binds source SHA, native run identity, reviewer-approved fixed profile, immutable upstream Git object hashes, 11 named behavior controls and explicit real_mail=false, headless_engine_run=false, model_inference=false.

Limitations: not a complete OpenWorker pip install, agent conversation, credential store, SMTP operation, interactive approval enforcement or verified model trajectory. The approval flags are metadata only; host action broker must independently enforce them. Duplicate attachment filenames appear in read results, but the name-addressed download API cannot unambiguously choose one of two identically named attachments. Preserve exact attachment source/position identity in the Mail Evidence canonical ingest rather than adopting filename-only addressing.

Operations: disposable temp files and no persistent service; on network/source hash mismatch fail closed. Native receipt and historical upstream pins form the O&M record. Rollback by not admitting the typed candidate profile; never elevate this test to real account or model access without separate admission.

## Native negative-addressability extension

The same original MIT connector is additionally exercised with a writable fictional scratch root, never a real mail account. Two requests to download same-filename report.txt return the first payload twice to distinct scratch paths; the second, different attachment byte payload cannot be selected by the connector's filename-only API. The independent typed oracle must report same_name_second_unaddressable=true and attachment_download_occurrence_complete=false, even though the read lists both attachments. This is a reproducible upstream limitation and canonical-preservation veto, not successful attachment CRUD. No host approval is bypassed in a live service: these in-process calls are confined to the fake connector and disposable local files.
