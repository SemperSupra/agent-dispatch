# Temporal R2 — Actual SWI-Prolog source-backed belief/contradiction qualification

Authority: Mail Evidence private #4 (overlapping source occurrences and clocks), #39 (reasoning DOE). This is a **native external prior-art engine**, not a custom Go simulation. The original SWI-Prolog interpreter is installed from Ubuntu 24.04's open-source `swi-prolog-nox` package in a disposable standard public GitHub Actions runner. Ubuntu noble exposes version 9.0.4+dfsg-3.1ubuntu4; record the actual executable version observed at runtime rather than assuming patch-level immutability. We do not fetch Prolog packages, external models or private mail.

## Research contract

Reviewed, non-generated `swi_temporal.pl` defines 8 fictional distinct source occurrences across alpha/beta tenants, known/acquired clocks, original evidence lineages and source quotations, with 8 actual/planned support/refute claims. Six temporal outcomes (NEITHER, REFUTED, BOTH, SUPPORTED and derived states) are tested under both **valid-at** and **knowledge-at** cutoffs. `sort` of lineage IDs avoids mistaking two exported copies for two independent corroborating witnesses while retaining both source occurrence IDs. Planned statements are not interpreted as completed, and late-arriving historical claims cannot affect knowledge cutoffs earlier than acquisition.

Derived `reimbursement_ready` and `transfer_ready` are conservative, explicitly reviewed rules based on source-quoted invoice and receipt premises. If an independently sourced contradiction arrives, the earlier derived conclusion is quarantined for *later* knowledge cutoffs without erasing the original historical belief. This native Prolog test is not a general AGM/ATMS system and does not establish objective truth.

## Native CI, provenance and O&M

The pre-existing `gha-typed-public-cpu.yml` receives a narrowly scoped `temporal-swi-prolog-native` job which is **disabled except** for PRs whose head ref begins `work/mail-temporal-prolog-`. This avoids installing extra distro packages in unrelated workflow runs. It uses a pinned checkout action, the Ubuntu 24.04 package repository, and runs the interpreter's original plunit suite **twice**. The runner emits only bounded source digest, interpreter version, 12-test count, scope booleans, and replay marker, never private content or full transcript. A separate verifier checks the allowed schema, actual source byte hash, runner source SHA, GitHub run ID and its own receipt SHA. Job permissions: contents read only; no secrets and no paid provider.

Requalification: open a new reviewed fixed-source temporal Prolog PR, preserve upstream package and source/policy digests, rerun exact native job, compare first-failure/receipt and independently check original source. This does **not** create recurring autonomous Sidecar authority or a generic code runner.

## Known limitations

- Ubuntu package sources are managed by Ubuntu, not a project hash-locked Prolog binary/OCI image; the receipt explicitly declares `version_hash_locked=false`. Supply-chain reproducibility remains a promotion gate.
- The fixture's timestamps are already fixed-width **UTC** RFC3339 strings; native comparison is lexical `@=<` only in that restricted domain, not general timezone parsing, DST intervals, imprecise time or Event Calculus.
- A fake original-lineage key is supplied, not derived from real PST/OST correspondence. Identity must be independently qualified.
- Conservative fixed rules do not do probabilistic truth, trustworthy source authority, belief logic completeness or automatic skill evolution; no real PST/appointment/attachment parity tested.
