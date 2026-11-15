# Public synthetic Go evidence challenge

Scope: typed deterministic evidence-contract qualification, NOT LLM question understanding, native PST parsing, or real email. All source material is invented and public-safe; Go 1.23+ standard library only, no runtime downloads.

## Corpus and independent gold

The immutable Go fixture holds 8 source occurrences, 5 attachment occurrences, overlapping archive acquisitions, a colliding Internet Message-ID across unrelated topics, two differently sized same-filename attachment bytes, a changed budget, German denial followed by Thai approval, a missing-ID observation, and a private beta account decoy. The separate manually authored testdata/gold.json holds 21 English/German/Thai question cards with typed intent, exact expected source identifiers, version/as-of behavior, negative cases and abstentions. The engine does not parse the natural-language question itself. Any derived state must retain full source occurrence identity, raw SHA-256, claim quote exact UTF-8 byte offsets and parent attachment identities.

## Reproduce and operate

Workdir: tools/mail-evidence-challenge
Commands:
    GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test -count=2 ./...
    GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly go run ./cmd/evidence

The CLI emits a JSON receipt. Test suite exercises exact source anchoring, cross-tenant denial, false-merge negatives, chronological revision, attachment multiplicity, unknown/abstain, clean restart from persisted JSON and corruption rejection. Persist writes an atomic temporary replacement and Recover verifies source and attachment byte digests. This is an ephemeral research snapshot, not actual user-data persistent storage.

Public GHA runs only the fixed mail-evidence-go-v1 typed profile on standard ubuntu-24.04 within 180 sec, 1 attempt and declared incremental cost 0. No private code, mail, credentials, model calls, new scheduler or custom workflow. Independent provider-linked receipt must show 21/21 exact typed gold, 8/8 retained occurrences, 5/5 attachments, zero violations, restart success and explicit model_inference=false, native_pst_qualified=false.

A green run certifies typed evidence plumbing only. Actual free-tier model semantics need independent natural-language-to-intent evaluation on held-out questions and a real admitted native PST reader, which are separate phase gates. Rollback: prior pinned workload; the test runner stores no service state.
