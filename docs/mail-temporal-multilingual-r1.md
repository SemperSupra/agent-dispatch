# Temporal DOE R1-C — conservative EN/DE/TH time, aspect and calendar annotation

Product authority: [Mail Evidence overlap/time #4](https://github.com/SupraShellScripts/mail-evidence-private/issues/4); experimental owner [reasoning DOE #39](https://github.com/SupraShellScripts/mail-evidence-private/issues/39). Public synthetic fixtures only.

## Existing standards and scope

ISO-TimeML (events, temporal expressions, temporal relations), OWL-Time (intervals), Thai Buddhist Era calendar conversion and IANA tzdb are reusable standards/primitives. This experiment **does not** invent a multilingual NLP extractor or assert that a regex can interpret arbitrary emails. The caller supplies a source-anchored annotation (exact phrase, language, calendar and date) that is checked against nine small, explicitly reviewed patterns. Unrecognized aspect, missing calendar, vague intention, or absent source quote must remain UNKNOWN/unsupported, not become a physical-world event. A completed statement remains a **source assertion**, not independent objective truth.

## Qualification behaviors

- Original English, German and Thai invented claims distinguish explicitly completed versus prospective versus not-yet. Thai `แล้ว` and `จะ` are tested in exact reviewed context; their mere presence in an unrecognized sentence is not a universal grammar classifier.
- Thai Buddhist Era conversion is only performed for **explicitly labeled** calendar values (e.g., 2569 BE → 2026 CE). Neither language nor numeral magnitude alone admits a calendar inference. Gregorian leap-day validation is strict.
- Date-only values stay **dates** rather than invented UTC-midnight instants. For local wall-clock time, Go 1.23 standard `time.LoadLocation` (with compiled-in `time/tzdata`) enumerates offset-qualified instants, detecting Europe/Berlin 2026-03-29 02:30 missing DST hour and 2026-10-25 02:30 two valid UTC instants. An unqualified ambiguous local time is unresolved; only explicit corresponding UTC offset disambiguates. Asia/Bangkok controls fixed +07 without inventing DST.
- Relative `today/tomorrow/yesterday` is calculated in explicitly given source timezone and reference instant with **calendar-day arithmetic**, never a 24-hour UTC adjustment. `next Friday` is refused until a reviewed language-specific reference rule is qualified.
- Two different source occurrences that claim the same completed event date may have equal temporal **presentation**, but not equal logical identity or source evidence. Original quote anchoring remains mandatory.

## Build, O&M and safety

Go standard library only, under `tools/mail-evidence-challenge/temporal_language`; tested by existing fixed public Go CPU profile `go test -count=2 ./...`. Tests explicitly cover all nine EN/DE/TH annotated examples, unsupported or vague phrases, Thai BE vs Gregorian, invalid dates/leap years, Berlin DST spring gap and autumn fold, valid offset disambiguation, Bangkok reference zone and cross-date relative expressions. No new workflow/scheduler, model, database server, Python dependency, private corpus, action/attachment execution or external API.

This is **not** a general language model, Thai tokenizer, complete ISO-TimeML implementation, native PST Outlook timezone/recurrence engine, legal effective-date inference, or all-timezone ambiguity solver. Future adoption needs a true multilingual extraction benchmark with independent annotation on disjoint document families, plus source time zone evidence and accuracy/abstention measurements. Treat IANA tzdb version in the pinned Go toolchain as an explicit O&M dependency if promoting.
