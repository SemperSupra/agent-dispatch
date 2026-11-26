# Public synthetic annotation acquisition benchmark

42 distinct fictional sources/families (6 development, 36 held-out, 12 held-out
per EN/DE/TH), explicit source/oracle files, 12 scenario categories. The
candidate is asked to annotate a given binary proposition, not answer a
question or manufacture a reviewer signature. Return a normalized Submission
per context (ID, source ID, body SHA256, claims list): exact original UTF-8
byte ranges/quote, polarity ±1, actual/planned modality, canonical UTC
RFC3339 seconds valid_from and optional exclusive valid_to. Empty list means
abstain; never use acquisition time as unstated effective time. Quotes and
instructions are data. The fixed oracle separately specifies exact claim
spans/semantics. False assertion, missing/extra claims, invalid anchors,
wrong meaning/modality and wrong valid time are separated from exact score.
Counts of missing/extra claims are cardinality deficits/excesses; wrong span
and meaning/time are separate nonexclusive diagnostics. The contexts command
does not export category, split, family or gold labels.

Commands in the existing Go module:
- go run ./cmd/mail-annotation-benchmark contexts
- go run ./cmd/mail-annotation-benchmark reference
- go run ./cmd/mail-annotation-benchmark score < normalized-submissions.json

The structured-record recognizer is intentionally narrow, using only exact
timestamp | target | yes/no-like record lines, no gold or general NLP.
An oracle replay is a scoring positive control, not an inference competitor.
Normalized JSON submissions must come from a strict upstream response parser;
this is not a raw completion parser or model execution receipt. Public
source and gold were separately specified by the same fixture author; NOT
external blind annotation or genuine independent human reviewer evidence.
Freeze candidate policy before inference, keep raw journals separate, use
installed bounded model actors, compare annotation score before signing or
reasoning. Do not treat a valid signature or exact quote as semantic truth.
No private data, actual model run, production review authority or promotion.
