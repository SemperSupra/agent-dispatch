# Raw completion normalization and scoring boundary

The producer receives only the frozen context and the fixed response schema:
{"claims":[{"quote":"exact source text","polarity":1,"modality":"actual","valid_from":"2026-09-01T08:00:00Z","valid_to":""}]}.
An explicit empty array is abstention; missing or invalid output is not. Use
explicit RFC3339 seconds with timezone, exact unique source quotes, polarity
+1/-1 and actual/planned. No inferred effective time, fuzzy anchor, partial
claim repair, extra keys, duplicate JSON keys, or embedded completion fragments.
A replacement character is conservatively unsupported. The harness derives
byte offsets, source IDs and body digests; it does not repair interpretations.

The new command score-raw accepts an array of exactly 42 harness-bound rows
(id, source_id, body_sha256, status, completion). Status is completed, timeout,
transport_error or truncated. The completion is the raw response string.
Malformed completed responses and unsuccessful executions become invalid
submissions, never successful abstentions. Misbound, missing or duplicated
rows reject the entire arm. The normalized report binds the raw journal and
completion digests; retain actual raw journal locally. Public synthetic
benchmark only. This does not authenticate model execution, supply a reviewer,
or qualify natural-language claims. The model never receives the oracle.
