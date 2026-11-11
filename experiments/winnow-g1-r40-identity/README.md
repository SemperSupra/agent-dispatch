# R40 — native upstream carousel identity parser differential (public synthetic)

## Question

Do the **actual pinned upstream REST carousel parsers** retain native per-child IDs across three reorders and rotations of fictional signed media URLs, or only ordinal indices? This is distinct from CLI startup (R36), fake extractor containment (R35), native URL dispatch (R32) and real media/source authorization (G1).

## Source and protocol evidence

- Gallery-dl v1.32.19, [upstream `gallery_dl/extractor/instagram.py` at tag `v1.32.19`](https://github.com/mikf/gallery-dl/blob/v1.32.19/gallery_dl/extractor/instagram.py): `InstagramExtractor._parse_post_rest` takes an in-memory dict; its `_files[]` maps each `item["pk"]` to `media_id`, and enumeration to `num`. This workcell invokes that published method directly without creating sessions or calling API/network.
- Parth-dl v1.2.1, [upstream `parth_dl/extractors.py` at tag `v1.2.1`](https://github.com/parthmax2/parth-dl/blob/v1.2.1/parth_dl/extractors.py): `MediaExtractor._parse_media_item` takes the *same shape* synthetic metadata dict but emits entries containing `kind` and `formats` without the native `pk`/child ID, while format IDs are positional (`image-{idx}-{f_idx}`). That makes a stable ID contract unqualified without an added/changed adapter. The test records this as **FAIL CLOSED for native child ID**, not an unconditional defect across all alternative metadata formats.

## Method

Four native public GHA jobs: both pinned PyPI wheel hashes (gallery-dl 1.32.19, parth-dl 1.2.1) × AMD64/ARM64. Public PyPI install is a distinct network phase. After download and hash validation, run the real parser **only** as uid/gid 65534/caps 0 inside the disposable Linux route-less `unshare --net` namespace with a denied-kernel TCP canary. No live Instagram, accounts, user data, original bytes, API requests, or private Winnow code.

Three controlled permutations of the same three synthetic child `pk` values, each with a different fictional signed CDN query value. The test asserts three image entries remain, their ordinals follow extraction order, and detects whether native stable IDs survive. It deliberately **does not** validate signed URLs as usable or authorized; test data is invented.

**Evidence boundary:** A green job means the actual pinned **REST parser function** behaved as observed against synthetic dicts. It does not verify that upstream exposes REST metadata without login, that its API returns this exact schema, stable original media bytes, gallery-dl CLI `--range` binding, a selected-only media download, parth alternate GraphQL parser formats, correct Go integration, credentials, rights, DNS redirects, production host containment or release.

## Acceptance

Run passes only if pinned gallery parser exposes distinct native IDs in all three permutations, or if pinned parth parser candidly reports missing native ID and does not pretend ordinal `format_id` is stable child identity. If a source API changes, any mismatch is a **red setup/semantic drift finding**; no invented green. Exact source/job/runner version and comprehensive negative outcomes are required in DLE #1.

Owner G1 original-byte and release HOLD unchanged. This independent draft does not modify the local actor's branch or any private Winnow source, and should not be merged without new review.
