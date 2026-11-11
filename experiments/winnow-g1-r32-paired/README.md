# Winnow G1 R32 — independent paired native URL-dispatch counterexamples

**Scope:** public-source-only offline bakeoff evidence. Does not include private Winnow code, user requests, credentials, Instagram media or live network to Instagram. This workcell is independent of the local actor's `rdte/winnow-extractor-public-safe-20261111` branch and must not be merged into that branch without a fresh review.

**Why:** previous synthetic G1 PR #578 uses two native gallery-dl URL-dispatch checks versus eleven parth-dl validation checks. Comparing counts as if they were a paired security bakeoff is an invalid inference. This new batch applies the exact same 14 synthetic permalink cases to both native libraries and records the observed differences without pretending their differing native APIs or the actual Winnow Go wrapper are equivalent.

- Tested versions: gallery-dl 1.32.19 (PyPI wheel SHA256 `f6b1eb5e9a7409a988b754335d99dbb1873e130d133ed5d164d32e5e645d1c50`), parth-dl 1.2.1 (`3117e4c7bd6fe7c6f1b668d05c40c303e54fc3992019bf6a40ab13b98434ebff`). Additional requests dependency v2.32.5; downloaded wheel closure hashes and installed freeze captured, not a production lock.
- **Reference policy** is the self-contained strict Python `reference_policy()` oracle for *comparison only*. It does **not** represent actual Go-origin admission. Native gallery result comes from `gallery_dl.extractor.find()` and Instagram module match; native parth result comes from `parth_dl.utils.validate_url()`. A tool's permissive dispatcher does **not** imply the Go wrapper permits the URL.
- Fourteen cases: canonical post (two syntaxes), HTTP, userinfo, nondefault/default explicit ports, lookalike, loopback IP, file URL, profile path, extra path, query, fragment, and encoded path.
- `paired.py` instruments Python's `socket.create_connection`, `socket.socket.connect`/`connect_ex`, and `socket.getaddrinfo`. A positive canary confirms the interception rejects a network attempt before classification begins. **This is Python-call interception, not an OS/kernel egress barrier**, subprocess sandbox, proof of zero native-network attempts, source-login test, or rights grant. PyPI wheel download is a separately permitted network phase.
- Real artifact output: `result.json` contains per-case observed native decisions, reference-policy comparisons, actual monitored attempt count, canary result, explicit unsupported qualification booleans, architecture, dependency hashes.
- Passing the workflow means the paired harness ran; native-policy mismatches are captured as red findings. Green workflow never means either vendor security qualified, correct carousel selection, or Instagram acquisition permitted.

Reproduce from the branch in an ephemeral public-only Linux environment:

```bash
bash experiments/winnow-g1-r32-paired/run.sh
```

The private DLE #1 controls downstream decisions. Do **not** copy any private Go implementation into this public repository or convert these observed dispatch results into claims about anonymous access. The local actor is independently working in another checkout; preserve its branch.

**Next true source-of-truth gates:** compare the same cases against actual private Go wrapper in private CI; add OS-enforced network/CPU/RSS/filesystem confinement, native selected-child binding; owner-authorized, permitted single and carousel source proof. No public Instagram request in this workcell.
