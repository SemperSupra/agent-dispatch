# Public-synthetic retrieval-policy optimization DOE (candidate)

This is a **mechanism-only** self-improvement proof. It does not use or train an LLM, edit source code, execute untrusted email, access any real mailbox or grant permissions. It demonstrates the smallest safe `observe failures -> propose reviewed candidate -> compare on development tasks -> hold out unseen thread families -> refuse automatic promotion` loop.

## Run from reviewed source

Requires the parent public-synthetic FTS5 mail benchmark and Python 3.10+ compiled with SQLite FTS5. No package installation or network.

```sh
python3 -m unittest discover -s tests -p test_mail_policy_optimization.py -v
python3 scripts/mail_policy_optimization.py --receipt /tmp/mail-policy-search.json
```

The child branch is stacked on the source-only FTS5 benchmark branch; merge/rebase must respect that ancestry. The existing public typed-workload PR contract gate imports/runs the independent six-case test suite; there is no new workflow or paid resource.

## Experimental design and limits

Nine fictional multilingual cases, indexed across all languages, become six development queries (two topic families per language) and three held-out queries (third family only). The queries are wrapped in ordinary user-facing instructions. Candidate policies are immutable: raw query, three single-language wrapper removals, and multilingual wrapper removal. Selection uses only development accuracy and independent wrong-citation/negative controls, with deterministic tie-breakers. Held-out outcome is measured **once**, after selection. No generation code or source evidence is modified.

The additional adversarial checks include fabricated/unknown targets containing generic terms, cross-tenant decoy and known prompt-injection text as data. No policy may claim full security from six narrow negatives; no automatic promotion to any real service is allowed.

**Important:** Because both the candidate rule pool and synthetic query-wrapper families are authored together, this is an *illustration of correct DOE plumbing*, not evidence of general multilingual language understanding, self-improving agent capability, prompt evolution or actual learned semantic correctness. GEPA/Agent Lightning and a truly independent new question corpus remain separate future comparisons.

## O&M and rollback

Run in an ephemeral unprivileged process with no credentials and an in-memory SQLite index. Store only versioned source, fixed public task seed, source SHA and compact outcome receipt in the owning DLE. Restart reruns all candidates deterministically. Hard-veto unsafe/contradictory citations, false merges, cross-account leakage or test contamination. Roll back by selecting `raw` policy; nothing changes in source objects. Production activation requires separate review and held-out oracle.
