# Exact, externally pinned review inventory

An individual valid signature cannot prove the caller submitted every applicable
review. This small independent primitive binds the exact source/revision payload
digest inventory to a separately trusted manifest digest, tenant, partition,
task, predicate, group, valid time, knowledge time, policy and context digest.
Canonical order is independent of submission order. Duplicate, unknown, future,
missing, additional and substituted entries fail closed. A stale manifest cannot
be used with the current pin.

This is a pure validation primitive with no storage, network, keys, real
mail, native PST or model invocation. The caller must obtain the pin from an
independent trusted catalog, validate payload signatures and build observed
entries from actual admitted annotations, not accept untrusted self-reported
hashes. It does not prove the catalog is complete, append-only, authorized,
fresh, or independently reviewed. The self-consistent omission negative control
explicitly demonstrates why an independently trusted checkpoint matters. An
empty manifest is valid only as a pinned inventory; this does not establish
an empty mailbox or absence of a claim. Historical snapshots must come from
trusted custody; do not infer them by deleting history. The signed annotation
adapter can compose this contract without introducing another executor.
