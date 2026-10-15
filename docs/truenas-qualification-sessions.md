# TrueNAS exact-version qualification sessions

Authority: `SemperSupra/agent-dispatch-private#480`.

This layer amortizes a single expensive disposable TrueNAS installation across multiple
independently authoritative test capsules. It does **not** turn a session into a product
verdict and does not move product authority into Agent Dispatch.

## Contracts

- `truenas-session/v1` binds one exact TrueNAS target, one immutable manifest digest,
  one disposable pool topology, one session authority, and one bounded resource budget.
- `truenas-capsule/v1` binds one independently owned test capsule to an exact provider,
  producer/artifact identities, namespace/ports, resource ceiling, oracle, cleanup
  policy, receipt contract, and retry policy.
- `config/truenas-capsule-providers.json` is only an execution adapter registry. It
  points at existing probes; it is not a product inventory or support matrix.

Foundry and product repositories remain authoritative for what should be tested and for
the meaning of product receipts.

## Isolation membrane

Every mutating capsule must eventually execute under this membrane:

```
observe owned namespace
  -> prove clean precondition
  -> setup/apply
  -> independent verify
  -> cleanup
  -> prove zero unintended residue
  -> re-observe platform health
```

A product/oracle failure may be followed by another independent capsule only if cleanup
and platform-health reconciliation both succeed. Cleanup ambiguity must stop subsequent
mutation and classify the session as contaminated.

## Immutable launch

The session manifest contains `manifest_sha256`, computed over canonical JSON with the
hash field excluded. A runtime request must bind that digest before the heavyweight job
starts. Editing both payload and digest creates a different proposed session; it cannot
change the semantic identity of an already-launched session.

The validator also fails closed on:

- unknown exact TrueNAS versions;
- unknown capsule providers;
- duplicate capsule ids, namespaces, or ports;
- dependency cycles or missing dependencies;
- mutating capsules without mandatory cleanup;
- resource/time budget overflow;
- the current 8-GiB guest and 50-minute heavyweight guardrails.

## Migration sequence

1. Prove this static contract.
2. Wrap current T6 probes without rewriting them.
3. Prove one-capsule receipt equivalence with the existing one-product execution path.
4. Add the session runner and cleanup/platform-health membrane.
5. Prove an intentionally failing multi-capsule BETA.3 session.
6. Only then migrate ordinary product requests to immutable session manifests.
7. Retain one-capsule manifests for high-risk/new experiments.

The active FolioRelay BETA.3 run that predates this contract is intentionally not
reinterpreted as a session.
