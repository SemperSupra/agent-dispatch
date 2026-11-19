# USB Fabric R21 parallel workcell contract

This is a **dispatch and reconciliation contract**, not a PASS receipt for R21-A/B/C. The private DLE issues #467, #468 and #469 own semantics and acceptance. The repo manifest is a compact mechanical projection, not a second source of truth.

## Algorithm for every local/web iteration

1. Snapshot the DLE, relevant base SHA/PR head, available runner slots and resources; do not invent state.
2. Build a dependency graph from prerequisite evidence. **Ready** means sources/base available, write scope independent, and resource slot available. Dependencies do not block unrelated work.
3. Take at most four READY tasks by priority, using two P0 execution lanes plus one nonblocking lane when possible. **Minimum three independent active or completed workcells per iteration**; when fewer exist, explicitly record why and refill from backlog.
4. Dispatch selected tasks simultaneously. Never await A before starting independent B/C. Actors own disjoint file paths and branches, and must not merge or retarget another actor's branch.
5. Each actor runs one bounded experiment and emits exact branch, commit SHA, CI run/job, test oracles and artifacts, failure history, limitation, next step, rollback. **No evidence = NOT QUALIFIED.**
6. Reconcile all children and parent issues after results. Count *independent useful receipts* per iteration, not the number of chat messages. No second iteration while prior results are unrecorded unless execution is ongoing and recoverably recorded.

## Weak-model actor baton (copy verbatim)

> Work on exactly ONE assigned workcell with its assigned branch and write prefixes. Read the DLE issue and base SHA before edits. Do not alter sibling files. Perform one executable, falsifiable experiment; run public/free CI when available. Emit (1) changed files + SHA, (2) exact run/job IDs, (3) PASS/RED/NOT_TESTED assertions, (4) original failing evidence, (5) remaining security limits, (6) rollback. Do not mark qualified from code-only or narrative. Never merge, use private paid minutes, production resources or credentials. Stop and report BLOCKED with an exact refusal if preconditions fail.

## Supervisor exit rule

A repetition is not complete until it reports **all** admitted workcells in one ledger: READY/RUNNING/BLOCKED/RED/QUALIFIED_TEST_ONLY with per-cell receipts. If only one task ran, include a concrete explanation (dependency conflict, unavailable runners, permissions, exhausted capacity), and use the next iteration to remove that bottleneck. R21 optional Pi USB/IP must not block the native Go/QMP MVP.
