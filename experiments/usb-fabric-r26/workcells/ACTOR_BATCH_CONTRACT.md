# USB Fabric actor execution contract — four-cell batch
Authority: private DLE #369 / #443 / #447. This instruction is for weaker and stronger actors alike; use precise checks rather than interpreting narrative.

1. **Observe** current exact Git SHA, available runner slots and DLE issue owner. Never infer from old chat.
2. **Select up to four workcells** with different write paths and no unmet dependencies. Prefer P0; allow unrelated P1 while P0 test runs. A dependency is a real build/test input, not merely the same project.
3. **Launch selected cells concurrently**, each on its own pinned branch with its own CI workflow. Do not await workcell A before starting independent B/C/D. Record dispatched refs/run IDs. Sequential operations *inside* a cell are allowed.
4. **Verify independently** using exact source SHA, actual workflow+job IDs and log assertions. Classify PASS / RED / NOT_TESTED; green workflow does not mean a security assertion passed.
5. **Reconcile once across the batch** to the private DLE: actor, base SHA, head SHA, source diff, trace/log anchors, acceptance, residual failures and rollback. Preserve draft proof PRs. Never force-push, merge, delete evidence or start physical HIL without owner gate.
6. **Repeat** with newly available slots. If fewer than two cells can run, record actual blocking dependency/resource reason; do not silently collapse to serial execution.

**Small-model output schema:** `cell_id | base_sha | branch | allowed_paths | dependency_ids | execution_ref | verdict | evidence_ref | blocker | rollback`.
No fabricated completion, no arbitrary reassignment, no production secrets or private billed runners. Keep DLE Durable/Legible/Executable. This manifest is an example of a qualified batch; update the next-iteration file only after observing real current heads.
