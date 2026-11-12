# R64 — fail-closed cgroup v2 provisioning/admission on disposable public runners

Winnow R61 showed that killing a synthetic Linux PID namespace's init terminates even a detached `setsid` descendant in that namespace. It did **not** establish CPU, memory, PID or I/O quotas. R64 probes **whether a public Ubuntu runner can create a disposable child cgroup and set CPU, memory, PID limits at all**. It reads actual cgroup v2 controller availability, requires parent delegation and writable child control files, writes/readbacks small benign limits to a *new empty child* and removes it. No process is placed inside the cgroup, no shared parent cgroup is modified, and no tool is installed.

This is an admission probe, not actual quota enforcement. Its outcomes are deliberately distinct:
- `R64_CGROUP_V2_PROVISIONING_ADMITTED`: control files provisionable on that runner, **enforcement=NOT_RUN**.
- `R64_CGROUP_V2_ADMISSION_BLOCKED`: cannot safely provision in the runner. Workflow fails nonzero, retaining diagnostic stderr and a tiny public report. Do not bypass with host-wide privilege/config edits or claim cgroup capability passed.

No private Winnow source, real extractor, Instagram, media, credentials, cgroup I/O device enforcement, production security sandbox, user data or target-host parity. Public synthetic only. DLE must record first failure and choice of other **disposable** venues if blocked. Private integration and release HOLD.
