# R69 — per-process memory limit positive and aggregate-escape negative

An independent Linux native experiment for the unresolved R66 cgroup-memory enforcement blocker. It uses only the Python standard library on disposable public GitHub-hosted AMD64/ARM64 runners. Three repetitions check:

1. A nonroot synthetic process with `RLIMIT_AS=112MiB` can mmap/touch 16MiB.
2. The **same per-process virtual-memory limit** denies a 256MiB allocation via `ENOMEM` or `MemoryError`.
3. Two separately limited processes each mmap/touch 72MiB concurrently, and the supervisor checks actual `VmRSS` for both. Their **aggregate resident memory exceeds 112MiB** even though both individually obey their RLIMIT_AS.

That is a qualification of a **process-local emergency bound and a negative demonstration against whole-tree quota claims**, not a cgroup substitute. It also does not cover CPU/I/O, shared mmap file accounting, BigMac/macOS/TrueNAS, noncooperative process-tree kill, actual Winnow backend integration, or safe source acquisition. Network namespace and uid65534/zero caps are verified. No private source/media/credentials or live requests. DRAFT, NO MERGE, RELEASE HOLD.
