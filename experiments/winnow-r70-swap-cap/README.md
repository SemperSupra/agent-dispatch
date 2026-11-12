# R70 — Linux cgroup memory-plus-swap denied synthetic differential

R68 used a 64MiB `memory.max` with **anonymous mmap** (192MiB touched). Native arm64 reported OOM SIGKILL + kernel event in three repetitions; native amd64 touched the mapping and exited 17 without an OOM event, with cgroup `memory.peak` exactly 64MiB. One plausible hypothesis is that the x86_64 public runner can charge overflow into swap rather than to `memory.current`, but **that is not proven by R68**.

This separate, *public only* controlled differential repeats R68 on fresh disposable GitHub Actions native AMD64/ARM64 nodes and additionally sets **`memory.swap.max=0` on each new disposable CHILD cgroup only**, verifies readback, and records `memory.swap.peak`. It **does not** change host/parent quotas, swap devices, global sysctls, persistent machine state or private source.

Three 16MiB positive mmap controls per arch must exit normally; three 192MiB under 64MiB memory plus zero swap limit must die via SIGKILL with an actual `memory.events oom_kill` increment; any shortfall fails CI. Workers drop uid/gid65534, only the scoped host observer remains root on a disposable public GHA runner and isolates its network namespace. Kernel cgroups and transient contents are removed after each case.

If it passes across both architectures, this would support a **narrow swap-accounting mitigation on GitHub public Linux runners only**, not a product sandbox. If it fails, preserve the error and investigate ancestor `memory` accounting with target VM diagnostics. No real downloader, source rights, private Winnow code, media, credentials or release.
