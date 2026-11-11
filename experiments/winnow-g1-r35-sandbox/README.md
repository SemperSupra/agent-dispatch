# R35: Public synthetic extractor under real OS containment

**Purpose:** Bounded extension of R34 (the disposable public-runner network namespace primitive) to an actual *fake extractor subprocess*. The executable and all fixtures are newly written, public-safe, deterministic Python stdlib code. **No gallery-dl/parth-dl execution, Instagram request, private Winnow source, login, cookie, user media or credential is involved.**

## Two native Ubuntu architectures, seven cases

Run as uid/gid 65534, effective capabilities zero, in a separate route-less Linux netns created with `sudo -n unshare --net` on disposable GHA runners. A Python stdlib parent starts each fake subprocess in a **new process group** with `resource.setrlimit` and `subprocess.Popen`. Each case runs in its own empty stage directory; all stages must be removed on completion or rejection.

| Case | Expected verified outcome |
|---|---|
| normal | One tiny synthetic file and explicit success marker, cleaned |
| net | Kernel denies TCP to `192.0.2.1` inside netns; no file |
| stdout | Parent streaming stdout+stderr cap 8 KiB, group killed on exceed; no file |
| disk | Per-file kernel `RLIMIT_FSIZE` 64 KiB denies 1 MiB write; no oversized file persists |
| memory | `RLIMIT_AS` 192 MiB prevents 512 MiB allocation |
| cpu | `RLIMIT_CPU` soft 2/hard 3 seconds terminates synthetic busy loop |
| descendant | Parent expires wall deadline, kills new process group and checks spawned child is not running |

Additional limits: `RLIMIT_NOFILE=32`, per-case wall deadline 4 seconds (1.25 seconds for descendant), output collected with bounded streaming, no shell command construction for the child. Actual kernel errno must demonstrate the network refusal. R34's initial checkout-permission failure taught us to stage only the public scripts in a random readable directory, with an isolated empty writable scratch root for uid 65534. Scratch is deleted by the host cleanup trap after the test.

## Evidence / limitations

This demonstrates possible **OS-level containment of a controlled fake extractor** on the ephemeral GitHub-hosted runner images, not equivalence to the actual third-party extractor. RLIMIT_FSIZE limits an individual file, **not total disk usage across many files**, and RLIMIT_AS virtual address space is not a cgroup RSS cap. A kernel netns with no default route is not a complete solution to all possible local IPC/capability/network egress paths. Process-group kill is not equivalent to a full cgroup kill of processes that escape the group. Real gallery-dl/parth-dl dependency profile, signed CDN redirects, native carousel child identity, actual source rights and production BigMac/TrueNAS/container behavior remain **NOT RUN**.

There is no hidden pass-through on infrastructure failure: if `sudo -n unshare --net` is unavailable, or any canary/status check fails, the workflow must fail with observed first failure and must not claim R35 PASS.

This public workcell is independent of the user's ongoing local actor on `rdte/winnow-extractor-public-safe-20261111`, R32 PR #580, R34 PR #582 and all private Winnow code. It is stacked for review only, **not merged**. Do not use Agent Dispatch orchestration to execute it. Keep the source and Winnow MVP release gates on HOLD.
