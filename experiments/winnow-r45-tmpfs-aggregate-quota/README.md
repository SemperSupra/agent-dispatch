# R45 — OS-enforced aggregate stage storage quota capability

**Separate public synthetic-only test** from R35's per-file limit (`RLIMIT_FSIZE`) and R39's cooperative/private-Go stage monitor. This qualifies only whether disposable Ubuntu public GitHub-hosted AMD64/ARM64 runners can enforce a *whole-stage capacity* using a new mount namespace + 256 KiB `tmpfs`, while a fake unprivileged writer is under a separate route-less network namespace.

## False-green-resistant method

- On a disposable GHA runner, use `sudo -n unshare --mount --net --propagation private`; create a 256 KiB `tmpfs` with `nosuid,nodev,noexec` **inside the mount namespace only**, then drop effective UID/GID to 65534 using `setpriv`, zero effective Linux capabilities.
- The child verifies independent mount and net namespace IDs, actual `tmpfs` mountpoint, 262144-byte filesystem capacity, uid/gid/caps and a positive kernel TCP denial to RFC documentation-only 192.0.2.1.
- Attempt two synthetic **160 KiB** files. First must succeed; second must be stopped by kernel `ENOSPC` before reaching 160 KiB. Confirm the sum of actual file bytes never exceeds 256 KiB, then unlink both and assert the stage is empty.
- If `unshare/mount/tmpfs` are unavailable or any assertion fails, job must fail. No fallback to Python filesystem-size estimates, an ordinary directory, or simulated `ENOSPC`.
- The public runner tears down this private mount namespace at process exit. No persistent mount, host setting, credential or user-media change.

**Passing R45 proves only OS aggregate quota *availability on this GHA runner image*.** It is **not integrated into Winnow's Go `Backend`/gallery-dl subprocess, cannot be assumed available on BigMac macOS or TrueNAS, and does not prove cgroup RSS/CPU/OOM, process-tree cleanup, actual source rights, native selected child identity, live Instagram or release.** A real production sandbox requires separately admitted target-platform implementation and failure/cleanup integration.

This is independent of Winnow's R46 actors (they alone own private `core.go/job.go/recovery.go`); all content is new synthetic-public code in the public test site. Release and live source remain HOLD.
