# R62 native etcd network-isolation test on a disposable public runner

Independent of PR #689's process-kill tests. Builds a **local Docker image FROM scratch** containing only the official SHA256-verified etcd v3.6.16 binaries. Launches 3 **distinct container network namespaces** in an internal Docker bridge, with no published ports; read-only host clients use the private internal bridge addresses. Detaches peers from the bridge to induce a live **network partition without stopping their processes**; reconnects them without clearing their tmpfs data, reconciles UNKNOWN timed-out requests, and verifies previous committed state.

Entry point: `bash experiments/fencing/net-r62/run.sh` on a disposable Ubuntu GitHub-hosted runner with Docker Engine. Each run creates an isolated internal network, disposable image, nonroot read-only-rootfs containers and tmpfs data stores. Cleanup is trap-protected. Public/secretless with pinned upstream asset hash, no production registry, no host deployment.

**Do not overstate this test:** all three containers share one physical free runner, one Docker daemon and disk/power failure domain. Network separation and partition logic is real, but independent machine or cloud-zone HA, TLS/authenticated principals, protected restore, external budget authority, genuine GitHub Actions effect sink fencing and OCI-primary activation remain NOT TESTED.
