# R66 native etcd mTLS/RBAC qualification (public-safe)

Execute `bash experiments/fencing/etcd-r66-tls/run.sh` from a **disposable Linux amd64** environment with curl, OpenSSL, tar, and SHA256. It verifies the upstream pinned etcd 3.6.16 binary, starts one loopback-only real etcd server, uses an ephemeral test CA and certificate-identified clients, then checks native scoped RBAC denial, missing-client-cert refusal, revocation and unaffected principal continuity. All private keys are temporary and removed by the exit trap. Only summary classifications are emitted.

**No release claim:** single machine, single etcd peer, synthetic users, unencrypted local peer port, no external worker, protected host, independent fault domain, irreversible effect or trusted external monotonic backup. TLS and native RBAC establish authenticated admission only; they do not fence external effects or prevent privileged rollback. Do not use this script to provision a real service.
