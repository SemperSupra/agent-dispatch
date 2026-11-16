# etcd v3.6 native three-member quorum qualification (R61)

Public-safe **provider-native** experiment, not Agent Dispatch production coordination. This workcell runs three real etcd processes on a *single disposable GitHub Actions Ubuntu runner* with independent local data dirs and loopback-only peer/client ports. No credentials, secrets, external listener, new account, production service, or real dispatch.

Run from the repository root on a disposable Linux x86_64 runner:
```sh
bash experiments/fencing/etcd-r61/run.sh
```

The script downloads the official **etcd v3.6.16 Linux amd64** release archive and verifies GitHub's published asset SHA256 before extraction into `RUNNER_TEMP`. It starts three peers, exercises concurrent **real etcd v3 transaction compare/put** via different loopback endpoints, verifies 2/3 quorum operations, then intentionally removes quorum and preserves a timed-out write as **UNKNOWN**. Following peer restart it reads back the old budget claim and the UNKNOWN transaction's result without retrying. All processes and temporary files are torn down.

**Acceptance limitations:** this is a real Raft server and networked-client test but all members share one host, network stack, physical disk/failure domain, and no TLS/client auth. It does not demonstrate *cross-host HA*, independent writer principals, protected snapshot/restore, downstream effect-sink fencing, irreversible external idempotency or native Cloudflare/GitHub CAS. Exact RUN receipt from GitHub Actions must be independently inspected. Never apply these test ports/configuration to production.

Official release source: https://github.com/etcd-io/etcd/releases/tag/v3.6.16

## R62 additional native transaction oracle

`gateway_txn_test.py` extends the same real three-peer etcd cluster with 40 independent budget=1 contention races. Each transaction atomically compares the current synthetic epoch and unspent budget, then marks a unique effect key `UNKNOWN` while decrementing the budget. It independently tests duplicate lost-ACK retry, old-owner replay, new-owner overclaim and UNKNOWN survival through epoch transfer. A privileged epoch reset deliberately reproduces an **EXPECTED RED ABA**. This tests native etcd atomic reservation, **not** an irreversible GitHub Actions or other provider effect. With no client auth, direct writes can spoof/reset the epoch: production authority remains HOLD.
