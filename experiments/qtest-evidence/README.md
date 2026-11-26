# Read-only replay evidence projector (experimental)

This offline, standard-library Go CLI independently decodes the fixed synthetic legacy VirtIO queue replay fixture. It checks a caller-supplied expected ZIP SHA-256, bounded regular members, exact member manifest/CRC, source pin and plan digest, the complete 24 QTest command/response sequence (including setup), and the 44-byte guest witness preconditions and five observations. It emits one JSON object per raw observation with deterministic archive/member/operation occurrence identity and the related receipt's digest, not a receipt authenticity claim.

Build and invoke (Go modules disabled; no downloads):

```sh
cd experiments/qtest-evidence
GO111MODULE=off GOPROXY=off GOTOOLCHAIN=local go test -race -count=2 -v .
GO111MODULE=off GOPROXY=off GOTOOLCHAIN=local go build -o /tmp/qtest-evidence .
/tmp/qtest-evidence -archive /path/to/replay.zip -sha256 EXPECTED_ARCHIVE_SHA256
```

Exit 0 means the supported raw witness matches the fixed oracle and the input bytes are consistent with the externally supplied digest; 1 means refused. No input is executed or extracted to disk. No network, actuation, host access, timestamp-derived joins, release or live promotion. Eight QTest and eight TCG raw witnesses, five reads each, are supported; arbitrary experiments, missing evidence or changed plans are refused. The caller must independently obtain the expected digest from its trust/custody authority, establish native job status and use the existing strict replay receipt checker for lifecycle and semantic receipt acceptance. Digest consistency is not producer authentication, and archive member identity is not a new hardware or runtime identity. The output is a candidate VHE-local schema, not an accepted Observatory/CLIP contract. Guest and QTest vantages share one QEMU implementation; no cross-vantage causal join is asserted.
