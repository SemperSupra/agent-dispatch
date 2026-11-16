# R63 synthetic HTTP effect-commit boundary

Test-only Go stdlib `httptest` service: no GitHub Actions, OCI, TrueNAS or consequential executor is contacted. Uses two actual localhost HTTP clients and a mutex-protected **synthetic** receiver to distinguish **preflight-only** admission (EXPECTED RED after owner transfer) from an **at-commit** receiver rejection, budget=1 2-client collision, scope/epoch substitution, dropped HTTP acknowledgment with UNKNOWN reservation and idempotent replay.

Run `go vet ./...` and `go test -race -count=10 -v ./...` from this folder. The only genuine transport is local HTTP; the sink and budget authority are synthetic. This does **not** establish that GitHub Actions or another external provider accepts fencing epochs or idempotency keys. The present production boundary remains HOLD until a real trusted receiver/exclusive gateway and independent durable receipts are admitted and qualified. Separate public draft PR; no private source or credential.
