package main

// Public self-contained Go oracle verifying receiver-side monotonic fence
// invariants over an in-process httptest sink (pure stdlib, zero external
// network).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type fenceWriteRequest struct {
	IdempotencyKey string `json:"idempotency_key"`
	Epoch          uint64 `json:"epoch"`
	IntentPayload  string `json:"intent_payload"`
	IntentDigest   string `json:"intent_digest"`
}

type fenceReceipt struct {
	ReceiptID      string `json:"receipt_id"`
	IdempotencyKey string `json:"idempotency_key"`
	Epoch          uint64 `json:"epoch"`
	IntentDigest   string `json:"intent_digest"`
	ExecSeq        int    `json:"exec_seq"`
	Replayed       bool   `json:"replayed"`
}

type fenceErrorResponse struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type sinkOutcome string

const (
	outcomeCommitted sinkOutcome = "COMMITTED"
	outcomeRejected  sinkOutcome = "REJECTED"
	outcomeUnknown   sinkOutcome = "UNKNOWN"
)

func computeIntentDigest(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

type fencedReceiverSink struct {
	mu           sync.Mutex
	requiredAuth string
	requiredRole string
	maxEpoch     uint64
	execCount    int
	receipts     map[string]fenceReceipt
	dropNextACK  map[string]bool
}

func newFencedReceiverSink(requiredAuth, requiredRole string) *fencedReceiverSink {
	return &fencedReceiverSink{
		requiredAuth: requiredAuth,
		requiredRole: requiredRole,
		receipts:     make(map[string]fenceReceipt),
		dropNextACK:  make(map[string]bool),
	}
}

func (s *fencedReceiverSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/sink/apply" {
		http.NotFound(w, r)
		return
	}

	// Enforce authentication and scope at the sink boundary before touching state.
	if r.Header.Get("X-Sink-Auth") != s.requiredAuth || r.Header.Get("X-Sink-Scope") != s.requiredRole {
		writeFenceJSON(w, http.StatusForbidden, fenceErrorResponse{
			Code:   "forbidden",
			Detail: "missing or insufficient sink authorization scope",
		})
		return
	}

	var req fenceWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeFenceJSON(w, http.StatusBadRequest, fenceErrorResponse{
			Code:   "bad_request",
			Detail: "invalid json payload",
		})
		return
	}
	if req.IdempotencyKey == "" || req.Epoch == 0 {
		writeFenceJSON(w, http.StatusBadRequest, fenceErrorResponse{
			Code:   "bad_request",
			Detail: "idempotency_key and positive epoch are required",
		})
		return
	}

	expectedDigest := computeIntentDigest(req.IntentPayload)
	if req.IntentDigest != expectedDigest {
		writeFenceJSON(w, http.StatusConflict, fenceErrorResponse{
			Code:   "digest_mismatch",
			Detail: "declared intent digest does not match payload",
		})
		return
	}

	s.mu.Lock()
	// Check idempotency ledger first so same-key altered intent is always
	// rejected with 409 Conflict and identical replay returns the committed receipt.
	if existing, ok := s.receipts[req.IdempotencyKey]; ok {
		s.mu.Unlock()
		if existing.IntentDigest != req.IntentDigest {
			writeFenceJSON(w, http.StatusConflict, fenceErrorResponse{
				Code:   "idempotency_conflict",
				Detail: "same idempotency key used with altered intent digest",
			})
			return
		}
		if req.Epoch < s.currentEpoch() {
			// Even on replay, a stale epoch cannot pretend to hold current leadership
			// if the caller submits an older epoch than the sink's high-water mark,
			// unless it matches the originally committed epoch of that exact receipt.
			if req.Epoch != existing.Epoch {
				writeFenceJSON(w, http.StatusConflict, fenceErrorResponse{
					Code:   "stale_epoch",
					Detail: "epoch is older than receiver fence high-water mark",
				})
				return
			}
		}
		replayed := existing
		replayed.Replayed = true
		writeFenceJSON(w, http.StatusOK, replayed)
		return
	}

	// Enforce monotonic epoch fence at the receiver sink.
	if req.Epoch < s.maxEpoch {
		s.mu.Unlock()
		writeFenceJSON(w, http.StatusConflict, fenceErrorResponse{
			Code:   "stale_epoch",
			Detail: "epoch is strictly lower than receiver monotonic fence",
		})
		return
	}

	// Commit effect and advance monotonic fence atomically under sink lock.
	if req.Epoch > s.maxEpoch {
		s.maxEpoch = req.Epoch
	}
	s.execCount++
	rec := fenceReceipt{
		ReceiptID:      fmt.Sprintf("rcpt-%04d", s.execCount),
		IdempotencyKey: req.IdempotencyKey,
		Epoch:          req.Epoch,
		IntentDigest:   req.IntentDigest,
		ExecSeq:        s.execCount,
		Replayed:       false,
	}
	s.receipts[req.IdempotencyKey] = rec
	dropACK := s.dropNextACK[req.IdempotencyKey]
	if dropACK {
		delete(s.dropNextACK, req.IdempotencyKey)
	}
	s.mu.Unlock()

	if dropACK {
		// Simulate post-commit transport failure: effect is durable at the sink,
		// but the HTTP connection closes before any ACK reaches the caller.
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	}

	writeFenceJSON(w, http.StatusOK, rec)
}

func (s *fencedReceiverSink) currentEpoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxEpoch
}

func (s *fencedReceiverSink) totalExecutions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.execCount
}

func writeFenceJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type fenceClientResult struct {
	Outcome    sinkOutcome
	StatusCode int
	Receipt    *fenceReceipt
	ErrCode    string
	Transport  error
}

func sendFencedWrite(client *http.Client, baseURL, auth, scope string, req fenceWriteRequest) fenceClientResult {
	body, err := json.Marshal(req)
	if err != nil {
		return fenceClientResult{Outcome: outcomeUnknown, Transport: err}
	}
	httpReq, err := http.NewRequest(http.MethodPost, baseURL+"/v1/sink/apply", bytes.NewReader(body))
	if err != nil {
		return fenceClientResult{Outcome: outcomeUnknown, Transport: err}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if auth != "" {
		httpReq.Header.Set("X-Sink-Auth", auth)
	}
	if scope != "" {
		httpReq.Header.Set("X-Sink-Scope", scope)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		// Transport error after dispatch means commit state at sink is indeterminate.
		return fenceClientResult{Outcome: outcomeUnknown, Transport: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var rec fenceReceipt
		if decErr := json.NewDecoder(resp.Body).Decode(&rec); decErr != nil {
			return fenceClientResult{Outcome: outcomeUnknown, StatusCode: resp.StatusCode, Transport: decErr}
		}
		return fenceClientResult{Outcome: outcomeCommitted, StatusCode: resp.StatusCode, Receipt: &rec}
	}

	var errResp fenceErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	return fenceClientResult{
		Outcome:    outcomeRejected,
		StatusCode: resp.StatusCode,
		ErrCode:    errResp.Code,
	}
}

func TestAtSinkFenceMonotonicEpochRejectsStaleWriterAfterPartition(t *testing.T) {
	sink := newFencedReceiverSink("synthetic-writer-key", "sink:write")
	srv := httptest.NewServer(sink)
	defer srv.Close()

	// Leader at epoch 1 commits an initial operation.
	p1 := `{"action":"set","target":"slot-a","value":"v1"}`
	r1 := sendFencedWrite(srv.Client(), srv.URL, "synthetic-writer-key", "sink:write", fenceWriteRequest{
		IdempotencyKey: "op-epoch-1",
		Epoch:          1,
		IntentPayload:  p1,
		IntentDigest:   computeIntentDigest(p1),
	})
	if r1.Outcome != outcomeCommitted || r1.StatusCode != http.StatusOK {
		t.Fatalf("epoch 1 write failed: %+v", r1)
	}

	// Partition heals; successor leader advances sink fence to epoch 2.
	p2 := `{"action":"set","target":"slot-a","value":"v2"}`
	r2 := sendFencedWrite(srv.Client(), srv.URL, "synthetic-writer-key", "sink:write", fenceWriteRequest{
		IdempotencyKey: "op-epoch-2",
		Epoch:          2,
		IntentPayload:  p2,
		IntentDigest:   computeIntentDigest(p2),
	})
	if r2.Outcome != outcomeCommitted || r2.StatusCode != http.StatusOK {
		t.Fatalf("epoch 2 write failed: %+v", r2)
	}

	// Delayed zombie write from partitioned epoch 1 arrives after epoch 2 committed.
	pStale := `{"action":"set","target":"slot-a","value":"zombie-v1"}`
	rStale := sendFencedWrite(srv.Client(), srv.URL, "synthetic-writer-key", "sink:write", fenceWriteRequest{
		IdempotencyKey: "op-stale-from-epoch-1",
		Epoch:          1,
		IntentPayload:  pStale,
		IntentDigest:   computeIntentDigest(pStale),
	})
	if rStale.Outcome != outcomeRejected || rStale.StatusCode != http.StatusConflict || rStale.ErrCode != "stale_epoch" {
		t.Fatalf("expected stale_epoch 409 rejection, got %+v", rStale)
	}
	if got := sink.totalExecutions(); got != 2 {
		t.Fatalf("expected 2 sink executions (stale write must not execute), got %d", got)
	}
}

func TestAtSinkFenceIdempotentReplayReturnsIdenticalReceiptWithoutDuplicateExecution(t *testing.T) {
	sink := newFencedReceiverSink("synthetic-writer-key", "sink:write")
	srv := httptest.NewServer(sink)
	defer srv.Close()

	payload := `{"action":"deploy","artifact":"digest-1234"}`
	req := fenceWriteRequest{
		IdempotencyKey: "op-idempotent-1",
		Epoch:          5,
		IntentPayload:  payload,
		IntentDigest:   computeIntentDigest(payload),
	}

	first := sendFencedWrite(srv.Client(), srv.URL, "synthetic-writer-key", "sink:write", req)
	if first.Outcome != outcomeCommitted || first.Receipt == nil {
		t.Fatalf("first commit failed: %+v", first)
	}
	if first.Receipt.Replayed {
		t.Fatalf("first commit unexpectedly marked replayed")
	}

	second := sendFencedWrite(srv.Client(), srv.URL, "synthetic-writer-key", "sink:write", req)
	if second.Outcome != outcomeCommitted || second.Receipt == nil {
		t.Fatalf("idempotent replay failed: %+v", second)
	}
	if !second.Receipt.Replayed {
		t.Fatalf("expected replay flag on duplicate delivery")
	}
	if second.Receipt.ReceiptID != first.Receipt.ReceiptID ||
		second.Receipt.ExecSeq != first.Receipt.ExecSeq ||
		second.Receipt.IntentDigest != first.Receipt.IntentDigest {
		t.Fatalf("replayed receipt diverged: first=%+v second=%+v", first.Receipt, second.Receipt)
	}
	if got := sink.totalExecutions(); got != 1 {
		t.Fatalf("expected exactly 1 execution across idempotent replay, got %d", got)
	}
}

func TestAtSinkFenceSameKeyAlteredIntentDigestRejectedWithConflict(t *testing.T) {
	sink := newFencedReceiverSink("synthetic-writer-key", "sink:write")
	srv := httptest.NewServer(sink)
	defer srv.Close()

	origPayload := `{"action":"grant","target":"svc-alpha"}`
	first := sendFencedWrite(srv.Client(), srv.URL, "synthetic-writer-key", "sink:write", fenceWriteRequest{
		IdempotencyKey: "op-key-reuse",
		Epoch:          3,
		IntentPayload:  origPayload,
		IntentDigest:   computeIntentDigest(origPayload),
	})
	if first.Outcome != outcomeCommitted || first.StatusCode != http.StatusOK {
		t.Fatalf("initial commit failed: %+v", first)
	}

	alteredPayload := `{"action":"grant","target":"svc-beta"}`
	conflict := sendFencedWrite(srv.Client(), srv.URL, "synthetic-writer-key", "sink:write", fenceWriteRequest{
		IdempotencyKey: "op-key-reuse",
		Epoch:          3,
		IntentPayload:  alteredPayload,
		IntentDigest:   computeIntentDigest(alteredPayload),
	})
	if conflict.Outcome != outcomeRejected || conflict.StatusCode != http.StatusConflict || conflict.ErrCode != "idempotency_conflict" {
		t.Fatalf("expected 409 idempotency_conflict on altered intent, got %+v", conflict)
	}
	if got := sink.totalExecutions(); got != 1 {
		t.Fatalf("altered intent must not execute: expected 1 execution, got %d", got)
	}
}

func TestAtSinkFenceLostACKProducesUnknownWithoutBlindDuplicateExecution(t *testing.T) {
	sink := newFencedReceiverSink("synthetic-writer-key", "sink:write")
	sink.dropNextACK["op-lost-ack"] = true
	srv := httptest.NewServer(sink)
	defer srv.Close()

	payload := `{"action":"rotate","slot":"primary"}`
	req := fenceWriteRequest{
		IdempotencyKey: "op-lost-ack",
		Epoch:          7,
		IntentPayload:  payload,
		IntentDigest:   computeIntentDigest(payload),
	}

	// First attempt commits at sink, but connection closes before ACK arrives.
	first := sendFencedWrite(srv.Client(), srv.URL, "synthetic-writer-key", "sink:write", req)
	if first.Outcome != outcomeUnknown {
		t.Fatalf("expected UNKNOWN classification on lost ACK, got %+v", first)
	}
	if first.Transport == nil || errors.Is(first.Transport, nil) {
		t.Fatalf("expected non-nil transport error on lost ACK")
	}
	if got := sink.totalExecutions(); got != 1 {
		t.Fatalf("expected sink to have committed once before ACK drop, got %d", got)
	}

	// Reconcile using the SAME idempotency key and digest (never a blind new key).
	reconciled := sendFencedWrite(srv.Client(), srv.URL, "synthetic-writer-key", "sink:write", req)
	if reconciled.Outcome != outcomeCommitted || reconciled.Receipt == nil {
		t.Fatalf("reconciliation replay failed: %+v", reconciled)
	}
	if !reconciled.Receipt.Replayed || reconciled.Receipt.ExecSeq != 1 {
		t.Fatalf("expected replayed receipt for original exec_seq=1, got %+v", reconciled.Receipt)
	}
	if got := sink.totalExecutions(); got != 1 {
		t.Fatalf("lost-ACK recovery caused duplicate execution: got %d", got)
	}
}

func TestAtSinkFenceUnauthenticatedAndWrongScopeBypassRejectedForbidden(t *testing.T) {
	sink := newFencedReceiverSink("synthetic-writer-key", "sink:write")
	srv := httptest.NewServer(sink)
	defer srv.Close()

	payload := `{"action":"mutate","target":"protected"}`
	req := fenceWriteRequest{
		IdempotencyKey: "op-bypass-attempt",
		Epoch:          99,
		IntentPayload:  payload,
		IntentDigest:   computeIntentDigest(payload),
	}

	cases := []struct {
		name  string
		auth  string
		scope string
	}{
		{name: "unauthenticated", auth: "", scope: ""},
		{name: "wrong-credential", auth: "wrong-key", scope: "sink:write"},
		{name: "read-only-scope", auth: "synthetic-writer-key", scope: "sink:read"},
		{name: "missing-scope", auth: "synthetic-writer-key", scope: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := sendFencedWrite(srv.Client(), srv.URL, tc.auth, tc.scope, req)
			if res.Outcome != outcomeRejected || res.StatusCode != http.StatusForbidden || res.ErrCode != "forbidden" {
				t.Fatalf("expected 403 forbidden for %s, got %+v", tc.name, res)
			}
		})
	}

	if got := sink.totalExecutions(); got != 0 {
		t.Fatalf("rejected bypasses must not execute: got %d", got)
	}
	if got := sink.currentEpoch(); got != 0 {
		t.Fatalf("rejected bypasses must not advance epoch fence: got %d", got)
	}
}

func TestAtSinkFenceConcurrentEpochRacePreservesMonotonicity(t *testing.T) {
	sink := newFencedReceiverSink("synthetic-writer-key", "sink:write")
	srv := httptest.NewServer(sink)
	defer srv.Close()

	// Advance fence to epoch 10 before launching concurrent writers.
	pInit := `{"action":"init"}`
	initRes := sendFencedWrite(srv.Client(), srv.URL, "synthetic-writer-key", "sink:write", fenceWriteRequest{
		IdempotencyKey: "op-race-init",
		Epoch:          10,
		IntentPayload:  pInit,
		IntentDigest:   computeIntentDigest(pInit),
	})
	if initRes.Outcome != outcomeCommitted {
		t.Fatalf("init write failed: %+v", initRes)
	}

	var wg sync.WaitGroup
	staleRejected := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := fmt.Sprintf(`{"action":"stale","n":%d}`, i)
			res := sendFencedWrite(srv.Client(), srv.URL, "synthetic-writer-key", "sink:write", fenceWriteRequest{
				IdempotencyKey: fmt.Sprintf("op-race-stale-%d", i),
				Epoch:          9,
				IntentPayload:  p,
				IntentDigest:   computeIntentDigest(p),
			})
			staleRejected <- (res.Outcome == outcomeRejected && res.StatusCode == http.StatusConflict && res.ErrCode == "stale_epoch")
		}(i)
	}
	wg.Wait()
	close(staleRejected)

	for ok := range staleRejected {
		if !ok {
			t.Fatal("a concurrent stale-epoch write was not rejected with 409 stale_epoch")
		}
	}
	if got := sink.totalExecutions(); got != 1 {
		t.Fatalf("expected only initial execution to succeed, got %d", got)
	}
}
