package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"
)

var (
	errInvalidClientGrant   = errors.New("invalid or duplicate client grant ID")
	errWorksetNotAdmitted   = errors.New("workset not in admitted registry")
	errExecutorDisabled     = errors.New("executor is disabled by admission policy")
	errScopeEscalationDenied = errors.New("read-only grant cannot claim mutating writer scope")
	errWebhookClockSkew     = errors.New("webhook timestamp skew exceeds tolerance")
	errInvalidSignature     = errors.New("webhook HMAC signature mismatch")
)

type clientCohortAdmission struct {
	AdmittedWorksets []string
	EnabledExecutors []string
	Grants           map[string]string // grantID -> scope ("read" or "write")
}

func evaluateWorksetAdmission(
	cohort clientCohortAdmission,
	grantID string,
	workset string,
	executor string,
	requestedScope string,
) error {
	if grantID == "" {
		return errInvalidClientGrant
	}
	grantedScope, exists := cohort.Grants[grantID]
	if !exists {
		return errInvalidClientGrant
	}
	if !slices.Contains(cohort.AdmittedWorksets, workset) {
		return errWorksetNotAdmitted
	}
	if !slices.Contains(cohort.EnabledExecutors, executor) {
		return errExecutorDisabled
	}
	if grantedScope == "read" && requestedScope == "write" {
		return errScopeEscalationDenied
	}
	return nil
}

type webhookRequest struct {
	Timestamp      int64  `json:"timestamp"`
	IdempotencyKey string `json:"idempotency_key"`
	Action         string `json:"action"`
}

func verifyWebhookPayload(
	payload []byte,
	providedSignature string,
	secret []byte,
	currentTime time.Time,
	toleranceSec int64,
) (*webhookRequest, error) {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(providedSignature), []byte(expectedSig)) {
		return nil, errInvalidSignature
	}

	var req webhookRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}

	skew := currentTime.Unix() - req.Timestamp
	if skew < 0 {
		skew = -skew
	}
	if skew > toleranceSec {
		return nil, errWebhookClockSkew
	}

	return &req, nil
}

func TestAdmissionCohortInvariantsOracle(t *testing.T) {
	cohort := clientCohortAdmission{
		AdmittedWorksets: []string{"workset-alpha", "workset-beta", "workset-gamma"},
		EnabledExecutors: []string{"wow-sidecar-truenas", "wow-sidecar-oci", "garm-truenas", "gha-public-safe", "local-workstation"},
		Grants: map[string]string{
			"grant-reader-001": "read",
			"grant-writer-002": "write",
		},
	}

	// 1. Valid admission
	err := evaluateWorksetAdmission(cohort, "grant-writer-002", "workset-alpha", "wow-sidecar-truenas", "write")
	if err != nil {
		t.Fatalf("expected valid admission, got: %v", err)
	}

	// 2. Reject unadmitted workset
	err = evaluateWorksetAdmission(cohort, "grant-writer-002", "workset-unadmitted", "wow-sidecar-truenas", "write")
	if !errors.Is(err, errWorksetNotAdmitted) {
		t.Fatalf("expected errWorksetNotAdmitted, got: %v", err)
	}

	// 3. Reject disabled executor
	err = evaluateWorksetAdmission(cohort, "grant-writer-002", "workset-alpha", "disabled-executor-x", "write")
	if !errors.Is(err, errExecutorDisabled) {
		t.Fatalf("expected errExecutorDisabled, got: %v", err)
	}

	// 4. Reject scope escalation (read -> write)
	err = evaluateWorksetAdmission(cohort, "grant-reader-001", "workset-alpha", "wow-sidecar-truenas", "write")
	if !errors.Is(err, errScopeEscalationDenied) {
		t.Fatalf("expected errScopeEscalationDenied, got: %v", err)
	}

	// 5. Allow reader with read scope
	err = evaluateWorksetAdmission(cohort, "grant-reader-001", "workset-alpha", "wow-sidecar-truenas", "read")
	if err != nil {
		t.Fatalf("expected valid read admission, got: %v", err)
	}
}

func TestWebhookClockSkewAndSignatureOracle(t *testing.T) {
	secret := []byte("fixed-test-secret-32-bytes-long!")
	now := time.Unix(1763600000, 0)

	payloadValid := []byte(`{"timestamp":1763600010,"idempotency_key":"idem-001","action":"reconcile"}`)
	mac := hmac.New(sha256.New, secret)
	mac.Write(payloadValid)
	sigValid := hex.EncodeToString(mac.Sum(nil))

	// 1. Valid webhook
	req, err := verifyWebhookPayload(payloadValid, sigValid, secret, now, 60)
	if err != nil {
		t.Fatalf("expected valid webhook, got: %v", err)
	}
	if req.IdempotencyKey != "idem-001" || req.Action != "reconcile" {
		t.Fatalf("unexpected parsed req: %+v", req)
	}

	// 2. Signature mismatch fails closed
	_, err = verifyWebhookPayload(payloadValid, "invalid-sig-hex", secret, now, 60)
	if !errors.Is(err, errInvalidSignature) {
		t.Fatalf("expected errInvalidSignature, got: %v", err)
	}

	// 3. Timestamp skew > 60s fails closed
	payloadStale := []byte(`{"timestamp":1763599800,"idempotency_key":"idem-002","action":"reconcile"}`)
	macStale := hmac.New(sha256.New, secret)
	macStale.Write(payloadStale)
	sigStale := hex.EncodeToString(macStale.Sum(nil))

	_, err = verifyWebhookPayload(payloadStale, sigStale, secret, now, 60)
	if !errors.Is(err, errWebhookClockSkew) {
		t.Fatalf("expected errWebhookClockSkew, got: %v", err)
	}
}
