package main

// PUBLIC SYNTHETIC ONLY: exact-field signed ACK binding for a loopback sink.
// No production source, host, credential, external service, or network access.
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSyntheticPostSendACKExactIntentFieldBinding(t *testing.T) {
	wanted := syntheticEffectIntent{
		EffectID: "fictional-effect-r115",
		IntentDigest: "fictional-digest-r115",
		Epoch: 17,
		BudgetUnits: 3,
	}
	key := []byte("synthetic-only-r115-fixture-key")
	for _, tc := range []struct {
		name string
		mutate func(*syntheticEffectIntent)
		want syntheticACKOutcome
	}{
		{"wrong_digest_valid_signature", func(i *syntheticEffectIntent) { i.IntentDigest = "other-fictional-digest" }, syntheticACKUnknown},
		{"wrong_epoch_valid_signature", func(i *syntheticEffectIntent) { i.Epoch++ }, syntheticACKUnknown},
		{"wrong_budget_valid_signature", func(i *syntheticEffectIntent) { i.BudgetUnits++ }, syntheticACKUnknown},
		{"matching_signed_receipt", func(*syntheticEffectIntent) {}, syntheticACKVerified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Method != http.MethodPost {
					t.Errorf("unexpected method: %s", r.Method)
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				var got syntheticEffectIntent
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got != wanted {
					t.Errorf("wrong synthetic request: %+v, %v", got, err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				tc.mutate(&got)
				_ = json.NewEncoder(w).Encode(syntheticSignedACK{
					Intent: got,
					Signature: signSyntheticACK(key, got),
				})
			}))
			defer server.Close()
			result, err := observeSyntheticACK(server.Client(), server.URL, key, wanted)
			if result != tc.want {
				t.Fatalf("unverified altered intent was accepted: got %s want %s err=%v", result, tc.want, err)
			}
			if (tc.want == syntheticACKVerified) != (err == nil) {
				t.Fatalf("outcome and receipt-verification error disagree: %v", err)
			}
			if got := hits.Load(); got != 1 {
				t.Fatalf("blind retry detected: requests=%d", got)
			}
		})
	}
}
