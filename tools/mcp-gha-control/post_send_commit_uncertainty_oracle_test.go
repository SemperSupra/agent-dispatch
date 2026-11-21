package main

// Public, synthetic-only receiver experiment. An HTTP status is not a
// cryptographically authenticated, durable assertion that no effect occurred.
// The harness never contacts a real effect provider or uses private material.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type syntheticEffectIntent struct {
	EffectID     string `json:"effect_id"`
	IntentDigest string `json:"intent_digest"`
	Epoch        uint64 `json:"epoch"`
	BudgetUnits  uint64 `json:"budget_units"`
}

type syntheticSignedACK struct {
	Intent    syntheticEffectIntent `json:"intent"`
	Signature string                `json:"signature"`
}

func signSyntheticACK(key []byte, in syntheticEffectIntent) string {
	raw, _ := json.Marshal(in)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("synthetic-postsend-v1\x00"))
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

type syntheticAmbiguousSink struct {
	mu      sync.Mutex
	mode    string
	key     []byte
	hits    int
	commits int
}

func (s *syntheticAmbiguousSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in syntheticEffectIntent
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid fixture", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.hits++
	if s.mode != "deny-before-commit" {
		s.commits++
	}
	s.mu.Unlock()

	switch s.mode {
	case "403-after-commit", "deny-before-commit":
		http.Error(w, "synthetic forbidden", http.StatusForbidden)
	case "403-after-commit-sensitive":
		http.Error(w, "fictional credential: DO-NOT-LEAK-R113", http.StatusForbidden)
	case "409-after-commit":
		http.Error(w, "synthetic conflict", http.StatusConflict)
	case "malformed-200":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not-json"))
	case "unsigned-200":
		_ = json.NewEncoder(w).Encode(syntheticSignedACK{Intent: in})
	case "wrong-effect-200":
		in.EffectID = "unrelated-effect"
		_ = json.NewEncoder(w).Encode(syntheticSignedACK{Intent: in, Signature: signSyntheticACK(s.key, in)})
	case "wrong-signer-200":
		_ = json.NewEncoder(w).Encode(syntheticSignedACK{Intent: in, Signature: signSyntheticACK([]byte("untrusted-fixture-key"), in)})
	case "lost-ack":
		if hijacker, ok := w.(http.Hijacker); ok {
			if conn, _, err := hijacker.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	case "signed-200":
		_ = json.NewEncoder(w).Encode(syntheticSignedACK{Intent: in, Signature: signSyntheticACK(s.key, in)})
	default:
		http.Error(w, "invalid fixture mode", http.StatusInternalServerError)
	}
}

func (s *syntheticAmbiguousSink) counts() (hits, commits int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits, s.commits
}

type syntheticACKOutcome string

const (
	syntheticACKUnknown  syntheticACKOutcome = "UNKNOWN_NO_RETRY"
	syntheticACKVerified syntheticACKOutcome = "VERIFIED_EFFECT"
)

func observeSyntheticACK(client *http.Client, url string, key []byte, intent syntheticEffectIntent) (syntheticACKOutcome, error) {
	raw, err := json.Marshal(intent)
	if err != nil {
		return syntheticACKUnknown, err
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		return syntheticACKUnknown, err
	}
	defer resp.Body.Close()
	// A 4xx/5xx response after a possibly-effectful POST has no signed
	// no-commit proof. A new effect ID must never be issued blindly.
	if resp.StatusCode != http.StatusOK {
		return syntheticACKUnknown, errors.New("unverified post-send HTTP status")
	}
	var ack syntheticSignedACK
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return syntheticACKUnknown, err
	}
	if ack.Intent != intent || !hmac.Equal([]byte(ack.Signature), []byte(signSyntheticACK(key, ack.Intent))) {
		return syntheticACKUnknown, errors.New("unverified or mismatched signed receipt")
	}
	return syntheticACKVerified, nil
}

func TestSyntheticPostSendACKNeverTreatsUnverifiedStatusAsNoEffect(t *testing.T) {
	const effectID = "fictional-effect-1"
	intent := syntheticEffectIntent{EffectID: effectID, IntentDigest: "fictional-digest", Epoch: 7, BudgetUnits: 2}
	key := []byte("synthetic-test-key-never-a-real-secret")
	for _, tc := range []struct {
		name    string
		want    syntheticACKOutcome
		commits int
	}{
		{"403-after-commit", syntheticACKUnknown, 1},
		{"403-after-commit-sensitive", syntheticACKUnknown, 1},
		{"409-after-commit", syntheticACKUnknown, 1},
		{"malformed-200", syntheticACKUnknown, 1},
		{"unsigned-200", syntheticACKUnknown, 1},
		{"wrong-effect-200", syntheticACKUnknown, 1},
		{"wrong-signer-200", syntheticACKUnknown, 1},
		{"lost-ack", syntheticACKUnknown, 1},
		{"deny-before-commit", syntheticACKUnknown, 0},
		{"signed-200", syntheticACKVerified, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &syntheticAmbiguousSink{mode: tc.name, key: key}
			srv := httptest.NewServer(sink)
			defer srv.Close()
			got, err := observeSyntheticACK(srv.Client(), srv.URL, key, intent)
			if got != tc.want {
				t.Fatalf("status/ACK caused unsafe state transition: mode=%s got=%s want=%s err=%v", tc.name, got, tc.want, err)
			}
			if (tc.want == syntheticACKVerified && err != nil) || (tc.want == syntheticACKUnknown && err == nil) {
				t.Fatalf("inconsistent verification error: mode=%s outcome=%s err=%v", tc.name, got, err)
			}
			if err != nil && bytes.Contains([]byte(err.Error()), []byte("DO-NOT-LEAK-R113")) {
				t.Fatalf("untrusted remote response leaked into diagnostic: %v", err)
			}
			if hits, commits := sink.counts(); hits != 1 || commits != tc.commits {
				t.Fatalf("client performed blind retry or sink miscount: hits=%d commits=%d", hits, commits)
			}
		})
	}
}
