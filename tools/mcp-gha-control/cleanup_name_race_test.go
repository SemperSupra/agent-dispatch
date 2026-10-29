package main

// Purely synthetic, public-safe repository cleanup contract. No real GitHub
// deletion, credentials, network outside httptest, or privileged workcell.
import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

const syntheticRepoName = "ExampleOrg/synthetic-workcell"

type syntheticNamedRepository struct {
	mu         sync.Mutex
	id         int64
	exists     bool
	deletes    int
	deletedIDs []int64
	ambiguity  bool
}

func (s *syntheticNamedRepository) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/repos/"+syntheticRepoName {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.exists {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": s.id, "full_name": syntheticRepoName, "private": true,
		})
	case http.MethodDelete:
		s.deletes++
		s.deletedIDs = append(s.deletedIDs, s.id)
		s.exists = false
		if s.ambiguity {
			http.Error(w, "synthetic response failed after side effect", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unsupported synthetic method", http.StatusMethodNotAllowed)
	}
}

func syntheticGET(ctx context.Context, client *http.Client, base string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/repos/"+syntheticRepoName, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, errors.New("non-200 synthetic GET")
	}
	var observed struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
		Private  bool   `json:"private"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&observed); err != nil {
		return 0, err
	}
	if observed.ID <= 0 || observed.FullName != syntheticRepoName || !observed.Private {
		return 0, errors.New("invalid exact identity")
	}
	return observed.ID, nil
}

// This intentionally demonstrates a BROKEN algorithm, never a safe delete.
func syntheticNaiveNameDelete(ctx context.Context, client *http.Client, base string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, base+"/repos/"+syntheticRepoName, nil)
	if err != nil {
		return 0
	}
	res, err := client.Do(req)
	if err != nil {
		return 0
	}
	res.Body.Close()
	return res.StatusCode
}

// A boolean owner decision cannot manufacture a provider-supported atomic
// condition. This test-only hold has no mutation capability whatsoever.
func syntheticConservativeCleanup(ownerAcknowledged bool, expectedID, observedID int64) string {
	if !ownerAcknowledged || expectedID <= 0 || observedID != expectedID {
		return "BLOCKED_IDENTITY_OR_OWNER"
	}
	return "BLOCKED_NONATOMIC_NAME_DELETE"
}

func TestSyntheticNameReuseBetweenGETAndDELETEIsNotAtomic(t *testing.T) {
	store := &syntheticNamedRepository{id: 101, exists: true}
	server := httptest.NewServer(store)
	defer server.Close()
	client := server.Client()
	observed, err := syntheticGET(context.Background(), client, server.URL)
	if err != nil || observed != 101 {
		t.Fatalf("initial readback failed: id=%d error=%v", observed, err)
	}
	// Reassignment is possible between separate HTTP requests, even after
	// an exact positive-ID read and human-supplied cleanup decision.
	store.mu.Lock()
	store.id = 202
	store.exists = true
	store.mu.Unlock()
	if status := syntheticNaiveNameDelete(context.Background(), client, server.URL); status != http.StatusNoContent {
		t.Fatalf("synthetic delete status %d", status)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.deletedIDs) != 1 || store.deletedIDs[0] != 202 || store.deletedIDs[0] == observed {
		t.Fatalf("expected to reproduce wrong-repository deletion; ids=%v observed=%d", store.deletedIDs, observed)
	}
}

func TestSyntheticFailClosedWithoutConditionalDeleteDespiteOwnerFlag(t *testing.T) {
	for _, tc := range []struct {
		approved           bool
		expected, observed int64
		want               string
	}{
		{false, 101, 101, "BLOCKED_IDENTITY_OR_OWNER"},
		{true, 0, 101, "BLOCKED_IDENTITY_OR_OWNER"},
		{true, 101, 202, "BLOCKED_IDENTITY_OR_OWNER"},
		{true, 101, 101, "BLOCKED_NONATOMIC_NAME_DELETE"},
	} {
		if got := syntheticConservativeCleanup(tc.approved, tc.expected, tc.observed); got != tc.want {
			t.Fatalf("approved=%t expected=%d observed=%d: got %q want %q", tc.approved, tc.expected, tc.observed, got, tc.want)
		}
	}
}

func TestSyntheticAmbiguousDELETECannotAuthorizeRetry(t *testing.T) {
	store := &syntheticNamedRepository{id: 303, exists: true, ambiguity: true}
	server := httptest.NewServer(store)
	defer server.Close()
	status := syntheticNaiveNameDelete(context.Background(), server.Client(), server.URL)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("expected ambiguous response, got %d", status)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.deletes != 1 || store.exists || len(store.deletedIDs) != 1 {
		t.Fatalf("wrong synthetic unknown evidence deletes=%d exists=%t", store.deletes, store.exists)
	}
	// Deliberately do not retry; the request committed despite 503.
}
