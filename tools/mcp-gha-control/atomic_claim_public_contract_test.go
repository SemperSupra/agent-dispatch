// Public synthetic GitHub Git-ref contract, not the private Sidecar or a claim adapter.
// The mock HTTP server never reaches GitHub and the tests never dispatch work.
package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httptest"
    "strings"
    "sync"
    "sync/atomic"
    "testing"
    "time"
)

const syntheticBudgetRef = "refs/heads/claims/synthetic-hardone-epoch-001"

// A single shared ref is essential: per-assignment refs would not enforce hard-one.
type syntheticClaimServer struct {
    mu sync.Mutex
    ref string
    sha string
    postCount int
    failAfterCreate bool
    failReadback bool
}

func (s *syntheticClaimServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    switch {
    case r.Method == http.MethodPost && r.URL.Path == "/repos/synthetic/control/git/refs":
        var v struct { Ref string `json:"ref"`; SHA string `json:"sha"` }
        if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&v); err != nil || v.Ref != syntheticBudgetRef || len(v.SHA) != 40 {
            http.Error(w, "invalid public-synthetic claim", http.StatusBadRequest)
            return
        }
        s.mu.Lock()
        s.postCount++
        if s.ref != "" {
            s.mu.Unlock()
            http.Error(w, "Reference already exists", http.StatusUnprocessableEntity)
            return
        }
        s.ref, s.sha = v.Ref, v.SHA
        ambiguous := s.failAfterCreate
        s.mu.Unlock()
        if ambiguous {
            http.Error(w, "synthetic response lost after ref created", http.StatusServiceUnavailable)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        _ = json.NewEncoder(w).Encode(map[string]any{"ref": v.Ref, "object": map[string]string{"sha": v.SHA}})
    case r.Method == http.MethodGet && r.URL.Path == "/repos/synthetic/control/git/ref/heads/claims/synthetic-hardone-epoch-001":
        s.mu.Lock()
        ref, sha, missing := s.ref, s.sha, s.failReadback
        s.mu.Unlock()
        if missing {
            http.Error(w, "synthetic readback unavailable", http.StatusServiceUnavailable)
            return
        }
        if ref == "" {
            http.NotFound(w, r)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(map[string]any{"ref": ref, "object": map[string]string{"sha": sha}})
    default:
        http.NotFound(w, r)
    }
}

// A standalone test client: production ControlStore must separately bind the
// exact delegation/epoch and immutable source/authority before dispatch.
func syntheticClaimAttempt(ctx context.Context, client *http.Client, endpoint, sha string) string {
    input, _ := json.Marshal(map[string]string{"ref": syntheticBudgetRef, "sha": sha})
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/repos/synthetic/control/git/refs", bytes.NewReader(input))
    if err != nil { return "UNKNOWN" }
    req.Header.Set("Content-Type", "application/json")
    res, err := client.Do(req)
    if err != nil { return "UNKNOWN" }
    res.Body.Close()
    if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusUnprocessableEntity {
        // A 5xx POST is not permission to dispatch; the create might have committed.
        return "UNKNOWN"
    }
    read, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/repos/synthetic/control/git/ref/heads/claims/synthetic-hardone-epoch-001", nil)
    if err != nil { return "UNKNOWN" }
    observed, err := client.Do(read)
    if err != nil { return "UNKNOWN" }
    defer observed.Body.Close()
    if observed.StatusCode != http.StatusOK { return "UNKNOWN" }
    var v struct { Ref string `json:"ref"`; Object struct { SHA string `json:"sha"` } `json:"object"` }
    if json.NewDecoder(observed.Body).Decode(&v) != nil || v.Ref != syntheticBudgetRef || len(v.Object.SHA) != 40 { return "UNKNOWN" }
    if res.StatusCode == http.StatusCreated && v.Object.SHA == sha { return "CLAIM_CREATED" }
    if res.StatusCode == http.StatusUnprocessableEntity && v.Object.SHA == sha { return "BUDGET_CONSUMED" }
    return "BUDGET_CONFLICT"
}

func syntheticSHA(i int) string { return fmt.Sprintf("%040x", i+1) }

func TestSyntheticHardOneCrossAssignmentConcurrentCAS(t *testing.T) {
    source := &syntheticClaimServer{}
    server := httptest.NewServer(source)
    defer server.Close()
    client := &http.Client{Timeout: 3 * time.Second}
    const competingAssignments = 24
    var wins atomic.Int32
    var providerPOSTs atomic.Int32
    var wg sync.WaitGroup
    failures := make(chan string, competingAssignments)
    for i := 0; i < competingAssignments; i++ {
        wg.Add(1)
        go func(index int) {
            defer wg.Done()
            // Distinct assignment/request SHAs, one deliberately shared epoch.
            result := syntheticClaimAttempt(context.Background(), client, server.URL, syntheticSHA(index))
            switch result {
            case "CLAIM_CREATED":
                wins.Add(1)
                providerPOSTs.Add(1) // model sole permissible provider attempt
            case "BUDGET_CONFLICT":
            default:
                failures <- result
            }
        }(i)
    }
    wg.Wait()
    close(failures)
    for result := range failures { t.Errorf("unexpected collision outcome: %s", result) }
    if got := wins.Load(); got != 1 { t.Errorf("one ref creation required; winners=%d", got) }
    if got := providerPOSTs.Load(); got != 1 { t.Errorf("simulated provider attempts must not exceed one; got %d", got) }
    source.mu.Lock()
    posted := source.postCount
    source.mu.Unlock()
    if posted != competingAssignments { t.Errorf("expected %d competing claims, observed %d", competingAssignments, posted) }
}

func TestSyntheticHardOneSameAssignmentReplayDoesNotReDispatch(t *testing.T) {
    source := &syntheticClaimServer{}
    server := httptest.NewServer(source)
    defer server.Close()
    c := server.Client()
    sha := syntheticSHA(5)
    first := syntheticClaimAttempt(context.Background(), c, server.URL, sha)
    second := syntheticClaimAttempt(context.Background(), c, server.URL, sha)
    if first != "CLAIM_CREATED" || second != "BUDGET_CONSUMED" {
        t.Fatalf("expected created then consumed, got %s then %s", first, second)
    }
}

func TestSyntheticHardOneAmbiguousPOSTFailsClosed(t *testing.T) {
    source := &syntheticClaimServer{failAfterCreate: true}
    server := httptest.NewServer(source)
    defer server.Close()
    c := server.Client()
    first := syntheticClaimAttempt(context.Background(), c, server.URL, syntheticSHA(10))
    next := syntheticClaimAttempt(context.Background(), c, server.URL, syntheticSHA(11))
    if first != "UNKNOWN" || next != "BUDGET_CONFLICT" {
        t.Fatalf("ambiguous create must deny follow-on: first=%s second=%s", first, next)
    }
    source.mu.Lock()
    ref := source.ref
    source.mu.Unlock()
    if ref != syntheticBudgetRef { t.Fatal("ref should persist despite ambiguous POST response") }
}

func TestSyntheticHardOneAmbiguousReadbackFailsClosed(t *testing.T) {
    source := &syntheticClaimServer{failReadback: true}
    server := httptest.NewServer(source)
    defer server.Close()
    got := syntheticClaimAttempt(context.Background(), server.Client(), server.URL, syntheticSHA(15))
    if got != "UNKNOWN" { t.Fatalf("readback outage must deny dispatch: %s", got) }
}

func TestSyntheticHardOneSourceRevisionDoesNotRefreshBudget(t *testing.T) {
    source := &syntheticClaimServer{}
    server := httptest.NewServer(source)
    defer server.Close()
    c := server.Client()
    if got := syntheticClaimAttempt(context.Background(), c, server.URL, syntheticSHA(20)); got != "CLAIM_CREATED" { t.Fatal(got) }
    // A changed source SHA does not create a new delegation budget epoch.
    if got := syntheticClaimAttempt(context.Background(), c, server.URL, strings.Repeat("f", 40)); got != "BUDGET_CONFLICT" { t.Fatal(got) }
}
