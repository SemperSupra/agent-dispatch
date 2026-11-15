package main

// Public fictional-only negative oracle for AD #748 request-to-apply intent
// binding. This is not the private admissionctl product implementation.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"
)

type syntheticGrantIntent struct {
	Client string `json:"client"`
	Mode   string `json:"mode"`
	Ref    string `json:"ref"`
	Scope  string `json:"scope"`
}

type syntheticSignedDecision struct {
	Preimage    string
	IntentHash  string
	WholeDelete bool
}

func syntheticHashIntent(in syntheticGrantIntent) string {
	b, _ := json.Marshal(in)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func syntheticAcceptApprovedIntent(preimage string, intent syntheticGrantIntent, decision syntheticSignedDecision) bool {
	// Both the exact baseline and requested change must be identical to what
	// the host/owner approved; a config hash alone cannot bind the request.
	return preimage == decision.Preimage && syntheticHashIntent(intent) == decision.IntentHash
}

func syntheticDeletePrincipalAllowed(in syntheticGrantIntent, current []syntheticGrantIntent, legacyExtras int, decision syntheticSignedDecision) bool {
	if in.Mode != "revoke" || !syntheticAcceptApprovedIntent(decision.Preimage, in, decision) {
		return false
	}
	// This single-canary contract has no authority for additional exact
	// rights or legacy/provider-native rights. Explicit whole-delete needs
	// separate approval and a full-rights preimage, not this operation.
	return len(current) == 1 && current[0].Client == in.Client && current[0].Ref == in.Ref &&
		current[0].Scope == in.Scope && legacyExtras == 0 && !decision.WholeDelete
}

func TestSyntheticSameConfigRequestSwapMustFail(t *testing.T) {
	baseline := "fixture-config-sha"
	approved := syntheticGrantIntent{Client: "fixture-canary", Mode: "append", Ref: "fictional/a", Scope: "observe"}
	substituted := approved
	substituted.Ref = "fictional/b"
	decision := syntheticSignedDecision{Preimage: baseline, IntentHash: syntheticHashIntent(approved)}
	if !syntheticAcceptApprovedIntent(baseline, approved, decision) {
		t.Fatal("exact approved intent rejected")
	}
	if syntheticAcceptApprovedIntent(baseline, substituted, decision) {
		t.Fatal("changed requested ref accepted against unchanged config SHA")
	}
	if syntheticAcceptApprovedIntent("stale-config", approved, decision) {
		t.Fatal("stale config accepted")
	}
	// Negative witness: a preimage-only check would accept a substituted ref.
	if baseline != decision.Preimage {
		t.Fatal("negative witness invalid")
	}
}

func TestSyntheticWholePrincipalRevokeNeedsFullRightsProof(t *testing.T) {
	request := syntheticGrantIntent{Client: "fixture-canary", Mode: "revoke", Ref: "fictional/a", Scope: "observe"}
	decision := syntheticSignedDecision{Preimage: "fixture-config-sha", IntentHash: syntheticHashIntent(request)}
	if !syntheticDeletePrincipalAllowed(request, []syntheticGrantIntent{request}, 0, decision) {
		t.Fatal("single exact tuple rejected")
	}
	second := request
	second.Ref = "fictional/b"
	for name, tc := range map[string]struct {
		request syntheticGrantIntent
		grants []syntheticGrantIntent
		extras int
	}{
		"substituted-tuple": {second, []syntheticGrantIntent{request}, 0},
		"multiple-exact": {request, []syntheticGrantIntent{request, second}, 0},
		"legacy-extra": {request, []syntheticGrantIntent{request}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if syntheticDeletePrincipalAllowed(tc.request, tc.grants, tc.extras, decision) {
				t.Fatal("unapproved whole-principal rights loss accepted")
			}
		})
	}
}

func TestSyntheticConcurrentCASHasOneWinningEffect(t *testing.T) {
	// A cooperating-writer simulation, not an inode-replacement or power-loss
	// proof. Both actors start at the same approval/config revision.
	var mu sync.Mutex
	revision := "old"
	allowed := 0
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			intent := syntheticGrantIntent{Client: "fictional", Mode: "append", Ref: string(rune('a' + i)), Scope: "observe"}
			decision := syntheticSignedDecision{Preimage: "old", IntentHash: syntheticHashIntent(intent)}
			mu.Lock()
			defer mu.Unlock()
			if syntheticAcceptApprovedIntent(revision, intent, decision) {
				revision = "new"
				allowed++
			}
		}(i)
	}
	wg.Wait()
	if allowed != 1 {
		t.Fatalf("expected one CAS winner, got %d", allowed)
	}
}

func TestSyntheticCrashUnknownCannotReplay(t *testing.T) {
	phase := "UNKNOWN"
	apply := func() bool { return phase == "PREPARED" }
	if apply() {
		t.Fatal("UNKNOWN admission was replayed")
	}
}
