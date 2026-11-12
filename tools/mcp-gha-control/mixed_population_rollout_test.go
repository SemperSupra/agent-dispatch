package main

// Public fictional-only oracle: contrasts legacy Cartesian permissions with a
// global observe-only lease fence. Not a copy of product source or host state.
import (
	"fmt"
	"testing"
)

type fixtureIdentity struct {
	token             string
	legacyRefs        map[string]bool
	legacyDelegations map[string]bool
	exact             map[string]string
}
type fixtureProcess struct {
	globalFence bool
	identities  map[string]fixtureIdentity
}

func fixtureAuthorize(p fixtureProcess, token, ref, delegation, operation string) bool {
	identity, ok := p.identities[token]
	if !ok {
		return false
	}
	if p.globalFence {
		if operation != "observe" {
			return false
		}
		// A fenced process demands an exact typed observation entry;
		// legacy Cartesian fields are never an implicit allow.
		return identity.exact[ref+"#"+delegation] == "observe"
	}
	if len(identity.exact) != 0 {
		return identity.exact[ref+"#"+delegation] == operation ||
			(identity.exact[ref+"#"+delegation] == "actuate" && operation == "observe")
	}
	// Legacy unbounded Cartesian pairing is a distinct semantic regime.
	return identity.legacyRefs[ref] && identity.legacyDelegations[delegation]
}
func fixturePopulation() (fixtureProcess, fixtureProcess) {
	legacy := fixtureIdentity{token: "FICTIONAL-LEGACY-NOT-SECRET", legacyRefs: map[string]bool{}, legacyDelegations: map[string]bool{}}
	for i := 0; i < 5; i++ {
		legacy.legacyRefs[fmt.Sprintf("fictional/ref/%d", i)] = true
	}
	for i := 0; i < 4; i++ {
		legacy.legacyDelegations[fmt.Sprintf("fictional/delegation/%d", i)] = true
	}
	canary := fixtureIdentity{token: "FICTIONAL-CANARY-NOT-SECRET", exact: map[string]string{"fictional/ref/0#fictional/delegation/0": "observe"}}
	return fixtureProcess{globalFence: false, identities: map[string]fixtureIdentity{legacy.token: legacy}},
		fixtureProcess{globalFence: true, identities: map[string]fixtureIdentity{canary.token: canary}}
}
func TestSyntheticGlobalFenceCannotImplicitlyPreserveLegacyRights(t *testing.T) {
	old, canary := fixturePopulation()
	token := "FICTIONAL-LEGACY-NOT-SECRET"
	legacyPairs := 0
	for i := 0; i < 5; i++ {
		for j := 0; j < 4; j++ {
			ref, delegation := fmt.Sprintf("fictional/ref/%d", i), fmt.Sprintf("fictional/delegation/%d", j)
			if !fixtureAuthorize(old, token, ref, delegation, "observe") {
				t.Fatal("baseline legacy tuple missing")
			}
			legacyPairs++
		}
	}
	if legacyPairs != 20 {
		t.Fatal("unexpected Cartesian witness")
	}
	// Flip the global fence on the SAME old process: no typed admission
	// exists, so all 20 previously valid tuples deny. This is not a safe
	// semantic-preserving in-place migration, even though it fails closed.
	old.globalFence = true
	for i := 0; i < 5; i++ {
		for j := 0; j < 4; j++ {
			if fixtureAuthorize(old, token, fmt.Sprintf("fictional/ref/%d", i), fmt.Sprintf("fictional/delegation/%d", j), "observe") {
				t.Fatal("global fence silently preserved unqualified fallback")
			}
		}
	}
	if fixtureAuthorize(canary, token, "fictional/ref/0", "fictional/delegation/0", "observe") {
		t.Fatal("legacy credential gained a canary route")
	}
}
func TestSyntheticSeparateCanaryPreservesOldEndpointWithoutCredentialSharing(t *testing.T) {
	old, canary := fixturePopulation()
	if !fixtureAuthorize(old, "FICTIONAL-LEGACY-NOT-SECRET", "fictional/ref/4", "fictional/delegation/3", "plan") {
		t.Fatal("legacy original endpoint unexpectedly narrowed")
	}
	positive := fixtureAuthorize(canary, "FICTIONAL-CANARY-NOT-SECRET", "fictional/ref/0", "fictional/delegation/0", "observe")
	if !positive {
		t.Fatal("separately authenticated exact observe not admitted")
	}
	for _, tc := range []struct{ name, token, ref, delegation, operation string }{
		{"old-token", "FICTIONAL-LEGACY-NOT-SECRET", "fictional/ref/0", "fictional/delegation/0", "observe"},
		{"wrong-ref", "FICTIONAL-CANARY-NOT-SECRET", "fictional/ref/1", "fictional/delegation/0", "observe"},
		{"wrong-delegation", "FICTIONAL-CANARY-NOT-SECRET", "fictional/ref/0", "fictional/delegation/1", "observe"},
		{"plan", "FICTIONAL-CANARY-NOT-SECRET", "fictional/ref/0", "fictional/delegation/0", "plan"},
		{"actuate", "FICTIONAL-CANARY-NOT-SECRET", "fictional/ref/0", "fictional/delegation/0", "actuate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if fixtureAuthorize(canary, tc.token, tc.ref, tc.delegation, tc.operation) {
				t.Fatal("cross-route or over-class authority")
			}
		})
	}
}
