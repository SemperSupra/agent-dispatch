package main

// This is a PUBLIC-SAFE, FICTIONAL reference contract. It does not import,
// exercise, simulate credentials for, or qualify the private Sidecar operator.
// Failure here blocks promotion of a proposed policy *model*, not a live host.

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type revocationFixture struct {
	ID          string
	OwnedByHost bool
	ExactRules  []string
	LegacyRules []string
}

var pinnedSyntheticRef = regexp.MustCompile(`^github-file:fictional/[a-z0-9-]+@[0-9a-f]{40}:[a-z0-9/._-]+\.json$`)

// This standalone model emits ONLY actions, never performs an admission apply.
func syntheticPlan(current []revocationFixture, desired map[string][]string) ([]string, error) {
	if current == nil || desired == nil {
		return nil, errors.New("missing-authority")
	}
	known := map[string]revocationFixture{}
	for _, c := range current {
		if c.ID == "" {
			return nil, errors.New("invalid-identity")
		}
		if _, ok := known[c.ID]; ok {
			return nil, errors.New("duplicate-client")
		}
		known[c.ID] = c
	}
	actions := []string{}
	for id, refs := range desired {
		if id == "" || len(refs) == 0 {
			return nil, errors.New("empty-exact-rules")
		}
		seen := map[string]bool{}
		for _, ref := range refs {
			if !pinnedSyntheticRef.MatchString(ref) || strings.Contains(ref, "/../") || seen[ref] {
				return nil, errors.New("invalid-ref")
			}
			seen[ref] = true
		}
		if c, ok := known[id]; ok && !c.OwnedByHost {
			return nil, errors.New("legacy-capture")
		}
		if c, ok := known[id]; !ok {
			actions = append(actions, "CREATE:"+id)
		} else if !sameSet(c.ExactRules, refs) {
			actions = append(actions, "REPLACE:"+id)
		}
	}
	for _, c := range current {
		if c.OwnedByHost {
			if len(c.ExactRules) == 0 {
				return nil, errors.New("ambiguous-managed-legacy")
			}
			if _, ok := desired[c.ID]; !ok {
				actions = append(actions, "DELETE_TOKEN:"+c.ID)
			}
		}
	}
	sort.Strings(actions)
	return actions, nil
}
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestPublicSyntheticAdmissionRevocationContract(t *testing.T) {
	a := "github-file:fictional/demo@0123456789012345678901234567890123456789:observe.json"
	b := "github-file:fictional/demo@0123456789012345678901234567890123456789:other.json"
	baseline := []revocationFixture{{ID: "legacy", LegacyRules: []string{"observe", "plan"}}, {ID: "managed", OwnedByHost: true, ExactRules: []string{a}, LegacyRules: []string{a}}}
	before := append([]revocationFixture(nil), baseline...)
	operations, e := syntheticPlan(baseline, map[string][]string{})
	if e != nil || len(operations) != 1 || operations[0] != "DELETE_TOKEN:managed" {
		t.Fatalf("revocation=%v err=%v", operations, e)
	}
	if len(before[0].LegacyRules) != 2 || len(baseline[0].LegacyRules) != 2 {
		t.Fatal("legacy mutated")
	}
	if operations[0] == "REPLACE:managed" {
		t.Fatal("empty rights list would reactivate fallback")
	}
	denied := []struct {
		name    string
		current []revocationFixture
		desired map[string][]string
	}{
		{"legacy_capture", baseline, map[string][]string{"legacy": {a}}},
		{"empty_rules", baseline, map[string][]string{"managed": {}}},
		{"moving_ref", baseline, map[string][]string{"managed": {"github-file:fictional/demo@main:observe.json"}}},
		{"wildcard", baseline, map[string][]string{"managed": {"*"}}},
		{"duplicate_ref", baseline, map[string][]string{"managed": {a, a}}},
		{"ambiguous_managed", []revocationFixture{{ID: "managed", OwnedByHost: true, LegacyRules: []string{a}}}, map[string][]string{}},
		{"duplicate_client", []revocationFixture{{ID: "a"}, {ID: "a"}}, map[string][]string{}},
		{"absent_snapshot", nil, map[string][]string{}},
		{"absent_policy", baseline, nil},
	}
	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := syntheticPlan(tc.current, tc.desired); err == nil {
				t.Fatal("accepted invalid fixture")
			}
		})
	}
	good, e := syntheticPlan(baseline, map[string][]string{"managed": {a, b}})
	if e != nil || len(good) != 1 || good[0] != "REPLACE:managed" {
		t.Fatalf("replace=%v error=%v", good, e)
	}
	same, e := syntheticPlan(baseline, map[string][]string{"managed": {a}})
	if e != nil || len(same) != 0 {
		t.Fatalf("idempotency=%v error=%v", same, e)
	}
}
