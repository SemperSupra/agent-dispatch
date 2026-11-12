package main

// Public-safe reference oracle: fictional legacy/typed rights only.
// It never loads private Sidecar code, authenticates a caller, or changes a host.
import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

type fixtureCall struct {
	Ref, Delegation, Class, Assignment string
}
type fixtureLegacy struct {
	Refs, Delegations, Classes, Assignments []string
	UnboundedAssignments                    bool
}
type fixtureExact struct {
	Ref, Delegation, Class string
	Assignments            []string
}

func fixtureContains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
func fixtureKey(c fixtureCall) string {
	return strings.Join([]string{c.Ref, c.Delegation, c.Class, c.Assignment}, "\x00")
}
func fixtureLegacyAllows(legacy fixtureLegacy, call fixtureCall) bool {
	return fixtureContains(legacy.Refs, call.Ref) &&
		fixtureContains(legacy.Delegations, call.Delegation) &&
		fixtureContains(legacy.Classes, call.Class) &&
		(legacy.UnboundedAssignments || fixtureContains(legacy.Assignments, call.Assignment))
}
func fixtureExactAllows(rules []fixtureExact, call fixtureCall) bool {
	for _, rule := range rules {
		if rule.Ref == call.Ref && rule.Delegation == call.Delegation &&
			rule.Class == call.Class && fixtureContains(rule.Assignments, call.Assignment) {
			return true
		}
	}
	return false
}

// This is an intentionally strict and finite model. The explicit unbounded
// case is not representable by a list of finite assignment IDs.
func fixtureProveBoundedEquivalence(legacy fixtureLegacy, rules []fixtureExact) error {
	if legacy.UnboundedAssignments {
		return fmt.Errorf("unbounded-assignment-authority")
	}
	fields := [][]string{legacy.Refs, legacy.Delegations, legacy.Classes, legacy.Assignments}
	for _, values := range fields {
		if len(values) == 0 {
			return fmt.Errorf("unknown-legacy-authority")
		}
		seen := map[string]bool{}
		for _, v := range values {
			if v == "" || v == "*" || seen[v] {
				return fmt.Errorf("ambiguous-legacy-scope")
			}
			seen[v] = true
		}
	}
	expected := map[string]bool{}
	for _, ref := range legacy.Refs {
		for _, delegation := range legacy.Delegations {
			for _, class := range legacy.Classes {
				for _, assignment := range legacy.Assignments {
					expected[fixtureKey(fixtureCall{ref, delegation, class, assignment})] = true
				}
			}
		}
	}
	actual := map[string]bool{}
	for _, rule := range rules {
		if rule.Ref == "" || rule.Delegation == "" || rule.Class == "" ||
			rule.Ref == "*" || rule.Delegation == "*" || rule.Class == "*" ||
			len(rule.Assignments) == 0 {
			return fmt.Errorf("incomplete-exact-rule")
		}
		for _, assignment := range rule.Assignments {
			if assignment == "" || assignment == "*" {
				return fmt.Errorf("unbounded-exact-rule")
			}
			key := fixtureKey(fixtureCall{rule.Ref, rule.Delegation, rule.Class, assignment})
			if actual[key] {
				return fmt.Errorf("duplicate-exact-right")
			}
			actual[key] = true
		}
	}
	if len(expected) != len(actual) {
		return fmt.Errorf("rights-count-difference")
	}
	for right := range expected {
		if !actual[right] {
			return fmt.Errorf("rights-content-difference")
		}
	}
	return nil
}

func TestPublicLegacyTupleCountDoesNotProveMigrationEquivalence(t *testing.T) {
	// Five fictional references times four delegations = twenty *pairs*,
	// but these pairs do not encode caller class or assignment scope.
	legacy := fixtureLegacy{
		Refs:                 []string{"r1", "r2", "r3", "r4", "r5"},
		Delegations:          []string{"d1", "d2", "d3", "d4"},
		Classes:              []string{"observe", "plan"},
		Assignments:          []string{"a1"},
		UnboundedAssignments: true,
	}
	var typed []fixtureExact
	for _, ref := range legacy.Refs {
		for _, delegation := range legacy.Delegations {
			typed = append(typed, fixtureExact{ref, delegation, "observe", []string{"a1"}})
		}
	}
	if len(typed) != 20 {
		t.Fatal("incorrect fictional cardinality")
	}
	if err := fixtureProveBoundedEquivalence(legacy, typed); err == nil {
		t.Fatal("twenty typed entries falsely certified lossless legacy migration")
	}
	// Two concrete counterexamples, even before considering infinity.
	for _, call := range []fixtureCall{
		{"r1", "d1", "plan", "a1"},
		{"r1", "d1", "observe", "previously-unlisted-assignment"},
	} {
		if !fixtureLegacyAllows(legacy, call) || fixtureExactAllows(typed, call) {
			t.Fatalf("migration lost or widened authority on %+v", call)
		}
	}
}

func TestPublicFiniteScopeMustMatchContentNotJustCardinality(t *testing.T) {
	legacy := fixtureLegacy{
		Refs: []string{"r1", "r2"}, Delegations: []string{"d1"},
		Classes: []string{"observe"}, Assignments: []string{"a1", "a2"},
	}
	equal := []fixtureExact{
		{"r1", "d1", "observe", []string{"a1", "a2"}},
		{"r2", "d1", "observe", []string{"a2", "a1"}},
	}
	if err := fixtureProveBoundedEquivalence(legacy, equal); err != nil {
		t.Fatal(err)
	}
	negative := []struct {
		name  string
		rules []fixtureExact
	}{
		{"missing-right", []fixtureExact{{"r1", "d1", "observe", []string{"a1"}}, {"r2", "d1", "observe", []string{"a1", "a2"}}}},
		{"different-right-same-count", []fixtureExact{{"r1", "d1", "observe", []string{"a1", "a2"}}, {"r2", "d1", "plan", []string{"a1", "a2"}}}},
		{"duplicate-right", []fixtureExact{{"r1", "d1", "observe", []string{"a1", "a1"}}, {"r2", "d1", "observe", []string{"a1", "a2"}}}},
		{"extra-right", []fixtureExact{{"r1", "d1", "observe", []string{"a1", "a2", "a3"}}, {"r2", "d1", "observe", []string{"a1", "a2"}}}},
		{"wildcard-assignment", []fixtureExact{{"r1", "d1", "observe", []string{"*"}}, {"r2", "d1", "observe", []string{"a1", "a2"}}}},
	}
	for _, tc := range negative {
		t.Run(tc.name, func(t *testing.T) {
			if err := fixtureProveBoundedEquivalence(legacy, tc.rules); err == nil {
				t.Fatal("unsafe equivalence")
			}
		})
	}
	// Deterministic diagnostic view, independent of map iteration.
	keys := []string{}
	for _, r := range equal {
		keys = append(keys, r.Ref+":"+r.Delegation+":"+r.Class)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "r1:d1:observe,r2:d1:observe" {
		t.Fatal(keys)
	}
}
