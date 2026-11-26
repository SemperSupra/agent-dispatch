package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
)

const validationOutputPrefix = ".validation-output/"

type validatorCommandRecord struct {
	Command  string
	ExitCode int
}

type validatorAuthority struct {
	TargetRepositoryWrite bool
	MergeAuthority        bool
	WorkspaceWrite        bool
}

func evaluateCOWValidatorCell(
	expectedSourceBlobs map[string]string,
	observedTreeBlobs map[string]string,
	auth validatorAuthority,
	commands []validatorCommandRecord,
) (string, string) {
	for path, expSHA := range expectedSourceBlobs {
		obsSHA, ok := observedTreeBlobs[path]
		if !ok || obsSHA != expSHA {
			return "SOURCE_MUTATION_DETECTED", "projected source blob set changed during validation"
		}
	}
	for path := range observedTreeBlobs {
		if _, isSource := expectedSourceBlobs[path]; !isSource {
			if !strings.HasPrefix(path, validationOutputPrefix) {
				return "VALIDATOR_PROTOCOL_DEFECT", "validator wrote outside the evidence prefix"
			}
		}
	}
	if auth.TargetRepositoryWrite || auth.MergeAuthority || !auth.WorkspaceWrite {
		return "VALIDATOR_PROTOCOL_DEFECT", "validator authority declaration is not least-authority"
	}
	if len(commands) == 0 {
		return "EVIDENCE_INCOMPLETE", "at least one command record is required"
	}
	for _, c := range commands {
		if strings.TrimSpace(c.Command) == "" {
			return "EVIDENCE_INCOMPLETE", "command must be non-empty"
		}
		if c.ExitCode != 0 {
			return "VALIDATION_FAIL", "one or more validation commands returned non-zero"
		}
	}
	return "VALIDATION_PASS", "source immutable, authority bounded, and all recorded commands passed"
}

type executorTargetProfile struct {
	Name         string
	Venue        string
	Capabilities []string
}

type delegationProjection struct {
	ContractID           string
	DelegationID         string
	Grants               []string
	RequiredCapabilities []string
}

func selectEligibleTarget(proj delegationProjection, targets []executorTargetProfile) (*executorTargetProfile, string) {
	req := make(map[string]bool, len(proj.RequiredCapabilities))
	for _, c := range proj.RequiredCapabilities {
		req[c] = true
	}
	var eligible []executorTargetProfile
	for _, t := range targets {
		offered := make(map[string]bool, len(t.Capabilities))
		for _, c := range t.Capabilities {
			offered[c] = true
		}
		ok := true
		for c := range req {
			if !offered[c] {
				ok = false
				break
			}
		}
		if ok {
			eligible = append(eligible, t)
		}
	}
	if len(eligible) == 0 {
		return nil, "capability_mismatch"
	}
	if len(eligible) > 1 {
		return nil, "supervisor_selection_required"
	}
	return &eligible[0], ""
}

func blobDigest(content string) string {
	s := sha256.Sum256([]byte(content))
	return hex.EncodeToString(s[:])
}

func TestCOWValidatorCellImmutableSourceAndLeastAuthorityOracles(t *testing.T) {
	expected := map[string]string{
		".agent-dispatch/execution-workspace.json": blobDigest(`{"schema":1,"authoritative":false}`),
		"src/solver.go":                            blobDigest("package solver\nfunc Answer() int { return 42 }\n"),
	}
	leastAuth := validatorAuthority{
		TargetRepositoryWrite: false,
		MergeAuthority:        false,
		WorkspaceWrite:        true,
	}
	passCmd := []validatorCommandRecord{{Command: "go test -race ./...", ExitCode: 0}}

	t.Run("immutable_source_with_scoped_output_passes", func(t *testing.T) {
		observed := map[string]string{
			".agent-dispatch/execution-workspace.json": expected[".agent-dispatch/execution-workspace.json"],
			"src/solver.go":                            expected["src/solver.go"],
			".validation-output/summary.json":          blobDigest(`{"ok":true}`),
		}
		state, _ := evaluateCOWValidatorCell(expected, observed, leastAuth, passCmd)
		if state != "VALIDATION_PASS" {
			t.Fatalf("expected VALIDATION_PASS, got %s", state)
		}
	})

	t.Run("mutated_or_missing_source_blob_rejected_fail_closed", func(t *testing.T) {
		mutated := map[string]string{
			".agent-dispatch/execution-workspace.json": expected[".agent-dispatch/execution-workspace.json"],
			"src/solver.go":                            blobDigest("package solver\nfunc Answer() int { return 99 }\n"),
		}
		state, _ := evaluateCOWValidatorCell(expected, mutated, leastAuth, passCmd)
		if state != "SOURCE_MUTATION_DETECTED" {
			t.Fatalf("expected SOURCE_MUTATION_DETECTED, got %s", state)
		}
	})

	t.Run("write_outside_validation_output_prefix_rejected", func(t *testing.T) {
		rogue := map[string]string{
			".agent-dispatch/execution-workspace.json": expected[".agent-dispatch/execution-workspace.json"],
			"src/solver.go":                            expected["src/solver.go"],
			"untracked_escape.txt":                     blobDigest("rogue"),
		}
		state, _ := evaluateCOWValidatorCell(expected, rogue, leastAuth, passCmd)
		if state != "VALIDATOR_PROTOCOL_DEFECT" {
			t.Fatalf("expected VALIDATOR_PROTOCOL_DEFECT, got %s", state)
		}
	})

	t.Run("over_privileged_validator_authority_rejected", func(t *testing.T) {
		observed := map[string]string{
			".agent-dispatch/execution-workspace.json": expected[".agent-dispatch/execution-workspace.json"],
			"src/solver.go":                            expected["src/solver.go"],
		}
		badAuth := validatorAuthority{TargetRepositoryWrite: true, MergeAuthority: false, WorkspaceWrite: true}
		state, _ := evaluateCOWValidatorCell(expected, observed, badAuth, passCmd)
		if state != "VALIDATOR_PROTOCOL_DEFECT" {
			t.Fatalf("expected VALIDATOR_PROTOCOL_DEFECT, got %s", state)
		}
	})
}

func TestHeterogeneousExecutorSubstitutionPreservesAuthorityEnvelope(t *testing.T) {
	proj := delegationProjection{
		ContractID:           "contract-b6-001",
		DelegationID:         "deterministic-verify",
		Grants:               []string{"repo:read", "workflow:dispatch"},
		RequiredCapabilities: []string{"linux-cpu", "deterministic-test"},
	}

	venueA := []executorTargetProfile{{
		Name:         "public-gha-ubuntu",
		Venue:        "github-actions",
		Capabilities: []string{"linux-cpu", "deterministic-test"},
	}}
	venueB := []executorTargetProfile{{
		Name:         "disposable-container-worker",
		Venue:        "container-worker",
		Capabilities: []string{"linux-cpu", "deterministic-test", "isolated-fs"},
	}}

	selA, boundaryA := selectEligibleTarget(proj, venueA)
	selB, boundaryB := selectEligibleTarget(proj, venueB)
	if boundaryA != "" || boundaryB != "" || selA == nil || selB == nil {
		t.Fatalf("expected both profiles to bind cleanly, got (%v,%q) (%v,%q)", selA, boundaryA, selB, boundaryB)
	}
	if selA.Name == selB.Name || selA.Venue == selB.Venue {
		t.Fatalf("expected distinct executor embodiments, got %+v vs %+v", selA, selB)
	}

	// Authority grants remain unchanged across substitution.
	grantsCopy := append([]string(nil), proj.Grants...)
	sort.Strings(grantsCopy)
	if strings.Join(grantsCopy, ",") != "repo:read,workflow:dispatch" {
		t.Fatalf("unexpected grants mutation: %v", grantsCopy)
	}

	// Under-qualified target fails closed.
	under := []executorTargetProfile{{
		Name:         "missing-cap-worker",
		Venue:        "container-worker",
		Capabilities: []string{"linux-cpu"},
	}}
	if sel, boundary := selectEligibleTarget(proj, under); sel != nil || boundary != "capability_mismatch" {
		t.Fatalf("expected capability_mismatch, got sel=%v boundary=%q", sel, boundary)
	}

	// Ambiguous multi-target match without explicit selection fails closed.
	both := append(append([]executorTargetProfile(nil), venueA...), venueB...)
	if sel, boundary := selectEligibleTarget(proj, both); sel != nil || boundary != "supervisor_selection_required" {
		t.Fatalf("expected supervisor_selection_required, got sel=%v boundary=%q", sel, boundary)
	}
}
