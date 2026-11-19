package main

import (
	"slices"
	"testing"
)

type lanePurpose string

const (
	purposeAccomplish lanePurpose = "ACCOMPLISH"
	purposeReconcile  lanePurpose = "RECONCILE"
	purposeDream      lanePurpose = "DREAM"
	purposeTinker     lanePurpose = "TINKER"
	purposeValidate   lanePurpose = "VALIDATE"
)

type humanPosture string

const (
	postureEngaged     humanPosture = "ENGAGED"
	postureLowCeremony humanPosture = "LOW_CEREMONY"
	postureHandoff     humanPosture = "HANDOFF_LIKELY"
	postureOffline     humanPosture = "HUMAN_OFFLINE"
)

type dagLane struct {
	ID              string
	Purpose         lanePurpose
	DependsOn       []string
	Validated       bool
	RequiresHuman   bool
	Grants          []string
	BudgetRemaining int
}

type laneDecision struct {
	LaneID           string
	Status           string // "BOUND", "WAITING_DEP", "HUMAN_GATE", "PREEMPTED_NOOP"
	CandidateOnly    bool
	EscalationFormat string
	EffectiveGrants  []string
}

func evaluateMultiLaneSchedule(
	lanes []dagLane,
	validatedLanes map[string]bool,
	criticalPathContention bool,
	posture humanPosture,
) map[string]laneDecision {
	out := make(map[string]laneDecision, len(lanes))
	for _, l := range lanes {
		grantsCopy := append([]string(nil), l.Grants...)
		escFormat := "standard"
		if posture == postureLowCeremony || posture == postureOffline {
			escFormat = "batched-exception-only"
		}
		dec := laneDecision{
			LaneID:           l.ID,
			CandidateOnly:    l.Purpose == purposeDream || l.Purpose == purposeTinker,
			EscalationFormat: escFormat,
			EffectiveGrants:  grantsCopy,
		}
		if l.RequiresHuman {
			dec.Status = "HUMAN_GATE"
			out[l.ID] = dec
			continue
		}
		depsMet := true
		for _, dep := range l.DependsOn {
			if !validatedLanes[dep] {
				depsMet = false
				break
			}
		}
		if !depsMet {
			dec.Status = "WAITING_DEP"
			out[l.ID] = dec
			continue
		}
		if (l.Purpose == purposeDream || l.Purpose == purposeTinker) && (criticalPathContention || l.BudgetRemaining <= 0) {
			dec.Status = "PREEMPTED_NOOP"
			out[l.ID] = dec
			continue
		}
		if l.BudgetRemaining <= 0 {
			dec.Status = "PREEMPTED_NOOP"
			out[l.ID] = dec
			continue
		}
		dec.Status = "BOUND"
		out[l.ID] = dec
	}
	return out
}

func TestMultiLaneDAGDependencyReleaseAndDreamPreemptionOracles(t *testing.T) {
	lanes := []dagLane{
		{
			ID:              "lane-a-core",
			Purpose:         purposeAccomplish,
			Grants:          []string{"repo:read", "workflow:dispatch"},
			BudgetRemaining: 1,
		},
		{
			ID:              "lane-b-followup",
			Purpose:         purposeAccomplish,
			DependsOn:       []string{"lane-a-core"},
			Grants:          []string{"repo:read", "workflow:dispatch"},
			BudgetRemaining: 1,
		},
		{
			ID:              "lane-c-release-signoff",
			Purpose:         purposeValidate,
			RequiresHuman:   true,
			Grants:          []string{"repo:read"},
			BudgetRemaining: 1,
		},
		{
			ID:              "lane-d-auxiliary-explore",
			Purpose:         purposeDream,
			Grants:          []string{"repo:read"},
			BudgetRemaining: 1,
		},
	}

	t.Run("critical_path_contention_preempts_dream_while_ready_accomplish_binds", func(t *testing.T) {
		validated := map[string]bool{}
		decisions := evaluateMultiLaneSchedule(lanes, validated, true, postureEngaged)

		if decisions["lane-a-core"].Status != "BOUND" || decisions["lane-a-core"].CandidateOnly {
			t.Fatalf("expected lane-a-core BOUND non-candidate, got %+v", decisions["lane-a-core"])
		}
		if decisions["lane-b-followup"].Status != "WAITING_DEP" {
			t.Fatalf("expected lane-b-followup WAITING_DEP, got %+v", decisions["lane-b-followup"])
		}
		if decisions["lane-c-release-signoff"].Status != "HUMAN_GATE" {
			t.Fatalf("expected lane-c-release-signoff HUMAN_GATE, got %+v", decisions["lane-c-release-signoff"])
		}
		if decisions["lane-d-auxiliary-explore"].Status != "PREEMPTED_NOOP" || !decisions["lane-d-auxiliary-explore"].CandidateOnly {
			t.Fatalf("expected lane-d-auxiliary-explore PREEMPTED_NOOP candidate-only, got %+v", decisions["lane-d-auxiliary-explore"])
		}
	})

	t.Run("upstream_validation_releases_dependent_lane_and_idle_allows_candidate_only_dream", func(t *testing.T) {
		validated := map[string]bool{"lane-a-core": true}
		decisions := evaluateMultiLaneSchedule(lanes, validated, false, postureOffline)

		if decisions["lane-b-followup"].Status != "BOUND" {
			t.Fatalf("expected lane-b-followup released to BOUND, got %+v", decisions["lane-b-followup"])
		}
		if decisions["lane-d-auxiliary-explore"].Status != "BOUND" || !decisions["lane-d-auxiliary-explore"].CandidateOnly {
			t.Fatalf("expected dream lane BOUND as candidate-only when idle, got %+v", decisions["lane-d-auxiliary-explore"])
		}
		// Human posture changes presentation only; it never alters authority grants or bypasses HUMAN_GATE.
		if decisions["lane-c-release-signoff"].Status != "HUMAN_GATE" {
			t.Fatalf("HUMAN_OFFLINE posture must never bypass HUMAN_GATE, got %+v", decisions["lane-c-release-signoff"])
		}
		if !slices.Equal(decisions["lane-b-followup"].EffectiveGrants, []string{"repo:read", "workflow:dispatch"}) {
			t.Fatalf("unexpected grant mutation: %v", decisions["lane-b-followup"].EffectiveGrants)
		}
		if decisions["lane-c-release-signoff"].EscalationFormat != "batched-exception-only" {
			t.Fatalf("expected batched-exception-only presentation for offline posture, got %q", decisions["lane-c-release-signoff"].EscalationFormat)
		}
	})
}
