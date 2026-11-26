package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// StageRArmPacket models a synthetic Stage-R inner arm packet and its outer receipt.
type StageRArmPacket struct {
	Arm                string
	AssignmentID       string
	RunID              string
	SourceSHA          string
	PlanSHA256         string
	ProviderImageDigest string
	ConfigSHA256       string
	ScienceClass       string
	Ciphertext         []byte
	ReceiptHash        string
	Attempted          int
	Succeeded          int
	Failed             int
	TerminalState      string
}

type StageROuterManifest struct {
	AssignmentID        string
	RunID               string
	SourceSHA           string
	ProviderImageDigest string
	ConfigSHA256        string
	ExpectedArms        map[string]string // arm -> plan_sha256
}

// VerifyStageRPair enforces fail-closed synthetic Stage-R pair verification invariants:
// 1. Both "reference" and "treatment" arms must be present with distinct plan digests.
// 2. ScienceClass must not claim promoted/blind status from a synthetic fixture.
// 3. Outer identity (assignment, run, source SHA, image digest, config hash) must match every inner arm.
// 4. Ciphertext SHA-256 must match the arm receipt hash.
// 5. Commit target must use atomic no-replace semantics (existing output target refuses overwrite).
func VerifyStageRPair(manifest StageROuterManifest, arms map[string]StageRArmPacket, targetExists bool) (string, error) {
	if targetExists {
		return "HOLD_OUTPUT_ALREADY_EXISTS", nil
	}
	if len(arms) != 2 {
		return "HOLD_MISSING_ARM", nil
	}
	ref, hasRef := arms["reference"]
	treat, hasTreat := arms["treatment"]
	if !hasRef || !hasTreat {
		return "HOLD_MISSING_ARM", nil
	}
	if ref.PlanSHA256 == "" || treat.PlanSHA256 == "" || ref.PlanSHA256 == treat.PlanSHA256 {
		return "HOLD_CROSS_ARM_PLAN_COLLISION", nil
	}
	for armName, pkt := range arms {
		if pkt.Arm != armName {
			return "HOLD_INNER_ARM_MISMATCH", nil
		}
		if pkt.ScienceClass != "SYNTHETIC_TRANSPORT_ONLY" {
			return "HOLD_UNPROMOTED_SCIENCE_CLASS", nil
		}
		if pkt.AssignmentID != manifest.AssignmentID ||
			pkt.RunID != manifest.RunID ||
			pkt.SourceSHA != manifest.SourceSHA ||
			pkt.ProviderImageDigest != manifest.ProviderImageDigest ||
			pkt.ConfigSHA256 != manifest.ConfigSHA256 {
			return "HOLD_OUTER_INNER_IDENTITY_DRIFT", nil
		}
		if pkt.PlanSHA256 != manifest.ExpectedArms[armName] {
			return "HOLD_PLAN_DIGEST_MISMATCH", nil
		}
		sum := sha256.Sum256(pkt.Ciphertext)
		if hex.EncodeToString(sum[:]) != pkt.ReceiptHash {
			return "HOLD_CIPHERTEXT_RECEIPT_MISMATCH", nil
		}
		if pkt.Attempted <= 0 || pkt.Succeeded+pkt.Failed != pkt.Attempted {
			return "HOLD_ACCOUNTING_MISMATCH", nil
		}
	}
	return "STAGE_R_PAIR_VERIFIED", nil
}

// XyOpsClockCandidate models a read-only clock preview definition.
type XyOpsClockCandidate struct {
	TaskID         string
	Enabled        bool
	TriggerType    string
	Timezone       string
	HasCondition   bool
	HasEvaluator   bool
	AllowedFields  map[string]bool
	ObservedFields []string
}

// PreviewXyOpsClockGuard enforces fail-closed clock preview validation:
// - Rejects unknown/widened fields.
// - Rejects non-clock triggers or floating timezones.
// - Requires an explicit evaluator whenever a condition watch is attached.
// - Requires disabled preview posture before owner cutover.
func PreviewXyOpsClockGuard(c XyOpsClockCandidate) string {
	if strings.TrimSpace(c.TaskID) == "" || strings.ContainsAny(c.TaskID, "/\\..") {
		return "HOLD_INVALID_TASK_ID"
	}
	if c.Enabled {
		return "HOLD_LIVE_CLOCK_ENABLED_BEFORE_CUTOVER"
	}
	if c.TriggerType != "calendar" && c.TriggerType != "one-shot" {
		return "HOLD_NON_CLOCK_TRIGGER"
	}
	if strings.TrimSpace(c.Timezone) == "" || c.Timezone == "floating" {
		return "HOLD_FLOATING_TIMEZONE"
	}
	for _, f := range c.ObservedFields {
		if !c.AllowedFields[f] {
			return "HOLD_WIDENED_SCHEMA_FIELD"
		}
	}
	if c.HasCondition && !c.HasEvaluator {
		return "HOLD_CONDITION_WITHOUT_EVALUATOR"
	}
	return "CLOCK_PREVIEW_ADMISSIBLE"
}

func TestStageRPairInnerVerificationOracle(t *testing.T) {
	refCipher := []byte(`{"arm":"reference","state":"RETRIEVAL_PASS"}`)
	treatCipher := []byte(`{"arm":"treatment","state":"RETRIEVAL_PASS"}`)
	refSum := sha256.Sum256(refCipher)
	treatSum := sha256.Sum256(treatCipher)

	manifest := StageROuterManifest{
		AssignmentID:        "assign-stage-r-01",
		RunID:               "9001",
		SourceSHA:           strings.Repeat("a", 40),
		ProviderImageDigest: "sha256:" + strings.Repeat("b", 64),
		ConfigSHA256:        strings.Repeat("c", 64),
		ExpectedArms: map[string]string{
			"reference": strings.Repeat("1", 64),
			"treatment": strings.Repeat("2", 64),
		},
	}

	validArms := func() map[string]StageRArmPacket {
		return map[string]StageRArmPacket{
			"reference": {
				Arm:                 "reference",
				AssignmentID:        manifest.AssignmentID,
				RunID:               manifest.RunID,
				SourceSHA:           manifest.SourceSHA,
				PlanSHA256:          strings.Repeat("1", 64),
				ProviderImageDigest: manifest.ProviderImageDigest,
				ConfigSHA256:        manifest.ConfigSHA256,
				ScienceClass:        "SYNTHETIC_TRANSPORT_ONLY",
				Ciphertext:          refCipher,
				ReceiptHash:         hex.EncodeToString(refSum[:]),
				Attempted:           1,
				Succeeded:           1,
				Failed:              0,
				TerminalState:       "RETRIEVAL_PASS",
			},
			"treatment": {
				Arm:                 "treatment",
				AssignmentID:        manifest.AssignmentID,
				RunID:               manifest.RunID,
				SourceSHA:           manifest.SourceSHA,
				PlanSHA256:          strings.Repeat("2", 64),
				ProviderImageDigest: manifest.ProviderImageDigest,
				ConfigSHA256:        manifest.ConfigSHA256,
				ScienceClass:        "SYNTHETIC_TRANSPORT_ONLY",
				Ciphertext:          treatCipher,
				ReceiptHash:         hex.EncodeToString(treatSum[:]),
				Attempted:           1,
				Succeeded:           1,
				Failed:              0,
				TerminalState:       "RETRIEVAL_PASS",
			},
		}
	}

	if status, err := VerifyStageRPair(manifest, validArms(), false); err != nil || status != "STAGE_R_PAIR_VERIFIED" {
		t.Fatalf("expected STAGE_R_PAIR_VERIFIED, got %s (err=%v)", status, err)
	}

	// Atomic no-replace refusal when target output directory already exists
	if status, _ := VerifyStageRPair(manifest, validArms(), true); status != "HOLD_OUTPUT_ALREADY_EXISTS" {
		t.Fatalf("expected HOLD_OUTPUT_ALREADY_EXISTS, got %s", status)
	}

	// Cross-arm swap refusal
	swapped := validArms()
	tmp := swapped["treatment"]
	tmp.Arm = "reference"
	swapped["treatment"] = tmp
	if status, _ := VerifyStageRPair(manifest, swapped, false); status != "HOLD_INNER_ARM_MISMATCH" {
		t.Fatalf("expected HOLD_INNER_ARM_MISMATCH, got %s", status)
	}

	// Unpromoted science class refusal
	unpromoted := validArms()
	ref := unpromoted["reference"]
	ref.ScienceClass = "BLIND_EMPIRICAL_V1"
	unpromoted["reference"] = ref
	if status, _ := VerifyStageRPair(manifest, unpromoted, false); status != "HOLD_UNPROMOTED_SCIENCE_CLASS" {
		t.Fatalf("expected HOLD_UNPROMOTED_SCIENCE_CLASS, got %s", status)
	}
}

func TestXyOpsClockPreviewGuardOracle(t *testing.T) {
	allowed := map[string]bool{
		"task_id":      true,
		"enabled":      true,
		"trigger_type": true,
		"timezone":     true,
		"schedule":     true,
	}

	valid := XyOpsClockCandidate{
		TaskID:         "6aa1197a06ac81919c7a2a5f77cd7935",
		Enabled:        false,
		TriggerType:    "calendar",
		Timezone:       "Europe/Berlin",
		HasCondition:   false,
		HasEvaluator:   false,
		AllowedFields:  allowed,
		ObservedFields: []string{"task_id", "enabled", "trigger_type", "timezone", "schedule"},
	}

	if got := PreviewXyOpsClockGuard(valid); got != "CLOCK_PREVIEW_ADMISSIBLE" {
		t.Fatalf("expected CLOCK_PREVIEW_ADMISSIBLE, got %s", got)
	}

	enabled := valid
	enabled.Enabled = true
	if got := PreviewXyOpsClockGuard(enabled); got != "HOLD_LIVE_CLOCK_ENABLED_BEFORE_CUTOVER" {
		t.Fatalf("expected HOLD_LIVE_CLOCK_ENABLED_BEFORE_CUTOVER, got %s", got)
	}

	floating := valid
	floating.Timezone = "floating"
	if got := PreviewXyOpsClockGuard(floating); got != "HOLD_FLOATING_TIMEZONE" {
		t.Fatalf("expected HOLD_FLOATING_TIMEZONE, got %s", got)
	}

	widened := valid
	widened.ObservedFields = append([]string{}, valid.ObservedFields...)
	widened.ObservedFields = append(widened.ObservedFields, "shell_command")
	if got := PreviewXyOpsClockGuard(widened); got != "HOLD_WIDENED_SCHEMA_FIELD" {
		t.Fatalf("expected HOLD_WIDENED_SCHEMA_FIELD, got %s", got)
	}

	condNoEval := valid
	condNoEval.HasCondition = true
	condNoEval.HasEvaluator = false
	if got := PreviewXyOpsClockGuard(condNoEval); got != "HOLD_CONDITION_WITHOUT_EVALUATOR" {
		t.Fatalf("expected HOLD_CONDITION_WITHOUT_EVALUATOR, got %s", got)
	}
}
