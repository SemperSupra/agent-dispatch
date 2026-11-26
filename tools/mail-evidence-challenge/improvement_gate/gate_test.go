package improvementgate

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func ptr(e Evidence) *Evidence { return &e }
func fixture() Experiment {
	sources := []Source{
		{ID: "dev", Tenant: "alpha", AcquiredAt: "2026-05-01T00:00:00Z", Body: "Release pending."},
		{ID: "approval-de", Tenant: "alpha", AcquiredAt: "2026-05-04T00:00:00Z", Body: "Freigabe abgelehnt."},
		{ID: "approval-th", Tenant: "alpha", AcquiredAt: "2026-05-05T00:00:00Z", Body: "อนุมัติแล้ว"},
		{ID: "late", Tenant: "alpha", AcquiredAt: "2026-05-20T00:00:00Z", Body: "Approval retroactive."},
		{ID: "beta", Tenant: "beta", AcquiredAt: "2026-05-02T00:00:00Z", Body: "Private beta marker."},
	}
	for i := range sources {
		sources[i].SHA256 = sourceDigest(sources[i].Body)
	}
	devEv := Evidence{SourceID: "dev", Begin: 0, End: len(sources[0].Body)}
	deEv := Evidence{SourceID: "approval-de", Begin: 0, End: len(sources[1].Body)}
	thEv := Evidence{SourceID: "approval-th", Begin: 0, End: len([]byte(sources[2].Body))}
	dev := []Case{{ID: "D1", Family: "release", Lineage: "export-1", Tenant: "alpha", Language: "en", KnownAt: "2026-05-02T00:00:00Z", ExpectedValue: "pending", Allowed: []Evidence{devEv}}}
	held := []Case{
		{ID: "H1", Family: "approval-german", Lineage: "export-2", Tenant: "alpha", Language: "de", KnownAt: "2026-05-06T00:00:00Z", ExpectedValue: "denied", Allowed: []Evidence{deEv}},
		{ID: "H2", Family: "approval-thai", Lineage: "export-3", Tenant: "alpha", Language: "th", KnownAt: "2026-05-06T00:00:00Z", ExpectedValue: "approved", Allowed: []Evidence{thEv}},
		{ID: "H3", Family: "insurance", Lineage: "export-4", Tenant: "alpha", Language: "en", KnownAt: "2026-05-06T00:00:00Z", ExpectedValue: Unknown},
	}
	baseline := Arm{Name: "baseline", PolicySHA256: sourceDigest("baseline"),
		Dev:     []Answer{{CaseID: "D1", Value: Unknown}},
		Heldout: []Answer{{CaseID: "H1", Value: "denied", Citation: ptr(deEv)}, {CaseID: "H2", Value: Unknown}, {CaseID: "H3", Value: Unknown}}}
	candidate := Arm{Name: "candidate", PolicySHA256: sourceDigest("candidate"),
		Dev: []Answer{{CaseID: "D1", Value: "pending", Citation: ptr(devEv)}},
		Heldout: []Answer{{CaseID: "H1", Value: "denied", Citation: ptr(deEv)},
			{CaseID: "H2", Value: "approved", Citation: ptr(thEv)}, {CaseID: "H3", Value: Unknown}}}
	return Experiment{Sources: sources, Dev: dev, Heldout: held, Arms: []Arm{baseline, candidate}, Baseline: "baseline", InferenceKind: Simulated}
}
func TestDevOnlySelectionAndIndependentHeldoutScoring(t *testing.T) {
	e := fixture()
	v, err := Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	if v.SelectedOnDev != "candidate" || v.Dev["candidate"].Exact != 1 ||
		v.Heldout["candidate"].Exact != 3 || v.Heldout["baseline"].Exact != 2 ||
		v.PromotionStatus != "HOLD" || len(v.SelectedHardVetoes) != 0 || len(v.OracleSHA256) != 64 {
		t.Fatalf("unqualified promotion or invalid oracle: %+v", v)
	}
	// The candidate can lose on held-out and still be selected from dev only;
	// test outcomes cannot be used to retune the original selection decision.
	e.Arms[1].Heldout[0] = Answer{CaseID: "H1", Value: Unknown}
	e.Arms[1].Heldout[1] = Answer{CaseID: "H2", Value: Unknown}
	r, err := Evaluate(e)
	if err != nil || r.SelectedOnDev != "candidate" || r.Heldout["candidate"].Exact != 1 || r.PromotionStatus != "HOLD" {
		t.Fatalf("holdout contaminated candidate choice %+v %v", r, err)
	}
}
func TestAdversarialCitationVetoes(t *testing.T) {
	for _, tc := range []struct {
		name string
		cite Evidence
		veto string
	}{
		{"cross-tenant", Evidence{SourceID: "beta", Begin: 0, End: len("Private beta marker.")}, "CROSS_TENANT"},
		{"future-known", Evidence{SourceID: "late", Begin: 0, End: len("Approval retroactive.")}, "FUTURE_KNOWLEDGE"},
		{"wrong-span", Evidence{SourceID: "approval-th", Begin: 0, End: 1}, "SOURCE_CITATION"},
		{"wrong-occurrence", Evidence{SourceID: "dev", Begin: 0, End: len("Release pending.")}, "SOURCE_CITATION"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture()
			e.Arms[1].Heldout[1].Citation = ptr(tc.cite)
			v, err := Evaluate(e)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(v.SelectedHardVetoes, tc.veto) || v.Heldout["candidate"].Exact == 3 ||
				v.PromotionStatus != "HOLD" {
				t.Fatalf("unsafe score or promotion: %+v", v)
			}
		})
	}
}
func TestSourceTamperAndHoldoutLeakFailClosed(t *testing.T) {
	cases := []struct {
		name, why string
		mutate    func(*Experiment)
	}{
		{"source-mutated", "SOURCE_DIGEST", func(e *Experiment) { e.Sources[2].Body += "X" }},
		{"same-family", "LINEAGE_LEAKAGE", func(e *Experiment) { e.Heldout[0].Family = "release" }},
		{"same-lineage", "LINEAGE_LEAKAGE", func(e *Experiment) { e.Heldout[0].Lineage = "export-1" }},
		{"gold-cites-future", "GOLD_FUTURE_KNOWLEDGE", func(e *Experiment) { e.Heldout[0].Allowed[0].SourceID = "late" }},
		{"gold-other-tenant", "GOLD_CITATION_INVALID", func(e *Experiment) { e.Heldout[0].Allowed[0].SourceID = "beta" }},
		{"duplicate-response", "DUPLICATE_OUTPUT", func(e *Experiment) { e.Arms[1].Heldout[1].CaseID = "H1" }},
		{"missing-response", "OUTPUT_CASE_COUNT", func(e *Experiment) { e.Arms[1].Heldout = e.Arms[1].Heldout[:2] }},
		{"no-model-evidence", "INFERENCE_KIND", func(e *Experiment) { e.InferenceKind = "PROVED_REASONING" }},
		{"false-policy-digest", "POLICY_IDENTITY", func(e *Experiment) { e.Arms[1].PolicySHA256 = strings.Repeat("z", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture()
			tc.mutate(&e)
			_, err := Evaluate(e)
			if err == nil || !strings.Contains(err.Error(), tc.why) {
				t.Fatalf("missing %s: %v", tc.why, err)
			}
		})
	}
}
func TestSourceAndAnswerOrderDoNotChangeOracle(t *testing.T) {
	e := fixture()
	baseline, err := Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(e.Sources)
	slices.Reverse(e.Dev)
	slices.Reverse(e.Heldout)
	slices.Reverse(e.Arms[0].Heldout)
	slices.Reverse(e.Arms[1].Heldout)
	replay, err := Evaluate(e)
	if err != nil || !reflect.DeepEqual(baseline, replay) {
		t.Fatalf("permutation changed independent result: %+v %+v %v", baseline, replay, err)
	}
}
func TestUnknownMustAbstainWithoutCitation(t *testing.T) {
	e := fixture()
	e.Arms[1].Heldout[2].Citation = ptr(Evidence{SourceID: "beta", Begin: 0, End: 2})
	v, err := Evaluate(e)
	if err != nil {
		t.Fatal(err)
	}
	if v.Heldout["candidate"].WrongCitation != 1 || !slices.Contains(v.SelectedHardVetoes, "CROSS_TENANT") {
		t.Fatalf("fabricated unknown source accepted: %+v", v)
	}
}

func TestUnattestedModelLabelNeverQualifiesPromotion(t *testing.T) {
	e := fixture()
	e.InferenceKind = MeasuredModel
	// Duplicate semantic cases with fresh IDs are not independent model evidence.
	for i := 0; i < 30; i++ {
		c := e.Heldout[2]
		c.ID = fmt.Sprintf("extra-%02d", i)
		e.Heldout = append(e.Heldout, c)
		for j := range e.Arms {
			e.Arms[j].Heldout = append(e.Arms[j].Heldout, Answer{CaseID: c.ID, Value: Unknown})
		}
	}
	v, err := Evaluate(e)
	if err != nil || v.PromotionStatus != "HOLD" || v.Heldout["candidate"].Exact != 33 {
		t.Fatalf("claimed model label or repeated cases manufactured authority: %+v %v", v, err)
	}
}

func TestCandidateTieBreakIndependentOfArmOrder(t *testing.T) {
	e := fixture()
	other := e.Arms[1]
	other.Name = "a-candidate"
	other.PolicySHA256 = sourceDigest("other")
	e.Arms = append(e.Arms, other)
	first, err := Evaluate(e)
	if err != nil || first.SelectedOnDev != other.Name {
		t.Fatalf("unstable candidate tie: %+v %v", first, err)
	}
	slices.Reverse(e.Arms)
	again, err := Evaluate(e)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatalf("arm order changed verdict: %+v %+v %v", first, again, err)
	}
	// The baseline always wins an equal exact score.
	for i := range e.Arms {
		e.Arms[i].Dev = slices.Clone(other.Dev)
	}
	tied, err := Evaluate(e)
	if err != nil || tied.SelectedOnDev != e.Baseline {
		t.Fatalf("baseline tie changed policy: %+v %v", tied, err)
	}
}

func TestDisjointLabelsCannotHideSharedGoldSource(t *testing.T) {
	e := fixture()
	e.Heldout[0].Allowed = slices.Clone(e.Dev[0].Allowed)
	_, err := Evaluate(e)
	if err == nil || !strings.Contains(err.Error(), "TRAIN_HOLDOUT_SOURCE_LEAKAGE") {
		t.Fatalf("same source disguised by different case lineage: %v", err)
	}
}

func TestGoldRejectsPartialUTF8AndInvalidSourceText(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		mutate func(*Experiment)
	}{
		{"partial-rune-end", "GOLD_CITATION_UTF8_BOUNDARY", func(e *Experiment) { e.Heldout[1].Allowed[0].End = 1 }},
		{"partial-rune-start", "GOLD_CITATION_UTF8_BOUNDARY", func(e *Experiment) { e.Heldout[1].Allowed[0].Begin = 1 }},
		{"invalid-utf8", "SOURCE_DIGEST_OR_ID_INVALID", func(e *Experiment) {
			e.Sources[2].Body = string([]byte{255})
			e.Sources[2].SHA256 = sourceDigest(e.Sources[2].Body)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture()
			tc.mutate(&e)
			_, err := Evaluate(e)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("missing UTF-8/source guard: %v", err)
			}
		})
	}
}
