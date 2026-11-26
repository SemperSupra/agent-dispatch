// Package improvementgate is an independent, source-anchored evaluator for
// synthetic email-intelligence candidates. It never trains or promotes actors.
// A passing *evaluation contract* is not evidence that model inference ran.
package improvementgate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
	"unicode/utf8"
)

const (
	Unknown       = "UNKNOWN"
	Simulated     = "SIMULATED"
	MeasuredModel = "MEASURED_MODEL"
)

type Source struct {
	ID, Tenant, AcquiredAt, Body, SHA256 string
}
type Evidence struct {
	SourceID   string
	Begin, End int // Half-open UTF-8 byte offsets in original source body.
}
type Case struct {
	ID, Family, Lineage, Tenant, Language, KnownAt, ExpectedValue string
	Allowed                                                       []Evidence // Independently authored exact source-occurrence + span oracle.
}
type Answer struct {
	CaseID, Value string
	Citation      *Evidence // nil for an explicitly unsupported/unknown answer.
}
type Arm struct {
	Name, PolicySHA256 string
	Dev, Heldout       []Answer
}
type Experiment struct {
	Sources       []Source
	Dev, Heldout  []Case
	Arms          []Arm
	Baseline      string
	InferenceKind string // Explicitly SIMULATED or MEASURED_MODEL.
}
type Statistics struct {
	Total, Exact, WrongValue, WrongCitation, CrossTenant, FutureKnowledge, Abstained int
}
type Verdict struct {
	Schema, OracleSHA256, InferenceKind, SelectedOnDev string
	Dev, Heldout                                       map[string]Statistics
	SelectedHardVetoes                                 []string
	PromotionStatus                                    string // HOLD: no independent execution or policy custody attestation.
}

func sourceDigest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}
func validDigest(d string) bool {
	if len(d) != 64 {
		return false
	}
	_, err := hex.DecodeString(d)
	return err == nil && d == sourceDigestFromHex(d)
}
func sourceDigestFromHex(h string) string {
	// DecodeString accepts mixed case; the contract requires canonical lower-case.
	decoded, _ := hex.DecodeString(h)
	return hex.EncodeToString(decoded)
}
func instant(t string) (time.Time, error) {
	v, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return v, errors.New("INVALID_CLOCK")
	}
	return v, nil
}
func snapshotDigest(e Experiment) string {
	type oracle struct {
		Sources      []Source
		Dev, Heldout []Case
	}
	copySource := slices.Clone(e.Sources)
	copyDev := slices.Clone(e.Dev)
	copyHeldout := slices.Clone(e.Heldout)
	sort.Slice(copySource, func(i, j int) bool { return copySource[i].ID < copySource[j].ID })
	sort.Slice(copyDev, func(i, j int) bool { return copyDev[i].ID < copyDev[j].ID })
	sort.Slice(copyHeldout, func(i, j int) bool { return copyHeldout[i].ID < copyHeldout[j].ID })
	// Sort permitted citations in detached case copies; input is never mutated.
	for _, group := range [][]Case{copyDev, copyHeldout} {
		for i := range group {
			group[i].Allowed = slices.Clone(group[i].Allowed)
			sort.Slice(group[i].Allowed, func(a, b int) bool {
				x, y := group[i].Allowed[a], group[i].Allowed[b]
				if x.SourceID != y.SourceID {
					return x.SourceID < y.SourceID
				}
				if x.Begin != y.Begin {
					return x.Begin < y.Begin
				}
				return x.End < y.End
			})
		}
	}
	encoded, _ := json.Marshal(oracle{copySource, copyDev, copyHeldout})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func verifyCases(e Experiment) (map[string]Source, error) {
	if e.InferenceKind != Simulated && e.InferenceKind != MeasuredModel {
		return nil, errors.New("INFERENCE_KIND_REQUIRED")
	}
	if len(e.Dev) == 0 || len(e.Heldout) == 0 || len(e.Arms) < 2 {
		return nil, errors.New("DISJOINT_COMPARISON_REQUIRED")
	}
	sources := make(map[string]Source, len(e.Sources))
	for _, s := range e.Sources {
		if s.ID == "" || s.Tenant == "" || !utf8.ValidString(s.Body) || s.SHA256 != sourceDigest(s.Body) {
			return nil, errors.New("SOURCE_DIGEST_OR_ID_INVALID")
		}
		if _, err := instant(s.AcquiredAt); err != nil {
			return nil, err
		}
		if _, duplicate := sources[s.ID]; duplicate {
			return nil, errors.New("SOURCE_OCCURRENCE_COLLISION")
		}
		sources[s.ID] = s
	}
	ids := map[string]bool{}
	devFamilies := map[string]bool{}
	devLineages := map[string]bool{}
	devCitedSources := map[string]bool{}
	for partition, cases := range [][]Case{e.Dev, e.Heldout} {
		for _, c := range cases {
			if c.ID == "" || c.Family == "" || c.Lineage == "" || c.Tenant == "" || c.ExpectedValue == "" ||
				(c.Language != "en" && c.Language != "de" && c.Language != "th") {
				return nil, errors.New("GOLD_CASE_INVALID")
			}
			if ids[c.ID] {
				return nil, errors.New("TRAIN_HOLDOUT_ID_COLLISION")
			}
			ids[c.ID] = true
			known, err := instant(c.KnownAt)
			if err != nil {
				return nil, err
			}
			if partition == 0 {
				devFamilies[c.Family] = true
				devLineages[c.Lineage] = true
			} else if devFamilies[c.Family] || devLineages[c.Lineage] {
				return nil, errors.New("TRAIN_HOLDOUT_LINEAGE_LEAKAGE")
			}
			if (c.ExpectedValue == Unknown) != (len(c.Allowed) == 0) {
				return nil, errors.New("GOLD_UNSUPPORTED_MISMATCH")
			}
			for _, ev := range c.Allowed {
				s, ok := sources[ev.SourceID]
				if !ok || s.Tenant != c.Tenant || ev.Begin < 0 || ev.End <= ev.Begin || ev.End > len(s.Body) {
					return nil, errors.New("GOLD_CITATION_INVALID")
				}
				// Byte offsets must delimit complete UTF-8 code points, not fragments.
				if !utf8.RuneStart(s.Body[ev.Begin]) || (ev.End < len(s.Body) && !utf8.RuneStart(s.Body[ev.End])) {
					return nil, errors.New("GOLD_CITATION_UTF8_BOUNDARY")
				}
				// Even differently labeled cases must not share a gold source occurrence.
				// This does not prove that the wider retrieval context is disjoint.
				if partition == 0 {
					devCitedSources[ev.SourceID] = true
				} else if devCitedSources[ev.SourceID] {
					return nil, errors.New("TRAIN_HOLDOUT_SOURCE_LEAKAGE")
				}
				acquired, _ := instant(s.AcquiredAt)
				if acquired.After(known) {
					return nil, errors.New("GOLD_FUTURE_KNOWLEDGE")
				}
			}
		}
	}
	return sources, nil
}
func measure(cases []Case, answers []Answer, sources map[string]Source) (Statistics, error) {
	if len(answers) != len(cases) {
		return Statistics{}, errors.New("OUTPUT_CASE_COUNT_MISMATCH")
	}
	got := make(map[string]Answer, len(answers))
	for _, a := range answers {
		if _, seen := got[a.CaseID]; seen || a.CaseID == "" {
			return Statistics{}, errors.New("DUPLICATE_OUTPUT_ID")
		}
		got[a.CaseID] = a
	}
	stats := Statistics{Total: len(cases)}
	for _, c := range cases {
		a, ok := got[c.ID]
		if !ok {
			return Statistics{}, errors.New("MISSING_OUTPUT_ID")
		}
		valueCorrect := a.Value == c.ExpectedValue
		if !valueCorrect {
			stats.WrongValue++
		}
		citationCorrect := false
		if a.Citation == nil {
			citationCorrect = c.ExpectedValue == Unknown
			if a.Value == Unknown {
				stats.Abstained++
			}
		} else {
			s, ok := sources[a.Citation.SourceID]
			if ok {
				if s.Tenant != c.Tenant {
					stats.CrossTenant++
				}
				when, _ := instant(s.AcquiredAt)
				at, _ := instant(c.KnownAt)
				if when.After(at) {
					stats.FutureKnowledge++
				}
			}
			for _, allowed := range c.Allowed {
				if *a.Citation == allowed {
					citationCorrect = true
					break
				}
			}
		}
		if !citationCorrect {
			stats.WrongCitation++
		}
		if valueCorrect && citationCorrect {
			stats.Exact++
		}
	}
	return stats, nil
}

// Evaluate derives every score from independently authored gold and responses;
// it ignores any asserted agent reward, confidence or self-reported success.
func Evaluate(e Experiment) (Verdict, error) {
	sources, err := verifyCases(e)
	if err != nil {
		return Verdict{}, err
	}
	result := Verdict{Schema: "mail-improvement-independent-gate/v1", OracleSHA256: snapshotDigest(e),
		InferenceKind: e.InferenceKind, Dev: map[string]Statistics{}, Heldout: map[string]Statistics{}, PromotionStatus: "HOLD"}
	seen := map[string]bool{}
	for _, arm := range e.Arms {
		if arm.Name == "" || seen[arm.Name] || !validDigest(arm.PolicySHA256) {
			return Verdict{}, errors.New("POLICY_IDENTITY_INVALID")
		}
		seen[arm.Name] = true
		d, err := measure(e.Dev, arm.Dev, sources)
		if err != nil {
			return Verdict{}, fmt.Errorf("%s dev: %w", arm.Name, err)
		}
		h, err := measure(e.Heldout, arm.Heldout, sources)
		if err != nil {
			return Verdict{}, fmt.Errorf("%s heldout: %w", arm.Name, err)
		}
		result.Dev[arm.Name] = d
		result.Heldout[arm.Name] = h
	}
	if !seen[e.Baseline] {
		return Verdict{}, errors.New("BASELINE_ARM_MISSING")
	}
	selected := e.Baseline
	for _, arm := range e.Arms {
		// Baseline wins a tie; ties above baseline use stable name ordering.
		score, best := result.Dev[arm.Name].Exact, result.Dev[selected].Exact
		if score > best || (score == best && selected != e.Baseline && arm.Name < selected) {
			selected = arm.Name
		}
	}
	result.SelectedOnDev = selected
	chosen := result.Heldout[selected]
	if chosen.CrossTenant > 0 {
		result.SelectedHardVetoes = append(result.SelectedHardVetoes, "CROSS_TENANT")
	}
	if chosen.FutureKnowledge > 0 {
		result.SelectedHardVetoes = append(result.SelectedHardVetoes, "FUTURE_KNOWLEDGE")
	}
	if chosen.WrongCitation > 0 {
		result.SelectedHardVetoes = append(result.SelectedHardVetoes, "SOURCE_CITATION")
	}
	// Neither a claimed inference kind nor a count of cases proves independent
	// model execution, source partition isolation or policy identity. Keep the
	// research evaluator incapable of granting even a promotion-review status.
	// A separate receipt-bound qualification authority must decide promotion.
	return result, nil
}
