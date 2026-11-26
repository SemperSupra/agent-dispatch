package pipeline

import (
	"testing"

	evidence "sempersupra/mail-evidence-challenge"
	temporallogic "sempersupra/mail-evidence-challenge/temporal_logic"
)

func TestTemporalAssessmentBindsScopeAndReviewClock(t *testing.T) {
	const (
		first  = "2026-05-01T00:00:00Z"
		second = "2026-05-02T00:00:00Z"
		review = "2026-05-04T00:00:00Z"
	)
	observations := []evidence.Observation{
		{ID: "old", Archive: "a", Locator: "1", Tenant: "alpha", Group: "gate", CapturedAt: first, Raw: "The gate is open."},
		{ID: "new", Archive: "a", Locator: "2", Tenant: "alpha", Group: "gate", CapturedAt: second, Raw: "Correction: the gate is closed."},
	}
	store := temporallogic.Store{}
	for i := range observations {
		observation := &observations[i]
		observation.SHA256 = digest([]byte(observation.Raw))
		store.Sources = append(store.Sources, temporallogic.Source{
			ID: observation.ID, Tenant: observation.Tenant, Raw: observation.Raw, SHA256: observation.SHA256,
			Lineage: "gate-ledger", AuthoredAt: observation.CapturedAt, AcquiredAt: observation.CapturedAt,
		})
	}
	store.Claims = []temporallogic.Claim{
		{ID: "open", SourceID: "old", Predicate: "gate-open", Modality: "actual", Quote: observations[0].Raw, ValidFrom: first, Polarity: temporallogic.Supports},
		{ID: "close", SourceID: "new", Predicate: "gate-open", Modality: "actual", Quote: observations[1].Raw, ValidFrom: second, Polarity: temporallogic.Refutes},
	}
	revisions := []temporallogic.Revision{
		{ID: "review", PredecessorID: "open", SuccessorID: "close", Quote: observations[1].Raw, RecordedAt: review},
	}
	dev := evidence.Observation{ID: "dev", Archive: "d", Locator: "1", Tenant: "alpha", Group: "gate", CapturedAt: first, Raw: "Development scope."}
	dev.SHA256 = digest([]byte(dev.Raw))
	session, err := New(evidence.Ledger{Schema: evidence.Schema, Observations: append(observations, dev)},
		Split{DevIDs: []string{"dev"}, HeldoutIDs: []string{"new", "old"}})
	if err != nil {
		t.Fatal(err)
	}
	query := task("T", Heldout, "gate", "gate-open", second, "en", "Is the gate open?")
	before, err := session.AssessTemporal(query, second, store, revisions)
	if err != nil || len(before.Applied) != 0 || len(before.Assessment.Beliefs) != 1 ||
		before.Assessment.Beliefs[0].Status != temporallogic.Both {
		t.Fatalf("unexpected assessment before review: %+v, %v", before, err)
	}
	query.KnownAt = review
	after, err := session.AssessTemporal(query, second, store, revisions)
	if err != nil || len(after.Applied) != 1 || len(after.Assessment.Beliefs) != 1 ||
		after.Assessment.Beliefs[0].Status != temporallogic.Refuted {
		t.Fatalf("unexpected assessment after review: %+v, %v", after, err)
	}
	query.KnownAt = first
	if _, err := session.AssessTemporal(query, first, store, revisions); err == nil || err.Error() != "TEMPORAL_SOURCE_SCOPE_MISMATCH" {
		t.Fatalf("future source accepted: %v", err)
	}
	query.KnownAt = review
	store.Sources[0].Raw = "fabricated"
	if _, err := session.AssessTemporal(query, second, store, revisions); err == nil || err.Error() != "TEMPORAL_SOURCE_BINDING_MISMATCH" {
		t.Fatalf("altered source accepted: %v", err)
	}
}
