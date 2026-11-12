package main

// Public synthetic invariant oracle only. No private Sidecar code, real grants,
// production caller identity, secrets or workset references are exercised.
import (
	"errors"
	"testing"
)

type fixtureRuntimeLease struct {
	Phase                  string
	Generation             uint64
	CurrentGeneration      uint64
	ProcessEpoch           uint64
	ObservedEpoch          uint64
	ExpiresUnix            int64
	NowUnix                int64
	ApprovalDigest         string
	EffectiveDigest        string
	ExternalAuthorityKnown bool
	Revoked                bool
}

// A one-time authorization snapshot is insufficient after expiry/revocation.
func fixtureSnapshotAllows(cached bool) bool { return cached }

// This model requires a fresh trusted authority check for EACH operation.
// It is a *required behavior* oracle, not a production implementation.
func fixtureCheckRuntimeLease(cached bool, s fixtureRuntimeLease) error {
	if !cached || !s.ExternalAuthorityKnown || s.Revoked ||
		s.Phase != "EFFECTIVE" || s.Generation == 0 ||
		s.Generation != s.CurrentGeneration || s.ProcessEpoch == 0 ||
		s.ObservedEpoch != s.ProcessEpoch || s.ExpiresUnix <= s.NowUnix ||
		s.ApprovalDigest == "" || s.ApprovalDigest != s.EffectiveDigest {
		return errors.New("no-fresh-effective-authority")
	}
	return nil
}

func TestSyntheticSnapshotAuthorizationIsNotAContinuingLease(t *testing.T) {
	baseline := fixtureRuntimeLease{
		Phase: "EFFECTIVE", Generation: 3, CurrentGeneration: 3,
		ProcessEpoch: 5, ObservedEpoch: 5,
		ExpiresUnix: 110, NowUnix: 100,
		ApprovalDigest: "fictional-approval", EffectiveDigest: "fictional-approval",
		ExternalAuthorityKnown: true,
	}
	if err := fixtureCheckRuntimeLease(true, baseline); err != nil {
		t.Fatal(err)
	}
	if err := fixtureCheckRuntimeLease(false, baseline); err == nil {
		t.Fatal("absent verifier authorization accepted")
	}

	negative := []struct {
		name   string
		change func(*fixtureRuntimeLease)
	}{
		{"expired", func(x *fixtureRuntimeLease) { x.NowUnix = 111 }},
		{"exact-expiry-boundary", func(x *fixtureRuntimeLease) { x.NowUnix = x.ExpiresUnix }},
		{"revoked", func(x *fixtureRuntimeLease) { x.Revoked = true }},
		{"new-policy-generation", func(x *fixtureRuntimeLease) { x.CurrentGeneration++ }},
		{"stale-effective-receipt", func(x *fixtureRuntimeLease) { x.ObservedEpoch-- }},
		{"new-process-with-old-receipt", func(x *fixtureRuntimeLease) { x.ProcessEpoch++ }},
		{"missing-epoch", func(x *fixtureRuntimeLease) { x.ProcessEpoch = 0 }},
		{"wrong-effective-digest", func(x *fixtureRuntimeLease) { x.EffectiveDigest = "fictional-other" }},
		{"missing-approval-digest", func(x *fixtureRuntimeLease) { x.ApprovalDigest = "" }},
		{"lost-external-state", func(x *fixtureRuntimeLease) { x.ExternalAuthorityKnown = false }},
		{"unknown", func(x *fixtureRuntimeLease) { x.Phase = "UNKNOWN" }},
		{"prepared-not-effective", func(x *fixtureRuntimeLease) { x.Phase = "PREPARED" }},
		{"pending-reload", func(x *fixtureRuntimeLease) { x.Phase = "APPLIED_PENDING_RELOAD" }},
		{"bootstrap-not-effective", func(x *fixtureRuntimeLease) { x.Phase = "BOOTSTRAP" }},
		{"zero-generation", func(x *fixtureRuntimeLease) { x.Generation = 0; x.CurrentGeneration = 0 }},
	}
	for _, tc := range negative {
		t.Run(tc.name, func(t *testing.T) {
			state := baseline
			tc.change(&state)
			if !fixtureSnapshotAllows(true) {
				t.Fatal("negative witness setup invalid")
			}
			if err := fixtureCheckRuntimeLease(true, state); err == nil {
				t.Fatal("stale cached allow remained effective")
			}
		})
	}
}
