package releaseguard

import (
	"strings"
	"testing"
)

func good() Manifest {
	h0 := strings.Repeat("a", 64)
	h1 := strings.Repeat("b", 64)
	h2 := strings.Repeat("c", 64)
	h3 := strings.Repeat("d", 64)
	devs := []string{"wyse-001", "wyse-002", "wyse-003", "wyse-004", "wyse-005", "wyse-006"}
	return Manifest{
		SchemaVersion: 1, Intent: "SYNTHETIC_PLAN_ONLY",
		ReleaseID: "release-001", OperationID: "op-002", PreviousOperationID: "op-001",
		PreviousState: "RELEASE_CANDIDATE", State: "SIX_NODE_STAGED_ACCEPTED",
		SourceSHA256: h0, UnsignedUKISHA256: h1,
		Witnesses: []Witness{
			{Runner: "alpha", SourceSHA256: h0, UnsignedUKISHA256: h1, Oracle: "PASS"},
			{Runner: "beta", SourceSHA256: h0, UnsignedUKISHA256: h1, Oracle: "PASS"},
		},
		RequestedBy: "build-actor", ApprovedBy: "owner-approver",
		ApprovedUnsignedSHA256: h1, ApprovalExpiresUnix: 2000, ObservedUnix: 1000,
		SignerCertSHA256: h2, SignedUKISHA256: h3,
		SignatureVerified: true, VerifiedSignedSHA256: h3,
		ArchiveID: "private-immutable-001", ArchivedSignedSHA256: h3,
		TargetHardwareID: "wyse-001", AllowedHardwareIDs: devs,
		StagedSignedSHA256: h3, ReadbackSignedSHA256: h3,
		CanaryHardwareID: "wyse-001", SignedBootOracle: true,
		UnsignedBootRefused: true, RecoverySSHOracle: true, CanaryReceiptID: "canary-001",
		AcceptedHardwareIDs: append([]string(nil), devs...),
	}
}

func TestEachAdjacentStateWithAllSyntheticProofs(t *testing.T) {
	all := []string{
		"UNBUILT", "BUILT_UNSIGNED", "REPRODUCED_UNSIGNED",
		"SIGNING_REQUESTED", "OWNER_APPROVED", "SIGNED_CANONICAL",
		"CRYPTO_VERIFIED", "ARCHIVED_IMMUTABLE", "MEDIA_STAGED",
		"READBACK_VERIFIED", "SINGLE_CANARY_BOOT_PROVEN", "RELEASE_CANDIDATE",
		"SIX_NODE_STAGED_ACCEPTED",
	}
	for i := 1; i < len(all); i++ {
		t.Run(all[i], func(t *testing.T) {
			m := good()
			m.PreviousState, m.State = all[i-1], all[i]
			if err := Validate(m); err != nil {
				t.Fatalf("valid synthetic transition refused: %v", err)
			}
			if !strings.Contains(Verdict(m), "PRODUCTION_ATTESTATION=NOT_TESTED") {
				t.Fatal("false live or production attestation claim")
			}
		})
	}
}

func TestFailClosedMutations(t *testing.T) {
	tests := []struct {
		name string
		change func(*Manifest)
	}{
		{"bad intent", func(m *Manifest) { m.Intent = "APPLY" }},
		{"unknown state", func(m *Manifest) { m.State = "IMAGINARY" }},
		{"skipped signing", func(m *Manifest) { m.PreviousState = "SIGNING_REQUESTED" }},
		{"replayed operation", func(m *Manifest) { m.PreviousOperationID = m.OperationID }},
		{"short source digest", func(m *Manifest) { m.SourceSHA256 = "abcd" }},
		{"one witness", func(m *Manifest) { m.Witnesses = m.Witnesses[:1] }},
		{"duplicate runner", func(m *Manifest) { m.Witnesses[1].Runner = "alpha" }},
		{"mismatched unsigned witness", func(m *Manifest) { m.Witnesses[1].UnsignedUKISHA256 = strings.Repeat("0", 64) }},
		{"untrusted witness", func(m *Manifest) { m.Witnesses[1].Oracle = "UNKNOWN" }},
		{"missing owner approval", func(m *Manifest) { m.ApprovedBy = "" }},
		{"stale approval", func(m *Manifest) { m.ApprovalExpiresUnix = 999 }},
		{"approved wrong hash", func(m *Manifest) { m.ApprovedUnsignedSHA256 = strings.Repeat("0", 64) }},
		{"signer cert missing", func(m *Manifest) { m.SignerCertSHA256 = "" }},
		{"signed equal unsigned", func(m *Manifest) { m.SignedUKISHA256 = m.UnsignedUKISHA256 }},
		{"crypto flag missing", func(m *Manifest) { m.SignatureVerified = false }},
		{"wrong verified hash", func(m *Manifest) { m.VerifiedSignedSHA256 = strings.Repeat("0", 64) }},
		{"archive wrong digest", func(m *Manifest) { m.ArchivedSignedSHA256 = "" }},
		{"unbound media target", func(m *Manifest) { m.TargetHardwareID = "wyse-007" }},
		{"sdX assumed identity", func(m *Manifest) { m.TargetHardwareID = "sda" }},
		{"staging mismatched", func(m *Manifest) { m.StagedSignedSHA256 = "" }},
		{"readback missing", func(m *Manifest) { m.ReadbackSignedSHA256 = "" }},
		{"canary wrong device", func(m *Manifest) { m.CanaryHardwareID = "wyse-003" }},
		{"canary unsigned allowed", func(m *Manifest) { m.UnsignedBootRefused = false }},
		{"canary SSH absent", func(m *Manifest) { m.RecoverySSHOracle = false }},
		{"canary witness absent", func(m *Manifest) { m.CanaryReceiptID = "" }},
		{"only five accepted", func(m *Manifest) { m.AcceptedHardwareIDs = m.AcceptedHardwareIDs[:5] }},
		{"duplicate accepted", func(m *Manifest) { m.AcceptedHardwareIDs[5] = "wyse-001" }},
		{"unallowlisted accepted", func(m *Manifest) { m.AcceptedHardwareIDs[5] = "wyse-007" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := good()
			tc.change(&m)
			if err := Validate(m); err == nil {
				t.Fatalf("fail-open mutation accepted: %s", tc.name)
			}
		})
	}
}
