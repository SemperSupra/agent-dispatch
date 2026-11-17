// Package releaseguard validates a *synthetic plan-only* Wyse recovery
// release state transition. It performs no signing, I/O, hardware or attestation.
package releaseguard

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type Witness struct {
	Runner             string `json:"runner"`
	SourceSHA256       string `json:"source_sha256"`
	UnsignedUKISHA256  string `json:"unsigned_uki_sha256"`
	Oracle             string `json:"oracle"`
}

type Manifest struct {
	SchemaVersion          int       `json:"schema_version"`
	Intent                 string    `json:"intent"`
	ReleaseID              string    `json:"release_id"`
	OperationID            string    `json:"operation_id"`
	PreviousOperationID    string    `json:"previous_operation_id"`
	PreviousState          string    `json:"previous_state"`
	State                  string    `json:"state"`
	SourceSHA256           string    `json:"source_sha256"`
	UnsignedUKISHA256      string    `json:"unsigned_uki_sha256"`
	Witnesses              []Witness `json:"witnesses"`
	RequestedBy            string    `json:"requested_by"`
	ApprovedBy             string    `json:"approved_by"`
	ApprovedUnsignedSHA256 string    `json:"approved_unsigned_sha256"`
	ApprovalExpiresUnix    int64     `json:"approval_expires_unix"`
	ObservedUnix           int64     `json:"observed_unix"`
	SignerCertSHA256       string    `json:"signer_cert_sha256"`
	SignedUKISHA256        string    `json:"signed_uki_sha256"`
	SignatureVerified      bool      `json:"signature_verified"`
	VerifiedSignedSHA256   string    `json:"verified_signed_sha256"`
	ArchiveID              string    `json:"archive_id"`
	ArchivedSignedSHA256   string    `json:"archived_signed_sha256"`
	TargetHardwareID       string    `json:"target_hardware_id"`
	AllowedHardwareIDs     []string  `json:"allowed_hardware_ids"`
	StagedSignedSHA256     string    `json:"staged_signed_sha256"`
	ReadbackSignedSHA256   string    `json:"readback_signed_sha256"`
	CanaryHardwareID       string    `json:"canary_hardware_id"`
	SignedBootOracle       bool      `json:"signed_boot_oracle"`
	UnsignedBootRefused    bool      `json:"unsigned_boot_refused"`
	RecoverySSHOracle      bool      `json:"recovery_ssh_oracle"`
	CanaryReceiptID        string    `json:"canary_receipt_id"`
	AcceptedHardwareIDs    []string  `json:"accepted_hardware_ids"`
}

var stages = []string{
	"UNBUILT", "BUILT_UNSIGNED", "REPRODUCED_UNSIGNED",
	"SIGNING_REQUESTED", "OWNER_APPROVED", "SIGNED_CANONICAL",
	"CRYPTO_VERIFIED", "ARCHIVED_IMMUTABLE", "MEDIA_STAGED",
	"READBACK_VERIFIED", "SINGLE_CANARY_BOOT_PROVEN",
	"RELEASE_CANDIDATE", "SIX_NODE_STAGED_ACCEPTED",
}
var digestRE = regexp.MustCompile("^[0-9a-f]{64}$")
var idRE = regexp.MustCompile("^[A-Za-z0-9._:-]{3,128}$")

func stageIndex(s string) int {
	for i, v := range stages {
		if s == v { return i }
	}
	return -1
}

func validDigest(v string) bool { return digestRE.MatchString(v) }
func validID(v string) bool { return idRE.MatchString(v) }

func fail(s string) error { return errors.New("DENIED:" + s) }

func contains(xs []string, v string) bool {
	for _, x := range xs { if x == v { return true } }
	return false
}

// Validate checks a *declared* transition and conditional proof fields.
// The inputs are untrusted synthetic text. A PASS is NOT cryptographic
// verification, approval, hardware attestation or permission to apply.
func Validate(m Manifest) error {
	if m.SchemaVersion != 1 || m.Intent != "SYNTHETIC_PLAN_ONLY" {
		return fail("SCHEMA_OR_INTENT")
	}
	if !validID(m.ReleaseID) || !validID(m.OperationID) ||
		(m.PreviousOperationID != "" && m.OperationID == m.PreviousOperationID) {
		return fail("IDENTITY_OR_REPLAY")
	}
	prev, next := stageIndex(m.PreviousState), stageIndex(m.State)
	if prev < 0 || next != prev+1 {
		return fail("INVALID_STATE_TRANSITION")
	}
	if !validDigest(m.SourceSHA256) || !validDigest(m.UnsignedUKISHA256) {
		return fail("UNSIGNED_INPUT_DIGEST")
	}
	// A plan cannot promote a release on an invented "successful" build
	// unless two unique witnesses agree on exactly the same source/UKI bytes.
	if next >= stageIndex("REPRODUCED_UNSIGNED") {
		if len(m.Witnesses) != 2 { return fail("TWO_INDEPENDENT_WITNESSES") }
		seen := map[string]bool{}
		for _, w := range m.Witnesses {
			if !validID(w.Runner) || seen[w.Runner] || w.Oracle != "PASS" ||
				w.SourceSHA256 != m.SourceSHA256 ||
				w.UnsignedUKISHA256 != m.UnsignedUKISHA256 {
				return fail("INCONSISTENT_UNSIGNED_WITNESS")
			}
			seen[w.Runner] = true
		}
	}
	if next >= stageIndex("SIGNING_REQUESTED") && !validID(m.RequestedBy) {
		return fail("SIGNING_REQUEST_UNBOUND")
	}
	if next >= stageIndex("OWNER_APPROVED") {
		if !validID(m.ApprovedBy) ||
			m.ApprovedUnsignedSHA256 != m.UnsignedUKISHA256 ||
			m.ObservedUnix <= 0 || m.ApprovalExpiresUnix <= m.ObservedUnix {
			return fail("APPROVAL_MISSING_STALE_OR_WRONG_INPUT")
		}
	}
	if next >= stageIndex("SIGNED_CANONICAL") {
		if !validDigest(m.SignerCertSHA256) ||
			!validDigest(m.SignedUKISHA256) ||
			m.SignedUKISHA256 == m.UnsignedUKISHA256 {
			return fail("SIGNER_OR_SIGNED_DIGEST")
		}
	}
	if next >= stageIndex("CRYPTO_VERIFIED") {
		if !m.SignatureVerified || m.VerifiedSignedSHA256 != m.SignedUKISHA256 {
			return fail("SIGNATURE_VERIFICATION_RECEIPT")
		}
	}
	if next >= stageIndex("ARCHIVED_IMMUTABLE") {
		if !validID(m.ArchiveID) || m.ArchivedSignedSHA256 != m.SignedUKISHA256 {
			return fail("ARCHIVE_PROVENANCE_OR_READBACK")
		}
	}
	if next >= stageIndex("MEDIA_STAGED") {
		if !validID(m.TargetHardwareID) ||
			strings.HasPrefix(m.TargetHardwareID, "sd") ||
			!contains(m.AllowedHardwareIDs, m.TargetHardwareID) ||
			m.StagedSignedSHA256 != m.SignedUKISHA256 {
			return fail("MEDIA_TARGET_OR_STAGING_DIGEST")
		}
	}
	if next >= stageIndex("READBACK_VERIFIED") &&
		m.ReadbackSignedSHA256 != m.SignedUKISHA256 {
		return fail("MEDIA_READBACK_MISMATCH")
	}
	if next >= stageIndex("SINGLE_CANARY_BOOT_PROVEN") {
		if m.CanaryHardwareID != m.TargetHardwareID ||
			!m.SignedBootOracle || !m.UnsignedBootRefused ||
			!m.RecoverySSHOracle || !validID(m.CanaryReceiptID) {
			return fail("CANARY_EVIDENCE_INCOMPLETE")
		}
	}
	if next >= stageIndex("SIX_NODE_STAGED_ACCEPTED") {
		if len(m.AcceptedHardwareIDs) != 6 { return fail("FLEET_NOT_SIX") }
		seen := map[string]bool{}
		for _, hw := range m.AcceptedHardwareIDs {
			if !validID(hw) || seen[hw] || !contains(m.AllowedHardwareIDs, hw) {
				return fail("FLEET_IDENTITY_DUPLICATE_OR_UNAUTHORIZED")
			}
			seen[hw] = true
		}
	}
	return nil
}

func Verdict(m Manifest) string {
	if err := Validate(m); err != nil { return fmt.Sprintf("R42_RELEASE_GUARD=%s", err) }
	return "R42_RELEASE_GUARD=SYNTHETIC_PLAN_PASS;PRODUCTION_ATTESTATION=NOT_TESTED"
}
