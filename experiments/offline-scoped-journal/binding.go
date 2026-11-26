package journal

import (
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// BindingStatus describes retained-byte custody only, never live authentication.
type BindingStatus string

const (
	NoIndependentPin BindingStatus = "unknown_no_independent_pin"
	BindingRefused BindingStatus = "refused"
	RetainedByteMatch BindingStatus = "retained_byte_match"
)

// validArtifact accepts empty artifacts, but not invalid identity or digest.
func validArtifact(a ArtifactRef) bool {
	return validScope(a.Scope) && validID(a.Occurrence) && validSHA(a.SHA256)
}

// DecodeArtifactRef is a strict, bounded decoder for the artifact-reference wire shape.
func DecodeArtifactRef(b []byte) (ArtifactRef, error) {
	var a ArtifactRef
	if len(b) > 4096 || !utf8.Valid(b) {
		return a, errors.New("invalid artifact input size or UTF-8")
	}
	m, err := exact(b, "scope", "occurrence", "sha256", "size")
	if err != nil {
		return a, err
	}
	if _, err = exact(m["scope"], "run", "branch", "space", "producer"); err != nil {
		return a, err
	}
	if err = json.Unmarshal(b, &a); err != nil {
		return ArtifactRef{}, err
	}
	if !validArtifact(a) {
		return ArtifactRef{}, errors.New("invalid artifact reference")
	}
	return a, nil
}

// VerifyRetainedArtifact compares the claim with an independently obtained pin,
// then checks the exact bytes and size. The caller must establish pin independence.
// No pin is UNKNOWN, even if the claimant supplies a plausible digest.
func VerifyRetainedArtifact(src io.Reader, claim ArtifactRef, pin *ArtifactRef) (BindingStatus, error) {
	if !validArtifact(claim) {
		return BindingRefused, errors.New("invalid claimed artifact")
	}
	if pin == nil {
		return NoIndependentPin, nil
	}
	if !validArtifact(*pin) || claim != *pin {
		return BindingRefused, errors.New("independent occurrence pin mismatch")
	}
	if claim.Size > MaxSourceBytes {
		return BindingRefused, errors.New("artifact exceeds verification limit")
	}
	if src == nil {
		return BindingRefused, errors.New("source stream required")
	}
	size, err := VerifyArtifact(src, pin.SHA256)
	if err != nil {
		return BindingRefused, err
	}
	if size != pin.Size {
		return BindingRefused, errors.New("retained size mismatch")
	}
	return RetainedByteMatch, nil
}
