package main

// Fictional independent reference oracle, NOT the private Sidecar or signer.
// A signature authenticates a proposal; only independent runtime evidence
// and a host ceiling can establish effective permission.
import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

type syntheticSignedPolicy struct {
	RepoID     uint64
	Path       string
	Generation uint64
	PolicyHash [32]byte
	Signature  []byte
}
type syntheticHostScope struct {
	RepoID         uint64
	Path           string
	LastGeneration uint64
	CanObserve     bool
	CanActuate     bool
}
type syntheticRuntimeReceipt struct {
	Epoch         uint64
	Generation    uint64
	EffectiveHash [32]byte
	Observed      bool
}

func syntheticSigningBytes(p syntheticSignedPolicy) []byte {
	b := append([]byte("fictional-admission-owner-signature/v1\x00"), make([]byte, 16)...)
	binary.BigEndian.PutUint64(b[len(b)-16:], p.RepoID)
	binary.BigEndian.PutUint64(b[len(b)-8:], p.Generation)
	b = append(b, []byte(p.Path)...)
	b = append(b, 0)
	b = append(b, p.PolicyHash[:]...)
	return b
}
func syntheticEvaluate(p syntheticSignedPolicy, public ed25519.PublicKey, h syntheticHostScope, r syntheticRuntimeReceipt, requestClass string) error {
	if p.RepoID != h.RepoID || p.Path != h.Path || p.Generation == 0 || p.Generation < h.LastGeneration ||
		!ed25519.Verify(public, syntheticSigningBytes(p), p.Signature) {
		return errors.New("untrusted-policy")
	}
	if requestClass != "observe" || !h.CanObserve {
		return errors.New("host-ceiling-denied")
	}
	// Approval and desired Git state cannot be mistaken for the active grant.
	if !r.Observed || r.Epoch == 0 || r.Generation != p.Generation || r.EffectiveHash != p.PolicyHash {
		return errors.New("no-independent-effective-receipt")
	}
	return nil
}
func TestSyntheticSignedSourceStillRequiresRuntimeReceipt(t *testing.T) {
	seed := sha256.Sum256([]byte("FICTIONAL-PUBLIC-TEST-ONLY-DO-NOT-USE-FOR-AUTH"))
	key := ed25519.NewKeyFromSeed(seed[:])
	public := key.Public().(ed25519.PublicKey)
	hash := sha256.Sum256([]byte("fictional observe-only source"))
	p := syntheticSignedPolicy{RepoID: 12345, Path: "policy/fictional-observe.json", Generation: 7, PolicyHash: hash}
	p.Signature = ed25519.Sign(key, syntheticSigningBytes(p))
	host := syntheticHostScope{RepoID: p.RepoID, Path: p.Path, LastGeneration: 6, CanObserve: true}
	live := syntheticRuntimeReceipt{Epoch: 5, Generation: 7, EffectiveHash: hash, Observed: true}
	if err := syntheticEvaluate(p, public, host, live, "observe"); err != nil {
		t.Fatal(err)
	}
	negative := []struct {
		name   string
		change func(*syntheticSignedPolicy, *syntheticHostScope, *syntheticRuntimeReceipt, *string)
	}{
		{"signed-but-not-applied", func(_ *syntheticSignedPolicy, _ *syntheticHostScope, r *syntheticRuntimeReceipt, _ *string) {
			r.Observed = false
		}},
		{"missing-process-epoch", func(_ *syntheticSignedPolicy, _ *syntheticHostScope, r *syntheticRuntimeReceipt, _ *string) {
			r.Epoch = 0
		}},
		{"wrong-effective-digest", func(_ *syntheticSignedPolicy, _ *syntheticHostScope, r *syntheticRuntimeReceipt, _ *string) {
			r.EffectiveHash = sha256.Sum256([]byte("other"))
		}},
		{"old-receipt-after-update", func(p *syntheticSignedPolicy, _ *syntheticHostScope, _ *syntheticRuntimeReceipt, _ *string) {
			p.Generation = 8
			p.Signature = ed25519.Sign(key, syntheticSigningBytes(*p))
		}},
		{"stale-policy-generation", func(p *syntheticSignedPolicy, h *syntheticHostScope, _ *syntheticRuntimeReceipt, _ *string) {
			h.LastGeneration = 8
		}},
		{"wrong-repository", func(p *syntheticSignedPolicy, _ *syntheticHostScope, _ *syntheticRuntimeReceipt, _ *string) {
			p.RepoID++
		}},
		{"wrong-policy-path", func(p *syntheticSignedPolicy, _ *syntheticHostScope, _ *syntheticRuntimeReceipt, _ *string) {
			p.Path = "policy/unreviewed.json"
		}},
		{"tampered-policy-hash", func(p *syntheticSignedPolicy, _ *syntheticHostScope, _ *syntheticRuntimeReceipt, _ *string) {
			p.PolicyHash = sha256.Sum256([]byte("tampered"))
		}},
		{"unauthorized-class", func(_ *syntheticSignedPolicy, _ *syntheticHostScope, _ *syntheticRuntimeReceipt, req *string) {
			*req = "actuate"
		}},
		{"missing-host-ceiling", func(_ *syntheticSignedPolicy, h *syntheticHostScope, _ *syntheticRuntimeReceipt, _ *string) {
			h.CanObserve = false
		}},
		{"unsigned-manifest", func(p *syntheticSignedPolicy, _ *syntheticHostScope, _ *syntheticRuntimeReceipt, _ *string) {
			p.Signature = nil
		}},
	}
	for _, tc := range negative {
		t.Run(tc.name, func(t *testing.T) {
			copyP, copyH, copyR, operation := p, host, live, "observe"
			tc.change(&copyP, &copyH, &copyR, &operation)
			if err := syntheticEvaluate(copyP, public, copyH, copyR, operation); err == nil {
				t.Fatal("accepted hostile synthetic case")
			}
		})
	}
}
