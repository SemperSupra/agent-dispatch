package blue

// R27-M is a contract test compiled against original R27-D blue.Lease.
// This file is copied only into an isolated Actions checkout of that module.
// It does NOT make the current QEMU guest sign its dynamic lease.
import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

const r27mDomain = "usb-fabric/r27m/blue-lease-events/v1"

func r27mScope(lease Lease, nonce [32]byte, down, up uint64) []byte {
	var b bytes.Buffer
	put := func(s string) {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(s)))
		_, _ = b.WriteString(s)
	}
	put(r27mDomain)
	put(lease.Device)
	put(lease.Port)
	put(lease.Actor)
	put(lease.Epoch)
	_ = binary.Write(&b, binary.BigEndian, lease.Generation)
	_, _ = b.Write(nonce[:])
	_ = binary.Write(&b, binary.BigEndian, down)
	_ = binary.Write(&b, binary.BigEndian, up)
	return b.Bytes()
}

func r27mVerify(pub ed25519.PublicKey, want Lease, wantNonce [32]byte, wantDown, wantUp uint64, claimed Lease, claimedNonce [32]byte, down, up uint64, signature []byte) bool {
	if want.Generation == 0 || wantDown == 0 || wantUp <= wantDown || down == 0 || up <= down {
		return false
	}
	if claimed != want || claimedNonce != wantNonce || down != wantDown || up != wantUp {
		return false
	}
	return ed25519.Verify(pub, r27mScope(claimed, claimedNonce, down, up), signature)
}

func TestR27MDynamicLeaseEd25519Contract(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		t.Fatal(err)
	}
	lease := Lease{Device: "keyboard", Port: "vhci_hcd/port0", Actor: "consumer-A", Epoch: "host-epoch-A", Generation: 7}
	const down, up uint64 = 18, 19
	signature := ed25519.Sign(private, r27mScope(lease, challenge, down, up))
	verify := func(claim Lease, nonce [32]byte, d, u uint64, key ed25519.PublicKey) bool {
		return r27mVerify(key, lease, challenge, down, up, claim, nonce, d, u, signature)
	}
	if !verify(lease, challenge, down, up, pub) {
		t.Fatal("correct original dynamic blue.Lease signed DOWN/UP rejected")
	}
	t.Log("R27_M_ACTUAL_BLUE_LEASE_TYPE_DYNAMIC_SCOPE=PASS")
	for _, tc := range []struct {
		name  string
		alter func(*Lease)
	}{
		{"device", func(l *Lease) { l.Device = "mouse" }},
		{"port", func(l *Lease) { l.Port = "vhci_hcd/port1" }},
		{"actor", func(l *Lease) { l.Actor = "consumer-B" }},
		{"epoch", func(l *Lease) { l.Epoch = "old-host-epoch" }},
		{"generation", func(l *Lease) { l.Generation-- }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := lease
			tc.alter(&modified)
			if verify(modified, challenge, down, up, pub) {
				t.Fatalf("modified %s admitted under same signed lease scope", tc.name)
			}
		})
	}
	t.Log("R27_M_WRONG_DEVICE_PORT_ACTOR_EPOCH_GENERATION=DENIED")
	stale := challenge
	stale[0] ^= 0xff
	if verify(lease, stale, down, up, pub) {
		t.Fatal("old host challenge accepted")
	}
	if verify(lease, challenge, down-1, up, pub) || verify(lease, challenge, down, up+1, pub) {
		t.Fatal("spliced DOWN or UP accepted")
	}
	if verify(lease, challenge, up, down, pub) || verify(lease, challenge, 0, up, pub) {
		t.Fatal("reordered or missing DOWN accepted")
	}
	if verify(lease, challenge, down, up, wrongPub) {
		t.Fatal("wrong signing identity admitted")
	}
	t.Log("R27_M_STALE_CHALLENGE_EVENT_SPLICE_ORDER_AND_WRONG_KEY=DENIED")
}

func TestR27MScopeEncodingIsUnambiguous(t *testing.T) {
	var challenge [32]byte
	a := Lease{Device: "ab", Port: "c", Actor: "x", Epoch: "y", Generation: 1}
	b := Lease{Device: "a", Port: "bc", Actor: "x", Epoch: "y", Generation: 1}
	if bytes.Equal(r27mScope(a, challenge, 1, 2), r27mScope(b, challenge, 1, 2)) {
		t.Fatal("scope fields can be confused by concatenation")
	}
	t.Log("R27_M_CANONICAL_LENGTH_PREFIX_COLLISION_CRITIC=PASS")
}
