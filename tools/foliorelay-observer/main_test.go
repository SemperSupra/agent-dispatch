package main

import (
	"encoding/binary"
	"testing"
)

const testInstance = "FolioRelay._ipp._tcp.local"

func validObservation() observation {
	o := newObservation()
	o.universalTargets = []string{testInstance}
	owner := normalizeDNSName(testInstance)
	o.txtByOwner[owner] = []string{
		"UUID=01234567-89ab-4def-8123-456789abcdef",
		"rp=printers/FolioRelay",
		"pdl=application/pdf,image/urf",
	}
	o.srvByOwner[owner] = srvRecord{target: "foliorelay-t6.local.", port: 8634}
	return o
}

func TestObservationSocketPlan(t *testing.T) {
	port, join, id := observationSocketPlan(false)
	if port != 5353 || !join || id != 0 {
		t.Fatalf("multicast plan = port %d join %v id %d", port, join, id)
	}
	port, join, id = observationSocketPlan(true)
	if port != 0 || join || id != legacyQueryID {
		t.Fatalf("legacy plan = port %d join %v id %d", port, join, id)
	}
}

func TestBuildLegacyQueryCarriesCorrelationID(t *testing.T) {
	q := buildQuery(legacyQueryID)
	if len(q) < 12 {
		t.Fatal("short query")
	}
	if got := binary.BigEndian.Uint16(q[0:2]); got != legacyQueryID {
		t.Fatalf("query id=%#x want=%#x", got, legacyQueryID)
	}
	if got := binary.BigEndian.Uint16(q[4:6]); got != 1 {
		t.Fatalf("question count=%d want=1", got)
	}
}

func TestEncodeAndNameAt(t *testing.T) {
	wire := encodeName("_universal._sub._ipp._tcp.local")
	got, end, err := nameAt(wire, 0, nil)
	if err != nil { t.Fatal(err) }
	if got != queryName { t.Fatalf("got %q", got) }
	if end != len(wire) { t.Fatalf("end=%d want=%d", end, len(wire)) }
}

func TestCompressedNameAt(t *testing.T) {
	base := encodeName("_ipp._tcp.local")
	pkt := append([]byte{}, base...)
	off := len(pkt)
	pkt = append(pkt, 10)
	pkt = append(pkt, []byte("_universal")...)
	pkt = append(pkt, 0xC0, 0x00)
	got, end, err := nameAt(pkt, off, nil)
	if err != nil { t.Fatal(err) }
	if got != "_universal._ipp._tcp.local" { t.Fatalf("got %q", got) }
	if end != len(pkt) { t.Fatalf("end=%d want=%d", end, len(pkt)) }
}

func TestQualifying(t *testing.T) {
	o := validObservation()
	if !qualifying(o, "01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 8634) {
		t.Fatal("expected qualifying observation")
	}
}

func appendRR(pkt *[]byte, owner string, typ uint16, rdata []byte) {
	*pkt = append(*pkt, encodeName(owner)...)
	hdr := make([]byte, 10)
	binary.BigEndian.PutUint16(hdr[0:2], typ)
	binary.BigEndian.PutUint16(hdr[2:4], 1)
	binary.BigEndian.PutUint32(hdr[4:8], 120)
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(rdata)))
	*pkt = append(*pkt, hdr...)
	*pkt = append(*pkt, rdata...)
}

func TestParsePacket(t *testing.T) {
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[6:8], 3)
	appendRR(&pkt, queryName, 12, encodeName(testInstance))
	txt := []byte{}
	for _, s := range []string{
		"UUID=01234567-89ab-4def-8123-456789abcdef",
		"rp=printers/FolioRelay",
		"pdl=application/pdf,image/urf",
	} {
		txt = append(txt, byte(len(s)))
		txt = append(txt, []byte(s)...)
	}
	appendRR(&pkt, testInstance, 16, txt)
	srv := make([]byte, 6)
	binary.BigEndian.PutUint16(srv[4:6], 8634)
	srv = append(srv, encodeName("foliorelay-t6.local")...)
	appendRR(&pkt, testInstance, 33, srv)

	o, err := parsePacket(pkt)
	if err != nil { t.Fatal(err) }
	if !qualifying(o, "01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 8634) {
		t.Fatalf("not qualifying: %+v", o)
	}
}

func TestQualifyingRejectsCrossedIdentity(t *testing.T) {
	base := validObservation()
	tests := []struct {
		name string
		obs observation
		expected string
		host string
		port int
	}{
		{"missing-universal", func() observation {
			x := validObservation(); x.universalTargets = nil; return x
		}(), "01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 8634},
		{"wrong-uuid", base, "ffffffff-ffff-4fff-8fff-ffffffffffff", "foliorelay-t6.local", 8634},
		{"wrong-host", base, "01234567-89ab-4def-8123-456789abcdef", "other.local", 8634},
		{"wrong-port", base, "01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 9999},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if qualifying(tc.obs, tc.expected, tc.host, tc.port) {
				t.Fatal("unexpected qualifying observation")
			}
		})
	}
}

func TestRejectsCrossInstanceSplicing(t *testing.T) {
	o := newObservation()
	good := normalizeDNSName("Good._ipp._tcp.local")
	other := normalizeDNSName("Other._ipp._tcp.local")
	o.universalTargets = []string{"Good._ipp._tcp.local"}
	o.txtByOwner[good] = []string{
		"UUID=01234567-89ab-4def-8123-456789abcdef",
		"rp=printers/FolioRelay",
		"pdl=application/pdf,image/urf",
	}
	o.srvByOwner[other] = srvRecord{target: "foliorelay-t6.local.", port: 8634}
	if qualifying(o, "01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 8634) {
		t.Fatal("must not splice TXT and SRV from different service instances")
	}
}

func TestMergeAcrossPacketsPreservesSameInstanceCorrelation(t *testing.T) {
	owner := normalizeDNSName(testInstance)
	a := newObservation(); a.universalTargets = []string{testInstance}
	b := newObservation(); b.txtByOwner[owner] = []string{
		"UUID=01234567-89ab-4def-8123-456789abcdef",
		"rp=printers/FolioRelay",
		"pdl=application/pdf,image/urf",
	}
	c := newObservation(); c.srvByOwner[owner] = srvRecord{target: "foliorelay-t6.local.", port: 8634}
	a.merge(b); a.merge(c)
	if !qualifying(a, "01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 8634) {
		t.Fatal("same service instance split across packets should qualify")
	}
}

func TestParsePacketRejectsMalformedInput(t *testing.T) {
	if _, err := parsePacket([]byte{0, 1, 2}); err == nil {
		t.Fatal("expected short packet error")
	}
	loop := make([]byte, 18)
	binary.BigEndian.PutUint16(loop[4:6], 1)
	loop[12], loop[13] = 0xC0, 0x0C
	if _, err := parsePacket(loop); err == nil {
		t.Fatal("expected DNS compression pointer loop error")
	}
}

func TestQualifyingRejectsCanonicalURNInTXT(t *testing.T) {
	o := validObservation()
	owner := normalizeDNSName(testInstance)
	o.txtByOwner[owner][0] = "UUID=urn:uuid:01234567-89ab-4def-8123-456789abcdef"
	if qualifying(o, "01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 8634) {
		t.Fatal("canonical URN must not satisfy bare TXT UUID projection")
	}
}
