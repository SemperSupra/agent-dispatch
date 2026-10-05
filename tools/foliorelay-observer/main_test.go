package main

import (
    "encoding/binary"
    "testing"
)

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
    o := observation{
        universal: true,
        txt: []string{
            "UUID=01234567-89ab-4def-8123-456789abcdef",
            "rp=printers/FolioRelay",
            "pdl=application/pdf,image/urf",
        },
        srvTarget: "foliorelay-t6.local.",
        srvPort: 8634,
    }
    if !qualifying(o, "01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 8634) {
        t.Fatal("expected qualifying observation")
    }
}

func TestParsePacket(t *testing.T) {
    // One PTR owner for the universal subtype, one TXT RR, one SRV RR.
    pkt := make([]byte, 12)
    binary.BigEndian.PutUint16(pkt[6:8], 3)

    appendRR := func(owner string, typ uint16, rdata []byte) {
        pkt = append(pkt, encodeName(owner)...)
        hdr := make([]byte, 10)
        binary.BigEndian.PutUint16(hdr[0:2], typ)
        binary.BigEndian.PutUint16(hdr[2:4], 1)
        binary.BigEndian.PutUint32(hdr[4:8], 120)
        binary.BigEndian.PutUint16(hdr[8:10], uint16(len(rdata)))
        pkt = append(pkt, hdr...)
        pkt = append(pkt, rdata...)
    }

    appendRR(queryName, 12, encodeName("FolioRelay._ipp._tcp.local"))
    txt := []byte{}
    for _, s := range []string{
        "UUID=01234567-89ab-4def-8123-456789abcdef",
        "rp=printers/FolioRelay",
        "pdl=application/pdf,image/urf",
    } {
        txt = append(txt, byte(len(s)))
        txt = append(txt, []byte(s)...)
    }
    appendRR("FolioRelay._ipp._tcp.local", 16, txt)
    srv := make([]byte, 6)
    binary.BigEndian.PutUint16(srv[4:6], 8634)
    srv = append(srv, encodeName("foliorelay-t6.local")...)
    appendRR("FolioRelay._ipp._tcp.local", 33, srv)

    o, err := parsePacket(pkt)
    if err != nil { t.Fatal(err) }
    if !qualifying(o, "01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 8634) {
        t.Fatalf("not qualifying: %+v", o)
    }
}


func TestQualifyingRejectsCrossedIdentity(t *testing.T) {
	base := observation{
		universal: true,
		txt: []string{
			"UUID=urn:uuid:01234567-89ab-4def-8123-456789abcdef",
			"rp=printers/FolioRelay",
			"pdl=application/pdf,image/urf",
		},
		srvTarget: "foliorelay-t6.local.",
		srvPort:   8634,
	}
	tests := []struct {
		name string
		obs observation
		expected string
		host string
		port int
	}{
		{"missing-universal", observation{txt: base.txt, srvTarget: base.srvTarget, srvPort: base.srvPort}, "urn:uuid:01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 8634},
		{"wrong-uuid", base, "urn:uuid:ffffffff-ffff-4fff-8fff-ffffffffffff", "foliorelay-t6.local", 8634},
		{"wrong-host", base, "urn:uuid:01234567-89ab-4def-8123-456789abcdef", "other.local", 8634},
		{"wrong-port", base, "urn:uuid:01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 9999},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if qualifying(tc.obs, tc.expected, tc.host, tc.port) {
				t.Fatal("unexpected qualifying observation")
			}
		})
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
    o := observation{
        universal: true,
        txt: []string{
            "UUID=urn:uuid:01234567-89ab-4def-8123-456789abcdef",
            "rp=printers/FolioRelay",
            "pdl=application/pdf,image/urf",
        },
        srvTarget: "foliorelay-t6.local.",
        srvPort: 8634,
    }
    if qualifying(o, "01234567-89ab-4def-8123-456789abcdef", "foliorelay-t6.local", 8634) {
        t.Fatal("canonical URN must not satisfy bare TXT UUID projection")
    }
}
