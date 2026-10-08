package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const queryName = "_universal._sub._ipp._tcp.local"
const legacyQueryID uint16 = 0x4652

type resultState struct {
	mu sync.RWMutex
	v  map[string]any
}

func (s *resultState) set(v map[string]any) {
	s.mu.Lock()
	s.v = v
	s.mu.Unlock()
}

func (s *resultState) get() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]any, len(s.v))
	for k, v := range s.v {
		out[k] = v
	}
	return out
}

func encodeName(name string) []byte {
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

func nameAt(pkt []byte, off int, seen map[int]bool) (string, int, error) {
	if seen == nil {
		seen = map[int]bool{}
	}
	labels := []string{}
	end := -1
	for {
		if off >= len(pkt) {
			return "", 0, errors.New("dns name overflow")
		}
		n := int(pkt[off])
		if n == 0 {
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, nil
		}
		if n&0xC0 == 0xC0 {
			if off+1 >= len(pkt) {
				return "", 0, errors.New("dns pointer overflow")
			}
			ptr := ((n & 0x3f) << 8) | int(pkt[off+1])
			if seen[ptr] {
				return "", 0, errors.New("dns pointer loop")
			}
			seen[ptr] = true
			tail, _, err := nameAt(pkt, ptr, seen)
			if err != nil {
				return "", 0, err
			}
			if tail != "" {
				labels = append(labels, tail)
			}
			if end < 0 {
				end = off + 2
			}
			return strings.Join(labels, "."), end, nil
		}
		off++
		if n > 63 || off+n > len(pkt) {
			return "", 0, errors.New("dns label overflow")
		}
		labels = append(labels, string(pkt[off:off+n]))
		off += n
	}
}

func normalizeDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

type srvRecord struct {
	target string
	port   int
}

type observation struct {
	universalTargets []string
	txtByOwner       map[string][]string
	srvByOwner       map[string]srvRecord
}

func newObservation() observation {
	return observation{
		txtByOwner: map[string][]string{},
		srvByOwner: map[string]srvRecord{},
	}
}

func (o *observation) merge(other observation) {
	o.universalTargets = append(o.universalTargets, other.universalTargets...)
	for owner, items := range other.txtByOwner {
		o.txtByOwner[owner] = append(o.txtByOwner[owner], items...)
	}
	for owner, srv := range other.srvByOwner {
		o.srvByOwner[owner] = srv
	}
}

func parsePacket(pkt []byte) (observation, error) {
	o := newObservation()
	if len(pkt) < 12 {
		return o, errors.New("short dns packet")
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:6]))
	an := int(binary.BigEndian.Uint16(pkt[6:8]))
	ns := int(binary.BigEndian.Uint16(pkt[8:10]))
	ar := int(binary.BigEndian.Uint16(pkt[10:12]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := nameAt(pkt, off, nil)
		if err != nil {
			return o, err
		}
		off = next
		if off+4 > len(pkt) {
			return o, errors.New("short dns question")
		}
		off += 4
	}
	for i := 0; i < an+ns+ar; i++ {
		name, next, err := nameAt(pkt, off, nil)
		if err != nil {
			return o, err
		}
		off = next
		if off+10 > len(pkt) {
			return o, errors.New("short dns rr")
		}
		typ := binary.BigEndian.Uint16(pkt[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
		off += 10
		rstart := off
		if off+rdlen > len(pkt) {
			return o, errors.New("short dns rdata")
		}
		rdata := pkt[off : off+rdlen]
		off += rdlen
		owner := normalizeDNSName(name)

		if owner == normalizeDNSName(queryName) && typ == 12 {
			target, _, err := nameAt(pkt, rstart, nil)
			if err != nil {
				return o, err
			}
			o.universalTargets = append(o.universalTargets, target)
		}
		if typ == 16 {
			items := []string{}
			for j := 0; j < len(rdata); {
				n := int(rdata[j])
				j++
				if j+n > len(rdata) {
					return o, errors.New("short dns txt item")
				}
				items = append(items, string(rdata[j:j+n]))
				j += n
			}
			o.txtByOwner[owner] = append(o.txtByOwner[owner], items...)
		}
		if typ == 33 && rdlen >= 7 {
			target, _, err := nameAt(pkt, rstart+6, nil)
			if err != nil {
				return o, err
			}
			o.srvByOwner[owner] = srvRecord{
				target: target,
				port:   int(binary.BigEndian.Uint16(rdata[4:6])),
			}
		}
	}
	return o, nil
}

type serviceMatch struct {
	instance  string
	txt       []string
	srvTarget string
	srvPort   int
}

func matchObservation(o observation, expectedTxtUUID, expectedHost string, expectedPort int) (serviceMatch, bool) {
	for _, instance := range o.universalTargets {
		owner := normalizeDNSName(instance)
		txt, ok := o.txtByOwner[owner]
		if !ok {
			continue
		}
		srv, ok := o.srvByOwner[owner]
		if !ok {
			continue
		}
		uuidMatch := false
		for _, item := range txt {
			if strings.EqualFold(item, "UUID="+expectedTxtUUID) {
				uuidMatch = true
				break
			}
		}
		joined := strings.ToLower(strings.Join(txt, "\n"))
		if uuidMatch &&
			strings.Contains(joined, "rp=printers/foliorelay") &&
			strings.Contains(joined, "pdl=application/pdf,image/urf") &&
			strings.EqualFold(normalizeDNSName(srv.target), normalizeDNSName(expectedHost)) &&
			srv.port == expectedPort {
			return serviceMatch{
				instance:  instance,
				txt:       txt,
				srvTarget: srv.target,
				srvPort:   srv.port,
			}, true
		}
	}
	return serviceMatch{}, false
}

func qualifying(o observation, expectedTxtUUID, expectedHost string, expectedPort int) bool {
	_, ok := matchObservation(o, expectedTxtUUID, expectedHost, expectedPort)
	return ok
}

func observationSocketPlan(legacyUnicast bool) (bindPort int, joinMulticast bool, queryID uint16) {
	if legacyUnicast {
		return 0, false, legacyQueryID
	}
	return 5353, true, 0
}

func buildQuery(queryID uint16) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], queryID)
	binary.BigEndian.PutUint16(q[4:6], 1)
	q = append(q, encodeName(queryName)...)
	q = append(q, 0, 12, 0, 1)
	return q
}

func observe(expected, expectedTxtUUID, expectedHost string, expectedPort int, seconds float64, legacyUnicast bool) (map[string]any, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, 15, 1)
	bindPort, joinMulticast, queryID := observationSocketPlan(legacyUnicast)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: bindPort}); err != nil {
		return nil, err
	}
	if joinMulticast {
		mreq := &syscall.IPMreq{Multiaddr: [4]byte{224, 0, 0, 251}}
		if err := syscall.SetsockoptIPMreq(fd, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq); err != nil {
			return nil, err
		}
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 255); err != nil {
		return nil, err
	}
	tv := syscall.NsecToTimeval(int64(time.Second))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}

	q := buildQuery(queryID)
	dst := &syscall.SockaddrInet4{Port: 5353, Addr: [4]byte{224, 0, 0, 251}}
	if err := syscall.Sendto(fd, q, 0, dst); err != nil {
		return nil, err
	}

	aggregate := newObservation()
	deadline := time.Now().Add(time.Duration(seconds * float64(time.Second)))
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				_ = syscall.Sendto(fd, q, 0, dst)
				continue
			}
			return nil, err
		}
		if legacyUnicast && n >= 2 && binary.BigEndian.Uint16(buf[:2]) != queryID {
			continue
		}
		packetObservation, err := parsePacket(buf[:n])
		if err != nil {
			continue
		}
		aggregate.merge(packetObservation)
		if matched, ok := matchObservation(aggregate, expectedTxtUUID, expectedHost, expectedPort); ok {
			transport := "multicast-5353"
			if legacyUnicast {
				transport = "legacy-unicast"
			}
			return map[string]any{
				"query_transport": transport,
				"universal_ptr":   true,
				"service_instance": matched.instance,
				"uuid":            expected,
				"txt":             matched.txt,
				"srv_target":      matched.srvTarget,
				"srv_port":        matched.srvPort,
			}, nil
		}
	}
	return nil, errors.New("no qualifying _universal FolioRelay mDNS response")
}

func main() {
	uuid := flag.String("uuid", "", "expected canonical printer UUID")
	txtUUID := flag.String("txt-uuid", "", "expected bare DNS-SD TXT UUID")
	host := flag.String("expected-host", "", "expected DNS-SD SRV host")
	ippPort := flag.Int("expected-ipp-port", 0, "expected DNS-SD SRV port")
	port := flag.Int("port", 18081, "HTTP witness port")
	seconds := flag.Float64("seconds", 25, "mDNS observation window")
	legacyUnicast := flag.Bool("legacy-unicast", false, "query mDNS from an ephemeral source port and receive the RFC 6762 legacy-unicast reply")
	flag.Parse()
	if *uuid == "" || *txtUUID == "" || *host == "" || *ippPort <= 0 {
		fmt.Fprintln(os.Stderr, "uuid, txt-uuid, expected-host, and expected-ipp-port are required")
		os.Exit(2)
	}

	state := &resultState{v: map[string]any{"status": "pending"}}
	go func() {
		r, err := observe(*uuid, *txtUUID, *host, *ippPort, *seconds, *legacyUnicast)
		if err != nil {
			state.set(map[string]any{"status": "error", "error": fmt.Sprintf("%T: %v", err, err)})
			return
		}
		r["status"] = "success"
		state.set(r)
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(state.get())
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		_, _ = w.Write(body)
	})
	if err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", *port), nil); err != nil {
		panic(err)
	}
}
