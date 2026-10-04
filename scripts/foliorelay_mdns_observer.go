package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const universal = "_universal._sub._ipp._tcp.local"

type result struct {
	Status       string   `json:"status"`
	Error        string   `json:"error,omitempty"`
	UniversalPTR bool     `json:"universal_ptr,omitempty"`
	UUID         string   `json:"uuid,omitempty"`
	TXT          []string `json:"txt,omitempty"`
	SRVTarget    string   `json:"srv_target,omitempty"`
	SRVPort      int      `json:"srv_port,omitempty"`
}

type resultStore struct {
	mu sync.RWMutex
	r  result
}

func (s *resultStore) set(r result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.r = r
}

func (s *resultStore) get() result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.r
}

func encodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	return append(out, 0)
}

func decodeName(pkt []byte, off int, seen map[int]bool) (string, int, error) {
	var labels []string
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
		if n&0xc0 == 0xc0 {
			if off+1 >= len(pkt) {
				return "", 0, errors.New("truncated dns pointer")
			}
			ptr := ((n & 0x3f) << 8) | int(pkt[off+1])
			if seen[ptr] {
				return "", 0, errors.New("dns pointer loop")
			}
			seen[ptr] = true
			tail, _, err := decodeName(pkt, ptr, seen)
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
		if off+n > len(pkt) {
			return "", 0, errors.New("truncated dns label")
		}
		labels = append(labels, string(pkt[off:off+n]))
		off += n
	}
}

type observed struct {
	universalPTR bool
	txt          []string
	srvTarget    string
	srvPort      int
}

func consumePacket(pkt []byte, o *observed) error {
	if len(pkt) < 12 {
		return errors.New("short dns packet")
	}
	qd := int(binary.BigEndian.Uint16(pkt[4:6]))
	an := int(binary.BigEndian.Uint16(pkt[6:8]))
	ns := int(binary.BigEndian.Uint16(pkt[8:10]))
	ar := int(binary.BigEndian.Uint16(pkt[10:12]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := decodeName(pkt, off, map[int]bool{})
		if err != nil {
			return err
		}
		off = next + 4
		if off > len(pkt) {
			return errors.New("truncated dns question")
		}
	}
	for i := 0; i < an+ns+ar; i++ {
		name, next, err := decodeName(pkt, off, map[int]bool{})
		if err != nil {
			return err
		}
		off = next
		if off+10 > len(pkt) {
			return errors.New("truncated dns rr")
		}
		typ := binary.BigEndian.Uint16(pkt[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[off+8 : off+10]))
		off += 10
		rstart := off
		if off+rdlen > len(pkt) {
			return errors.New("truncated dns rdata")
		}
		r := pkt[off : off+rdlen]
		off += rdlen
		if strings.EqualFold(strings.TrimSuffix(name, "."), universal) && typ == 12 {
			o.universalPTR = true
		}
		if typ == 16 {
			for j := 0; j < len(r); {
				n := int(r[j])
				j++
				if j+n > len(r) {
					break
				}
				o.txt = append(o.txt, string(r[j:j+n]))
				j += n
			}
		}
		if typ == 33 && rdlen >= 7 {
			o.srvPort = int(binary.BigEndian.Uint16(r[4:6]))
			target, _, err := decodeName(pkt, rstart+6, map[int]bool{})
			if err == nil {
				o.srvTarget = target
			}
		}
	}
	return nil
}

func qualifies(o observed, expectedUUID, expectedHost string, expectedPort int) bool {
	joined := strings.ToLower(strings.Join(o.txt, "\n"))
	return o.universalPTR &&
		strings.Contains(joined, strings.ToLower(expectedUUID)) &&
		strings.Contains(joined, "rp=printers/foliorelay") &&
		strings.Contains(joined, "pdl=application/pdf,image/urf") &&
		strings.EqualFold(strings.TrimSuffix(o.srvTarget, "."), strings.TrimSuffix(expectedHost, ".")) &&
		o.srvPort == expectedPort
}

func observe(expectedUUID, expectedHost string, expectedPort int, seconds time.Duration) (result, error) {
	group := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	conn, err := net.ListenMulticastUDP("udp4", nil, group)
	if err != nil {
		return result{}, fmt.Errorf("listen multicast: %w", err)
	}
	defer conn.Close()
	if err := conn.SetReadBuffer(1 << 20); err != nil {
		return result{}, fmt.Errorf("read buffer: %w", err)
	}

	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[4:6], 1)
	query = append(query, encodeName(universal)...)
	query = append(query, 0, 12, 0, 1)

	deadline := time.Now().Add(seconds)
	var o observed
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := conn.WriteToUDP(query, group); err != nil {
			return result{}, fmt.Errorf("send multicast query: %w", err)
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return result{}, fmt.Errorf("read multicast: %w", err)
		}
		_ = consumePacket(buf[:n], &o)
		if qualifies(o, expectedUUID, expectedHost, expectedPort) {
			return result{
				Status:       "success",
				UniversalPTR: true,
				UUID:         expectedUUID,
				TXT:          append([]string(nil), o.txt...),
				SRVTarget:    o.srvTarget,
				SRVPort:      o.srvPort,
			}, nil
		}
	}
	return result{}, errors.New("no qualifying _universal FolioRelay mDNS response")
}

func main() {
	uuid := flag.String("uuid", "", "expected printer UUID")
	host := flag.String("expected-host", "", "expected SRV target")
	ippPort := flag.Int("expected-ipp-port", 0, "expected SRV port")
	httpPort := flag.Int("port", 18081, "HTTP witness port")
	seconds := flag.Duration("seconds", 25*time.Second, "observation window")
	flag.Parse()
	if *uuid == "" || *host == "" || *ippPort <= 0 || *httpPort <= 0 {
		panic("required observer arguments missing")
	}

	store := &resultStore{r: result{Status: "pending"}}
	go func() {
		r, err := observe(*uuid, *host, *ippPort, *seconds)
		if err != nil {
			store.set(result{Status: "error", Error: fmt.Sprintf("%T: %v", err, err)})
			return
		}
		store.set(r)
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(store.get())
	})
	if err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", *httpPort), nil); err != nil {
		panic(err)
	}
}
