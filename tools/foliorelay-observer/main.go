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

type observation struct {
	universal bool
	txt       []string
	srvTarget string
	srvPort   int
}

func parsePacket(pkt []byte) (observation, error) {
	var o observation
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

		if strings.EqualFold(strings.TrimSuffix(name, "."), queryName) && typ == 12 {
			o.universal = true
		}
		if typ == 16 {
			for j := 0; j < len(rdata); {
				n := int(rdata[j])
				j++
				if j+n > len(rdata) {
					break
				}
				o.txt = append(o.txt, string(rdata[j:j+n]))
				j += n
			}
		}
		if typ == 33 && rdlen >= 7 {
			o.srvPort = int(binary.BigEndian.Uint16(rdata[4:6]))
			target, _, err := nameAt(pkt, rstart+6, nil)
			if err == nil {
				o.srvTarget = target
			}
		}
	}
	return o, nil
}

func qualifying(o observation, expected, expectedHost string, expectedPort int) bool {
	joined := strings.ToLower(strings.Join(o.txt, "\n"))
	return o.universal &&
		strings.Contains(joined, strings.ToLower(expected)) &&
		strings.Contains(joined, "rp=printers/foliorelay") &&
		strings.Contains(joined, "pdl=application/pdf,image/urf") &&
		strings.EqualFold(strings.TrimSuffix(o.srvTarget, "."), strings.TrimSuffix(expectedHost, ".")) &&
		o.srvPort == expectedPort
}

func observe(expected, expectedHost string, expectedPort int, seconds float64) (map[string]any, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, 15, 1)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: 5353}); err != nil {
		return nil, err
	}
	mreq := &syscall.IPMreq{Multiaddr: [4]byte{224, 0, 0, 251}}
	if err := syscall.SetsockoptIPMreq(fd, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq); err != nil {
		return nil, err
	}
	tv := syscall.NsecToTimeval(int64(time.Second))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}

	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[4:6], 1)
	q = append(q, encodeName(queryName)...)
	q = append(q, 0, 12, 0, 1)
	dst := &syscall.SockaddrInet4{Port: 5353, Addr: [4]byte{224, 0, 0, 251}}
	if err := syscall.Sendto(fd, q, 0, dst); err != nil {
		return nil, err
	}

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
		o, err := parsePacket(buf[:n])
		if err != nil {
			continue
		}
		if qualifying(o, expected, expectedHost, expectedPort) {
			return map[string]any{
				"universal_ptr": true,
				"uuid":          expected,
				"txt":           o.txt,
				"srv_target":    o.srvTarget,
				"srv_port":      o.srvPort,
			}, nil
		}
	}
	return nil, errors.New("no qualifying _universal FolioRelay mDNS response")
}

func main() {
	uuid := flag.String("uuid", "", "expected canonical printer UUID")
	host := flag.String("expected-host", "", "expected DNS-SD SRV host")
	ippPort := flag.Int("expected-ipp-port", 0, "expected DNS-SD SRV port")
	port := flag.Int("port", 18081, "HTTP witness port")
	seconds := flag.Float64("seconds", 25, "mDNS observation window")
	flag.Parse()
	if *uuid == "" || *host == "" || *ippPort <= 0 {
		fmt.Fprintln(os.Stderr, "uuid, expected-host, and expected-ipp-port are required")
		os.Exit(2)
	}

	state := &resultState{v: map[string]any{"status": "pending"}}
	go func() {
		r, err := observe(*uuid, *host, *ippPort, *seconds)
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
