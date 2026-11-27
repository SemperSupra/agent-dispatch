package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, order string) (Receipt, []byte) {
	t.Helper()
	b, e := os.ReadFile("testdata/cohort.json")
	if e != nil {
		t.Fatal(e)
	}
	if digest(b) != "124ebf946c9c346cff09c0415c91f35c146ac752aeb34459550577f54356be60" {
		t.Fatal("cohort digest mismatch")
	}
	var files map[string]string
	if e = json.Unmarshal(b, &files); e != nil || len(files) != 12 {
		t.Fatalf("cohort: %v", e)
	}
	r, e := decode([]byte(files[order+".json"]))
	if e != nil {
		t.Fatal(e)
	}
	raw := []byte(files[order+".raw"])
	return r, raw
}
func TestActualCohorts(t *testing.T) {
	for _, order := range orders {
		t.Run(order, func(t *testing.T) {
			r, raw := fixture(t, order)
			if e := check(r, order, raw); e != nil {
				t.Fatal(e)
			}
			if e := checkRaw(r, raw); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestCoherentRehashEveryPair(t *testing.T) {
	for _, order := range orders {
		r, raw := fixture(t, order)
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		for i := 0; i < 60; i++ {
			for _, kind := range []string{"command", "response", "drop", "duplicate"} {
				t.Run(fmt.Sprintf("%s/%02d/%s", order, i, kind), func(t *testing.T) {
					l := append([]string(nil), lines...)
					j := 1 + 2*i
					switch kind {
					case "command":
						l[j] += " 0"
					case "response":
						if strings.HasSuffix(l[j+1], " OK") {
							l[j+1] += " 0x0"
						} else {
							n := strings.LastIndex(l[j+1], "0x")
							if n < 0 {
								t.Fatal("fixture")
							}
							if strings.HasSuffix(l[j+1], "0") {
								l[j+1] = l[j+1][:len(l[j+1])-1] + "1"
							} else {
								l[j+1] = l[j+1][:len(l[j+1])-1] + "0"
							}
						}
					case "drop":
						l = append(l[:j], l[j+2:]...)
					case "duplicate":
						l = append(append(append([]string{}, l[:j]...), l[j:j+2]...), l[j:]...)
					}
					m := []byte(strings.Join(l, "\n") + "\n")
					if bytes.Equal(m, raw) {
						t.Fatal("no-op")
					}
					q := r
					q.RawSHA256 = digest(m)
					if e := check(q, order, m); e != nil {
						t.Fatalf("old oracle unexpectedly rejects rehash: %v", e)
					}
					if e := checkRaw(q, m); e == nil {
						t.Fatal("accepted mutated transcript")
					}
				})
			}
		}
	}
}
func TestBoundaryControls(t *testing.T) {
	r, raw := fixture(t, "ABAB")
	cases := map[string][]byte{
		"close-inversion":  bytes.Replace(raw, []byte("[I +0.003608] CLOSED"), []byte("[I +0.000001] CLOSED"), 1),
		"mid-inversion":    bytes.Replace(raw, []byte("+0.000627"), []byte("+0.000001"), 1),
		"missing-final-LF": raw[:len(raw)-1], "CRLF": bytes.ReplaceAll(raw, []byte("\n"), []byte("\r\n")),
		"NUL":                  bytes.Replace(raw, []byte("OPENED"), []byte("OPENED\x00"), 1),
		"wrong-open":           bytes.Replace(raw, []byte("OPENED"), []byte("CLOSED"), 1),
		"bad-hex":              bytes.Replace(raw, []byte("0x10011af4\n"), []byte("0x10011afg\n"), 1),
		"overflow-hex":         bytes.Replace(raw, []byte("0x10011af4\n"), []byte("0x110011af4\n"), 1),
		"wrong-selector-write": bytes.Replace(raw, []byte("outw 0x100e 1"), []byte("outw 0x100e 2"), 1),
		"wrong-pfn-write":      bytes.Replace(raw, []byte("outl 0x1008 1"), []byte("outl 0x1008 2"), 1),
		"wrong-queue-size":     bytes.Replace(raw, []byte("OK 0x0100"), []byte("OK 0x0080"), 1),
		"failed-response":      bytes.Replace(raw, []byte("OK 0x10011af4"), []byte("FAIL"), 1),
		"trailing-blank":       append(append([]byte{}, raw...), '\n'),
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, m) {
				t.Fatal("no-op")
			}
			q := r
			q.RawSHA256 = digest(m)
			if e := check(q, "ABAB", m); e != nil {
				t.Fatal(e)
			}
			if e := checkRaw(q, m); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestElapsedOverflow(t *testing.T) {
	dir := t.TempDir()
	for _, order := range orders {
		r, raw := fixture(t, order)
		r.ElapsedNS = 1 << 62
		b, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, order+".json"), append(b, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, order+".raw"), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := run(dir); e == nil || !strings.Contains(e.Error(), "overflow") {
		t.Fatalf("expected overflow: %v", e)
	}
}
