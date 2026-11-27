package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Only the pinned six-schedule fixture grammar is supported. Not a general
// QTest parser, a producer authenticator, or proof of process cleanup.
var rawLine = regexp.MustCompile(`^\[([IRS]) (\+?)([0-9]{1,12})\.([0-9]{6})\] (.+)$`)
var hexValue = regexp.MustCompile(`^OK 0x[0-9a-f]{1,8}$`)

type rawReader struct {
	lines []string
	i     int
	last  uint64
}

func (q *rawReader) line(kind, sign string) (string, error) {
	if q.i >= len(q.lines) {
		return "", fmt.Errorf("missing %s at line %d", kind, q.i+1)
	}
	m := rawLine.FindStringSubmatch(q.lines[q.i])
	q.i++
	if m == nil || m[1] != kind || m[2] != sign {
		return "", fmt.Errorf("unexpected record at line %d", q.i)
	}
	sec, e := strconv.ParseUint(m[3], 10, 64)
	if e != nil {
		return "", e
	}
	us, e := strconv.ParseUint(m[4], 10, 64)
	if e != nil {
		return "", e
	}
	t := sec*1000000 + us
	if sign == "+" {
		if t < q.last {
			return "", fmt.Errorf("timestamp inversion at line %d", q.i)
		}
		q.last = t
	}
	return m[5], nil
}
func (q *rawReader) take(cmd string, want *uint32) error {
	got, e := q.line("R", "+")
	if e != nil {
		return e
	}
	if got != cmd {
		return fmt.Errorf("line %d expected %q got %q", q.i, cmd, got)
	}
	got, e = q.line("S", "+")
	if e != nil {
		return e
	}
	if want == nil {
		if got != "OK" {
			return fmt.Errorf("line %d expected acknowledgement", q.i)
		}
		return nil
	}
	if !hexValue.MatchString(got) {
		return fmt.Errorf("line %d expected hex response", q.i)
	}
	v, e := strconv.ParseUint(got[5:], 16, 32)
	if e != nil || uint32(v) != *want {
		return fmt.Errorf("line %d read mismatch for %s: got %s expected %#x", q.i, cmd, got, *want)
	}
	return nil
}
func (q *rawReader) write(cmd string) error          { return q.take(cmd, nil) }
func (q *rawReader) read(cmd string, v uint32) error { return q.take(cmd, &v) }
func (q *rawReader) snap(v Snap) error {
	for i, cmd := range []string{"inw 0x100e", "inw 0x100c", "inl 0x1008"} {
		if e := q.read(cmd, v[i]); e != nil {
			return e
		}
	}
	return nil
}
func checkRaw(r Receipt, raw []byte) error {
	// Caller must first use the independent typed fixed oracle. Bind all observed
	// operations and readbacks to that receipt; the typed checker supplies semantics.
	if len(raw) == 0 || len(raw) > 1<<20 || raw[len(raw)-1] != '\n' {
		return fmt.Errorf("raw size or final LF")
	}
	for _, b := range raw {
		if b != '\n' && (b < 32 || b > 126) {
			return fmt.Errorf("non-ASCII raw byte")
		}
	}
	q := rawReader{lines: strings.Split(string(raw[:len(raw)-1]), "\n")}
	if len(q.lines) != 122 {
		return fmt.Errorf("expected 60 request/response pairs plus bounds")
	}
	s, e := q.line("I", "")
	if e != nil || s != "OPENED" {
		return fmt.Errorf("opening record: %v", e)
	}
	for _, op := range []struct {
		cmd   string
		read  bool
		value uint32
	}{
		{"outl 0xcf8 0x80003000", false, 0}, {"inl 0xcfc", true, 0x10011af4},
		{"outl 0xcf8 0x80003010", false, 0}, {"outl 0xcfc 0x1001", false, 0},
		{"outl 0xcf8 0x80003004", false, 0}, {"outw 0xcfc 0x1", false, 0},
		{"outl 0xcf8 0x80003010", false, 0}, {"inl 0xcfc", true, 0x1001},
		{"memset 0x1000 0x4000 0", false, 0}, {"outb 0x1012 0", false, 0},
		{"outb 0x1012 1", false, 0}, {"outb 0x1012 3", false, 0}, {"outw 0x100e 0", false, 0},
	} {
		if op.read {
			e = q.read(op.cmd, op.value)
		} else {
			e = q.write(op.cmd)
		}
		if e != nil {
			return e
		}
	}
	if e = q.snap(Snap{0, 256, 0}); e != nil {
		return e
	}
	if e = q.read("inb 0x1012", 3); e != nil {
		return e
	}
	for _, step := range r.Steps {
		if e = q.snap(step.Before); e != nil {
			return e
		}
		switch step.Action {
		case "select":
			if step.Actor == "A" {
				e = q.write("outw 0x100e 1")
			} else if step.Actor == "B" {
				e = q.write("outw 0x100e 0")
			} else {
				return fmt.Errorf("unknown actor")
			}
		case "write":
			e = q.write("outl 0x1008 1")
		case "read":
			e = q.read("inl 0x1008", step.Before[2])
		default:
			return fmt.Errorf("unknown action")
		}
		if e != nil {
			return e
		}
		if e = q.snap(step.After); e != nil {
			return e
		}
	}
	if e = q.write("outw 0x100e 0"); e != nil {
		return e
	}
	if e = q.snap(r.Present); e != nil {
		return e
	}
	if e = q.write("outw 0x100e 1"); e != nil {
		return e
	}
	if e = q.snap(r.Absent); e != nil {
		return e
	}
	if e = q.read("inb 0x1012", r.Status); e != nil {
		return e
	}
	if e = q.write("outb 0x1012 0"); e != nil {
		return e
	}
	if e = q.read("inb 0x1012", r.ResetStatus); e != nil {
		return e
	}
	if e = q.write("outw 0x100e 0"); e != nil {
		return e
	}
	if e = q.snap(r.ResetPresent); e != nil {
		return e
	}
	s, e = q.line("I", "+")
	if e != nil || s != "CLOSED" || q.i != len(q.lines) {
		return fmt.Errorf("closing record: %v", e)
	}
	return nil
}
