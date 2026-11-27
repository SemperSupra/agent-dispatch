package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func makeCohort(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, order := range orders {
		r, raw := fixture(t, order)
		r.ElapsedNS = 1
		b, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		for name, data := range map[string][]byte{order + ".json": append(b, '\n'), order + ".raw": raw} {
			if e = os.WriteFile(filepath.Join(dir, name), data, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
	return dir
}
func TestIntakeHoldouts(t *testing.T) {
	for _, kind := range []string{"valid", "root-link", "member-link", "fifo", "extra", "missing", "directory", "oversize", "cross-schedule"} {
		t.Run(kind, func(t *testing.T) {
			dir := makeCohort(t)
			path := filepath.Join(dir, "ABAB.raw")
			target := filepath.Join(dir, "AABB.raw")
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			switch kind {
			case "root-link":
				link := filepath.Join(t.TempDir(), "link")
				must(os.Symlink(dir, link))
				dir = link
			case "member-link":
				must(os.Remove(path))
				must(os.Symlink(target, path))
			case "fifo":
				must(os.Remove(path))
				must(syscall.Mkfifo(path, 0600))
			case "extra":
				must(os.WriteFile(filepath.Join(dir, "extra"), []byte("x"), 0600))
			case "missing":
				must(os.Remove(path))
			case "directory":
				must(os.Remove(path))
				must(os.Mkdir(path, 0700))
			case "oversize":
				must(os.WriteFile(path, make([]byte, (1<<20)+1), 0600))
			case "cross-schedule":
				raw, e := os.ReadFile(target)
				must(e)
				must(os.WriteFile(path, raw, 0600))
				r, _ := fixture(t, "ABAB")
				r.RawSHA256 = digest(raw)
				b, e := json.Marshal(r)
				must(e)
				must(os.WriteFile(filepath.Join(dir, "ABAB.json"), append(b, '\n'), 0600))
			}
			e := run(dir)
			if (e == nil) != (kind == "valid") {
				t.Fatalf("%s: %v", kind, e)
			}
		})
	}
}
func TestPinnedDirectoryRename(t *testing.T) {
	parent := t.TempDir()
	d := filepath.Join(parent, "cohort")
	moved := filepath.Join(parent, "moved")
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(os.Mkdir(d, 0700))
	must(os.WriteFile(filepath.Join(d, "witness"), []byte("original"), 0600))
	fd, e := openCohort(d)
	must(e)
	defer fd.Close()
	must(os.Rename(d, moved))
	must(os.Mkdir(d, 0700))
	must(os.WriteFile(filepath.Join(d, "witness"), []byte("replacement"), 0600))
	got, e := bounded(fd, "witness", 64)
	must(e)
	if !bytes.Equal(got, []byte("original")) {
		t.Fatalf("read replacement: %q", got)
	}
}
func TestReportedTimingNotVerified(t *testing.T) {
	dir := makeCohort(t)
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	old := os.Stdout
	os.Stdout = w
	e = run(dir)
	os.Stdout = old
	w.Close()
	var out bytes.Buffer
	_, readErr := out.ReadFrom(r)
	r.Close()
	if e != nil || readErr != nil {
		t.Fatalf("%v %v", e, readErr)
	}
	if !strings.Contains(out.String(), "reported_elapsed_sum_ns=6 timing_authentication=unverified") || strings.Contains(out.String(), "schedules_per_min") {
		t.Fatal(out.String())
	}
}
