//go:build linux

package heldledger

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func newProtectedGenesisStore(t *testing.T) Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "protected")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return Store{Path: filepath.Join(dir, "held.json")}
}

func TestCreateHeldGenesisFirstInstallDenyAndReplay(t *testing.T) {
	s := newProtectedGenesisStore(t)
	st, err := s.CreateHeldGenesis()
	if err != nil || !st.Held || st.Key != KeyA || st.Version != Version || st.Sequence != 1 || st.AdmissionIntent {
		t.Fatalf("initial must remain HELD, not a grant: %+v %v", st, err)
	}
	info, err := os.Lstat(s.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe ledger permissions: %v %v", info, err)
	}
	before, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateHeldGenesis(); !errors.Is(err, ErrConflict) {
		t.Fatalf("second genesis silently overwrote: %v", err)
	}
	after, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("duplicate genesis changed prior HELD journal")
	}
	reopened := Store{Path: s.Path}
	recovered, err := reopened.Read()
	if err != nil || !recovered.Held || recovered.Sequence != 1 {
		t.Fatalf("restart did not retain HELD: %+v %v", recovered, err)
	}
	if _, err := reopened.BeginAdmission(1); !errors.Is(err, ErrConflict) {
		t.Fatalf("original clean-state admission accepted HELD: %v", err)
	}
}

func TestCreateHeldGenesisRejectsUntrustedFileAndDirectory(t *testing.T) {
	s := newProtectedGenesisStore(t)
	bad := []Store{{}, {Path: "held.json"}, {Path: filepath.Dir(s.Path) + "/../protected/held.json"}}
	for _, entry := range bad {
		if _, err := entry.CreateHeldGenesis(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe path admitted %s: %v", entry.Path, err)
		}
	}
	target := filepath.Join(filepath.Dir(s.Path), "target")
	if err := os.WriteFile(target, []byte("DO_NOT_TOUCH"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, s.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateHeldGenesis(); !errors.Is(err, ErrConflict) {
		t.Fatalf("symlink not rejected: %v", err)
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "DO_NOT_TOUCH" {
		t.Fatal("symlink target changed")
	}
	if err := os.Remove(s.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(s.Path), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateHeldGenesis(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("insecure parent allowed: %v", err)
	}
	if _, err := os.Lstat(s.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("insecure parent unexpectedly created journal: %v", err)
	}
}

func TestCreateHeldGenesisAmbiguousSyncNeverUnlinks(t *testing.T) {
	for _, point := range []string{"file", "directory"} {
		t.Run(point, func(t *testing.T) {
			s := newProtectedGenesisStore(t)
			fileSync := func(f *os.File) error { return f.Sync() }
			dirSync := func(f *os.File) error { return f.Sync() }
			failure := errors.New("synthetic I/O error")
			if point == "file" {
				fileSync = func(*os.File) error { return failure }
			}
			if point == "directory" {
				dirSync = func(*os.File) error { return failure }
			}
			if _, err := s.createHeldGenesis(fileSync, dirSync); !errors.Is(err, failure) {
				t.Fatalf("sync failure hidden: %v", err)
			}
			if _, err := s.CreateHeldGenesis(); !errors.Is(err, ErrConflict) {
				t.Fatalf("retry after ambiguous sync overwrote: %v", err)
			}
			state, err := s.Read()
			if err != nil || !state.Held || state.Sequence != 1 {
				t.Fatalf("ambiguous sync not fail-closed: %+v %v", state, err)
			}
		})
	}
}

func TestCreateHeldGenesisConcurrentWritersOnlyOne(t *testing.T) {
	s := newProtectedGenesisStore(t)
	const n = 16
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.CreateHeldGenesis(); results <- err }()
	}
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected writer error: %v", err)
		}
	}
	if success != 1 || conflicts != n-1 {
		t.Fatalf("racing genesis accepted %d writers, conflicts %d", success, conflicts)
	}
	st, err := s.Read()
	if err != nil || !st.Held || st.Sequence != 1 {
		t.Fatalf("raced ledger not HELD: %+v %v", st, err)
	}
}

func TestCreateHeldGenesisRejectsSymlinkJournalParent(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "actual")
	if err := os.Mkdir(protected, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatal(err)
	}
	s := Store{Path: filepath.Join(alias, "held.json")}
	if _, err := s.CreateHeldGenesis(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink parent admitted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(protected, "held.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink parent wrote journal: %v", err)
	}
}

func TestCreateHeldGenesisRejectsMissingSyncHooks(t *testing.T) {
	s := newProtectedGenesisStore(t)
	if _, err := s.createHeldGenesis(nil, func(*os.File) error { return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil file sync allowed: %v", err)
	}
	if _, err := os.Lstat(s.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nil sync created record: %v", err)
	}
}
