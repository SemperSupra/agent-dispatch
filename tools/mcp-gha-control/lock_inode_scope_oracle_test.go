package main

// Public fictional-only native Linux flock behavior tests for independent
// AD #748 P1 safety qualification. Not private product implementation.
import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func fixtureExclusiveFlock(t *testing.T, f *os.File) {
	t.Helper()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	})
}

func TestNativeFlockDifferentInodesAllowConcurrentLocks(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "fictional-policy.lock")
	stale := live + ".stale"
	old, err := os.OpenFile(live, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	fixtureExclusiveFlock(t, old)
	// An actor with write authority over the lock directory can move the
	// locked inode away. The first holder continues to own only that inode.
	if err := os.Rename(live, stale); err != nil {
		t.Fatal(err)
	}
	newLock, err := os.OpenFile(live, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	fixtureExclusiveFlock(t, newLock) // Both LOCK_EX succeed: NOT global CAS.
	oldInfo, err := old.Stat()
	if err != nil {
		t.Fatal(err)
	}
	newInfo, err := newLock.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(oldInfo, newInfo) {
		t.Fatal("fixture did not create distinct lock inodes")
	}
	if resolved, err := os.Lstat(live); err != nil || !os.SameFile(newInfo, resolved) {
		t.Fatal("new lock pathname does not resolve to new inode")
	}
}

func TestNativeOpenNoFollowRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "ledger-real")
	link := filepath.Join(dir, "ledger-link")
	if err := os.WriteFile(real, []byte("fictional"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(link, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err == nil {
		_ = syscall.Close(fd)
		t.Fatal("O_NOFOLLOW unexpectedly followed a symlink")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("unexpected nofollow refusal: %v", err)
	}
}

func TestNativeOpenedIdentityDetectsReplacedLedgerPath(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "ledger.json")
	old := filepath.Join(dir, "old.json")
	if err := os.WriteFile(live, []byte("fictional-1"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(live, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), live)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(live, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live, []byte("fictional-2"), 0600); err != nil {
		t.Fatal(err)
	}
	current, err := os.Lstat(live)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(fi, current) {
		t.Fatal("stale opened file falsely accepted as current live path")
	}
}
