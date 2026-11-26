//go:build linux

package heldledger

// CreateHeldGenesis is a fail-closed first-install fence on the ORIGINAL
// heldledger, not a grant or clean-state bootstrap. A caller must hold the
// canonical USB resource OS owner before invoking it. This function cannot
// establish that the old QMP/USBIP/kernel/network/guest paths were isolated.
//
// It deliberately creates HELD with sequence=1. R27-S recovered admission
// requires a preexisting CLEAN even sequence>=2, so it must continue to deny.
// A later, independently authorized and observed release is a separate gate.
import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// CreateHeldGenesis exclusively creates a journal in a protected directory.
// It never replaces an existing file or treats an absent file as clean.
// The file and parent directory must both fsync before success is returned.
// On ambiguous failure, the new file is deliberately left in place; no
// automatic rollback/unlink can make a successor mistake the state for clean.
func (s Store) CreateHeldGenesis() (State, error) {
	return s.createHeldGenesis((*os.File).Sync, (*os.File).Sync)
}

// The sync seams are only for bounded fault-injection tests. Production calls
// always use os.File.Sync above. No external caller can substitute a probe.
func (s Store) createHeldGenesis(fileSync, parentSync func(*os.File) error) (State, error) {
	return s.createGenesisRecord(State{Version: Version, Sequence: 1, Key: KeyA, Held: true}, fileSync, parentSync)
}

// CreateScopedHeldGenesis persists the exact enrolled resource scope in the
// original journal. Only HELD bootstrap is implemented: every legacy grant,
// release and recovery API rejects v2. Trusted enrollment and effective
// isolation are independent prerequisites for future v2 transitions.
func (s Store) CreateScopedHeldGenesis(scope GenesisScope) (State, error) {
	return s.createScopedHeldGenesis(scope, (*os.File).Sync, (*os.File).Sync)
}

func (s Store) createScopedHeldGenesis(scope GenesisScope, fileSync, parentSync func(*os.File) error) (State, error) {
	nonce,err:=newGenesisNonce()
	if err!=nil{return State{},err}
	st := State{Version: ScopedVersion, Sequence: 1, Key: KeyA, Held: true, Scope: &scope, GenesisNonce:nonce}
	if err := validateScopedHeldGenesis(st, scope); err != nil { return State{}, err }
	return s.createGenesisRecord(st, fileSync, parentSync)
}

func (s Store) createGenesisRecord(st State, fileSync, parentSync func(*os.File) error) (State, error) {
	if s.Path == "" || !filepath.IsAbs(s.Path) || filepath.Clean(s.Path) != s.Path ||
		filepath.Base(s.Path) == "." || filepath.Base(s.Path) == "/" ||
		fileSync == nil || parentSync == nil {
		return State{}, fmt.Errorf("%w: unsafe genesis path/sync", ErrInvalid)
	}
	dir := filepath.Dir(s.Path)
	dirfd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return State{}, fmt.Errorf("%w: protected journal parent: %v", ErrInvalid, err)
	}
	parent := os.NewFile(uintptr(dirfd), dir)
	if parent == nil {
		_ = syscall.Close(dirfd)
		return State{}, ErrInvalid
	}
	defer parent.Close()
	info, err := parent.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return State{}, fmt.Errorf("%w: protected journal directory mode", ErrInvalid)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return State{}, fmt.Errorf("%w: journal directory owner", ErrInvalid)
	}
	// The O_EXCL|O_CREAT operation is atomic with respect to existence of
	// the final path. Relative Openat is pinned to the already verified parent.
	// No temp-file rename may clobber an existing HELD, clean or corrupt log.
	fd, err := syscall.Openat(dirfd, filepath.Base(s.Path),
		syscall.O_WRONLY|syscall.O_EXCL|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if errors.Is(err, syscall.EEXIST) {
		return State{}, ErrConflict
	}
	if err != nil {
		return State{}, fmt.Errorf("%w: exclusive genesis create: %v", ErrInvalid, err)
	}
	file := os.NewFile(uintptr(fd), s.Path)
	if file == nil {
		_ = syscall.Close(fd)
		return State{}, ErrInvalid
	}
	// Once created, do not unlink on any subsequent error (including EIO).
	// A partially visible record is invalid/HELD, never authorization.
	data, err := json.Marshal(st)
	if err != nil {
		_ = file.Close()
		return State{}, err
	}
	data = append(data, '\n')
	if err = file.Chmod(0600); err != nil {
		_ = file.Close()
		return State{}, err
	}
	if n, writeErr := file.Write(data); writeErr != nil || n != len(data) {
		_ = file.Close()
		if writeErr != nil {
			return State{}, writeErr
		}
		return State{}, fmt.Errorf("%w: short genesis write", ErrInvalid)
	}
	if err = fileSync(file); err != nil {
		_ = file.Close()
		return State{}, err
	}
	if err = file.Close(); err != nil {
		return State{}, err
	}
	if err = parentSync(parent); err != nil {
		return State{}, err
	}
	return st, nil
}
