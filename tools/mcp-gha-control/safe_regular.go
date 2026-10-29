package main

// Linux/GitHub-hosted and Linux/TrueNAS source-only custody qualification.
// File descriptors are opened O_NOFOLLOW + O_NONBLOCK and inspected before
// reading, so symlink and FIFO substitution cannot change what we consume.
import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"syscall"
)

// Metadata alone can miss a same-size in-place write when filesystem clock
// resolution gives the old and new contents identical mtime and ctime.
type pinnedFileInfo struct {
	os.FileInfo
	digest [sha256.Size]byte
}

func digestOpenFile(file *os.File, size int64) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(file, 0, size+1))
	if err != nil {
		return digest, err
	}
	if n != size {
		return digest, errors.New("input length changed during digest")
	}
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func openPinnedRegular(path string, limit int64) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || info.Size() < 1 || info.Size() > limit {
		file.Close()
		return nil, nil, errors.New("unsafe regular input or out-of-bounds file")
	}
	// The path must still name the inode opened. os.SameFile compares inode
	// identity, rather than separately trusting pre-open lstat().
	latest, err := os.Lstat(path)
	if err != nil || !latest.Mode().IsRegular() || !os.SameFile(info, latest) {
		file.Close()
		return nil, nil, errors.New("input pathname replaced before read")
	}
	digest, err := digestOpenFile(file, info.Size())
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	// Keep the descriptor at offset zero for callers that stream or copy it.
	after, err := file.Stat()
	if err != nil || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		file.Close()
		return nil, nil, errors.New("input changed during initial digest")
	}
	return file, &pinnedFileInfo{FileInfo: info, digest: digest}, nil
}

func pinnedFileUnchanged(path string, file *os.File, original os.FileInfo) error {
	pinned, ok := original.(*pinnedFileInfo)
	if !ok {
		return errors.New("missing pinned input digest")
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	oldStat, ok1 := original.Sys().(*syscall.Stat_t)
	newStat, ok2 := after.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 || oldStat.Dev != newStat.Dev || oldStat.Ino != newStat.Ino ||
		oldStat.Nlink != newStat.Nlink || newStat.Nlink != 1 ||
		original.Size() != after.Size() || !original.ModTime().Equal(after.ModTime()) ||
		oldStat.Ctim != newStat.Ctim {
		return errors.New("input inode changed during read")
	}
	latest, err := os.Lstat(path)
	if err != nil || !latest.Mode().IsRegular() || !os.SameFile(after, latest) {
		return errors.New("input pathname replaced during read")
	}
	digest, err := digestOpenFile(file, original.Size())
	if err != nil {
		return err
	}
	if digest != pinned.digest {
		return errors.New("input contents changed during read")
	}
	final, err := file.Stat()
	if err != nil {
		return err
	}
	if final.Size() != after.Size() || !final.ModTime().Equal(after.ModTime()) {
		return errors.New("input changed during final digest")
	}
	return nil
}

// Consumers must read at most original size+1 and confirm exact byte count.
// Reading beyond that detects concurrent append/growth without unbounded IO.
func copyPinnedBytes(dst io.Writer, source *os.File, info os.FileInfo) (int64, error) {
	n, err := io.Copy(dst, io.LimitReader(source, info.Size()+1))
	if err != nil {
		return 0, err
	}
	if n != info.Size() {
		return 0, errors.New("input length changed during read")
	}
	return n, nil
}

func readPinnedRegular(path string, limit int64) ([]byte, error) {
	file, info, err := openPinnedRegular(path, limit)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var buffer bytes.Buffer
	if _, err = copyPinnedBytes(&buffer, file, info); err != nil {
		return nil, err
	}
	if err = pinnedFileUnchanged(path, file, info); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
