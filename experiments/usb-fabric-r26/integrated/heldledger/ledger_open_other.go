//go:build !linux

package heldledger

import "os"

// Non-Linux platforms retain R13 Lstat/SameFile protection only.
// Concurrent path swaps are NOT qualified there; callers must isolate the
// journal directory or provide a platform-specific no-follow open.
func openJournalNoFollow(path string)(*os.File,error){return os.Open(path)}
