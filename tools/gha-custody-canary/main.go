package main

// Synthetic-only mount probe for a disposable public runner. This binary
// does not read environment secrets or contact the network or real hosts.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

func verify() error {
	expected, err := strconv.Atoi(os.Getenv("EXPECTED_UID"))
	if err != nil || expected <= 0 || os.Geteuid() != expected {
		return errors.New("UNEXPECTED_CONTAINER_UID")
	}
	raw, err := os.ReadFile("/custody/fixture.txt")
	if err != nil {
		return fmt.Errorf("CUSTODY_READ_DENIED: %w", err)
	}
	if string(raw) != "synthetic-only\n" {
		return errors.New("CUSTODY_FIXTURE_MISMATCH")
	}
	if err := os.WriteFile("/custody/forbidden.txt", []byte("x"), 0600); err == nil {
		return errors.New("CUSTODY_READONLY_BROKEN")
	}
	if err := os.WriteFile("/forbidden-rootfs.txt", []byte("x"), 0600); err == nil {
		return errors.New("ROOTFS_READONLY_BROKEN")
	}
	if err := os.WriteFile("/ledger/uid-witness.txt", []byte("synthetic-ledger-witness\n"), 0600); err != nil {
		return fmt.Errorf("LEDGER_WRITE_DENIED: %w", err)
	}
	return nil
}

func main() {
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(78)
	}
	fmt.Println("SYNTHETIC_RUNNER_UID_MOUNT_PASS")
}
