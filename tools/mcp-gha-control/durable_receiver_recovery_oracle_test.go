//go:build linux

package main

// A PUBLIC SYNTHETIC receiver ledger oracle, not a real external effect sink.
// POSIX file locks plus fsynced replace let a process crash after a journal
// commit; the caller must resolve UNKNOWN by read-only receipt lookup. The
// "effect" in this fixture IS the journal increment, not a separate API.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

type syntheticDurableIntent struct {
	EffectID     string `json:"effect_id"`
	IntentSHA256 string `json:"intent_sha256"`
	Epoch        uint64 `json:"epoch"`
	BudgetUnits  uint64 `json:"budget_units"`
}

type syntheticDurableReceipt struct {
	Intent syntheticDurableIntent `json:"intent"`
	Seq    uint64                 `json:"seq"`
}

type syntheticDurableState struct {
	HighWater  uint64                             `json:"high_water"`
	BudgetUsed uint64                             `json:"budget_used"`
	Commits    uint64                             `json:"commits"`
	Receipts   map[string]syntheticDurableReceipt `json:"receipts"`
}

const syntheticBudgetCeiling uint64 = 5

// Synthetic provisioning is an explicit operation, separate from a receiver
// read. A missing journal after a prior commit must never reset the budget.
func syntheticBootstrap(root string) error {
	// Provisioning is create-once even if state.json later disappears. A
	// marker that survives journal loss prevents an ordinary recovery path
	// from silently reinitializing spent budget and committed effect IDs.
	marker, err := os.OpenFile(filepath.Join(root, ".receiver-provisioned"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := marker.Sync(); err != nil {
		marker.Close()
		return err
	}
	if err := marker.Close(); err != nil {
		return err
	}
	markerDir, err := os.Open(root)
	if err != nil {
		return err
	}
	if err := markerDir.Sync(); err != nil {
		markerDir.Close()
		return err
	}
	if err := markerDir.Close(); err != nil {
		return err
	}
	state := syntheticDurableState{Receipts: make(map[string]syntheticDurableReceipt)}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(root, "state.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err // repeated bootstrap cannot overwrite committed state
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func syntheticReadState(root string) (syntheticDurableState, error) {
	raw, err := os.ReadFile(filepath.Join(root, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return syntheticDurableState{}, errors.New("SYNTHETIC_LEDGER_MISSING_DENIED")
	}
	if err != nil {
		return syntheticDurableState{}, err
	}
	var state syntheticDurableState
	if err := json.Unmarshal(raw, &state); err != nil || state.Receipts == nil || state.BudgetUsed > syntheticBudgetCeiling || state.Commits != uint64(len(state.Receipts)) {
		return syntheticDurableState{}, errors.New("SYNTHETIC_LEDGER_UNTRUSTED_DENIED")
	}
	// Do not trust merely well-formed JSON and a matching receipt count:
	// under-reported usage or duplicated sequence IDs could silently grant
	// an extra budget after recovery. Validate the entire synthetic journal.
	var sum, maxEpoch uint64
	seqs := make(map[uint64]bool, len(state.Receipts))
	for effectID, receipt := range state.Receipts {
		in := receipt.Intent
		if strings.TrimSpace(effectID) == "" || in.EffectID != effectID ||
			len(in.IntentSHA256) != 64 || in.Epoch == 0 || in.BudgetUnits == 0 ||
			in.BudgetUnits > syntheticBudgetCeiling-sum ||
			receipt.Seq == 0 || receipt.Seq > state.Commits || seqs[receipt.Seq] {
			return syntheticDurableState{}, errors.New("SYNTHETIC_LEDGER_UNTRUSTED_DENIED")
		}
		if _, err := hex.DecodeString(in.IntentSHA256); err != nil {
			return syntheticDurableState{}, errors.New("SYNTHETIC_LEDGER_UNTRUSTED_DENIED")
		}
		seqs[receipt.Seq] = true
		sum += in.BudgetUnits
		if in.Epoch > maxEpoch {
			maxEpoch = in.Epoch
		}
	}
	if sum != state.BudgetUsed || maxEpoch != state.HighWater {
		return syntheticDurableState{}, errors.New("SYNTHETIC_LEDGER_UNTRUSTED_DENIED")
	}
	return state, nil
}

func syntheticStoreState(root string, state syntheticDurableState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(root, ".staged-receipt-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(root, "state.json")); err != nil {
		return err
	}
	dir, err := os.Open(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// syntheticApply commits only receiver-local journal state. The lock is shared
// across processes, unlike an in-process mutex. It cannot make a separate
// provider HTTP call atomic; that remains a protected production HOLD.
func syntheticApply(root string, intent syntheticDurableIntent) (syntheticDurableReceipt, bool, error) {
	var denied syntheticDurableReceipt
	if strings.TrimSpace(intent.EffectID) == "" || len(intent.IntentSHA256) != 64 || intent.Epoch == 0 || intent.BudgetUnits == 0 {
		return denied, false, errors.New("INVALID_INTENT_DENIED")
	}
	lock, err := os.OpenFile(filepath.Join(root, ".receiver-lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return denied, false, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return denied, false, err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	state, err := syntheticReadState(root)
	if err != nil {
		return denied, false, err
	}
	if previous, found := state.Receipts[intent.EffectID]; found {
		if previous.Intent != intent {
			return denied, false, errors.New("DUPLICATE_EFFECT_CONFLICT_DENIED")
		}
		return previous, true, nil
	}
	if intent.Epoch < state.HighWater {
		return denied, false, errors.New("STALE_EPOCH_DENIED")
	}
	if intent.BudgetUnits > syntheticBudgetCeiling-state.BudgetUsed {
		return denied, false, errors.New("BUDGET_EXHAUSTED_DENIED")
	}
	state.Commits++
	state.BudgetUsed += intent.BudgetUnits
	if intent.Epoch > state.HighWater {
		state.HighWater = intent.Epoch
	}
	receipt := syntheticDurableReceipt{Intent: intent, Seq: state.Commits}
	state.Receipts[intent.EffectID] = receipt
	if err := syntheticStoreState(root, state); err != nil {
		return denied, false, err
	}
	return receipt, false, nil
}

func syntheticReadOnlyReceipt(root, effectID string) (syntheticDurableReceipt, bool, error) {
	state, err := syntheticReadState(root)
	if err != nil {
		return syntheticDurableReceipt{}, false, err
	}
	result, found := state.Receipts[effectID]
	return result, found, nil
}

func syntheticIntent(effect string, epoch, budget uint64) syntheticDurableIntent {
	sum := sha256.Sum256([]byte("fictional-intent-v1:" + effect))
	return syntheticDurableIntent{EffectID: effect, IntentSHA256: hex.EncodeToString(sum[:]), Epoch: epoch, BudgetUnits: budget}
}

func TestSyntheticReceiverChildProcess(t *testing.T) {
	if os.Getenv("SYNTHETIC_RECEIVER_CHILD") != "1" {
		return
	}
	root := os.Getenv("SYNTHETIC_RECEIVER_ROOT")
	intent := syntheticIntent("one-fictional-effect", 7, 2)
	receipt, replay, err := syntheticApply(root, intent)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(78)
	}
	if os.Getenv("SYNTHETIC_RECEIVER_CRASH_AFTER_COMMIT") == "1" {
		os.Exit(71)
	}
	fmt.Printf("SYNTHETIC_COMMIT_OR_REPLAY seq=%d replay=%t\n", receipt.Seq, replay)
}

func syntheticRunChild(root string, crashAfterCommit bool) ([]byte, error) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestSyntheticReceiverChildProcess$")
	cmd.Env = append(os.Environ(), "SYNTHETIC_RECEIVER_CHILD=1", "SYNTHETIC_RECEIVER_ROOT="+root)
	if crashAfterCommit {
		cmd.Env = append(cmd.Env, "SYNTHETIC_RECEIVER_CRASH_AFTER_COMMIT=1")
	}
	return cmd.CombinedOutput()
}

func TestSyntheticReceiverConcurrentIndependentProcessesAndBudget(t *testing.T) {
	root := t.TempDir()
	if err := syntheticBootstrap(root); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failed := make(chan string, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := syntheticRunChild(root, false)
			if err != nil || !strings.Contains(string(data), "SYNTHETIC_COMMIT_OR_REPLAY seq=1") {
				failed <- fmt.Sprintf("child failed: %v %s", err, data)
			}
		}()
	}
	wg.Wait()
	close(failed)
	for message := range failed {
		t.Error(message)
	}
	state, err := syntheticReadState(root)
	if err != nil {
		t.Fatal(err)
	}
	if state.Commits != 1 || state.BudgetUsed != 2 || state.HighWater != 7 || len(state.Receipts) != 1 {
		t.Fatalf("multiple processes violated single committed receipt: %+v", state)
	}
	if _, _, err := syntheticApply(root, syntheticIntent("stale-other-effect", 6, 1)); err == nil || !strings.Contains(err.Error(), "STALE_EPOCH_DENIED") {
		t.Fatalf("stale epoch accepted: %v", err)
	}
	if _, _, err := syntheticApply(root, syntheticIntent("new-allowed-effect", 8, 3)); err != nil {
		t.Fatalf("remaining budget unexpectedly rejected: %v", err)
	}
	if _, _, err := syntheticApply(root, syntheticIntent("over-budget-effect", 9, 1)); err == nil || !strings.Contains(err.Error(), "BUDGET_EXHAUSTED_DENIED") {
		t.Fatalf("overbudget accepted: %v", err)
	}
	state, err = syntheticReadState(root)
	if err != nil || state.Commits != 2 || state.BudgetUsed != 5 {
		t.Fatalf("budget/commits drift: state=%+v err=%v", state, err)
	}
}

func TestSyntheticReceiverCrashAfterJournalCommitReadOnlyRecovery(t *testing.T) {
	root := t.TempDir()
	if err := syntheticBootstrap(root); err != nil {
		t.Fatal(err)
	}
	out, err := syntheticRunChild(root, true)
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 71 {
		t.Fatalf("expected crash after fsync/rename: output=%q err=%v", out, err)
	}
	// A fresh process/caller resolves UNKNOWN via read-only lookup, NOT a
	// blind second POST. The journal is the only synthetic effect.
	receipt, found, err := syntheticReadOnlyReceipt(root, "one-fictional-effect")
	if err != nil || !found || receipt.Seq != 1 {
		t.Fatalf("lost durable receipt after crash: %+v found=%v err=%v", receipt, found, err)
	}
	state, err := syntheticReadState(root)
	if err != nil || state.Commits != 1 || state.BudgetUsed != 2 {
		t.Fatalf("crash doubled or lost effect: %+v err=%v", state, err)
	}
	// A same-ID retry, if a faulty caller attempts one, cannot allocate a
	// second journal effect. Production must prefer receipt-only resolution.
	same, replay, err := syntheticApply(root, syntheticIntent("one-fictional-effect", 7, 2))
	if err != nil || !replay || same != receipt {
		t.Fatalf("idempotent replay diverged: %+v replay=%t err=%v", same, replay, err)
	}
}

func TestSyntheticReceiverCorruptionFailsClosed(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "state.json"), []byte(`{"commits":1,"budget_used":0,"receipts":null}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := syntheticApply(root, syntheticIntent("fake-effect", 1, 1)); err == nil || !strings.Contains(err.Error(), "SYNTHETIC_LEDGER_UNTRUSTED_DENIED") {
		t.Fatalf("corrupted durable ledger accepted: %v", err)
	}
	if _, _, err := syntheticReadOnlyReceipt(root, "fake-effect"); err == nil {
		t.Fatal("corrupt journal falsely produced safe readback")
	}
}

// A JSON ledger can be syntactically valid yet understate spent budget or
// contain forged receipts. These negative oracles must fail before any effect.
func TestSyntheticReceiverReceiptInvariantsDenyBudgetReset(t *testing.T) {
	root := t.TempDir()
	if err := syntheticBootstrap(root); err != nil { t.Fatal(err) }
	for _, in := range []syntheticDurableIntent{
		syntheticIntent("alpha", 7, 2),
		syntheticIntent("beta", 8, 1),
	} {
		if _, _, err := syntheticApply(root, in); err != nil { t.Fatal(err) }
	}
	original, err := syntheticReadState(root)
	if err != nil { t.Fatal(err) }
	for _, tc := range []struct {
		name string
		mutate func(*syntheticDurableState)
	}{
		{"underreported-budget", func(s *syntheticDurableState) { s.BudgetUsed = 0 }},
		{"high-water-rollback", func(s *syntheticDurableState) { s.HighWater = 7 }},
		{"inflated-high-water", func(s *syntheticDurableState) { s.HighWater = 99 }},
		{"duplicated-sequence", func(s *syntheticDurableState) { r := s.Receipts["beta"]; r.Seq = 1; s.Receipts["beta"] = r }},
		{"zero-sequence", func(s *syntheticDurableState) { r := s.Receipts["beta"]; r.Seq = 0; s.Receipts["beta"] = r }},
		{"mismatched-effect-key", func(s *syntheticDurableState) { r := s.Receipts["beta"]; r.Intent.EffectID = "other"; s.Receipts["beta"] = r }},
		{"zero-receipt-budget", func(s *syntheticDurableState) { r := s.Receipts["beta"]; r.Intent.BudgetUnits = 0; s.Receipts["beta"] = r }},
		{"malformed-intent-digest", func(s *syntheticDurableState) { r := s.Receipts["beta"]; r.Intent.IntentSHA256 = strings.Repeat("z", 64); s.Receipts["beta"] = r }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each subtest receives independent map copies; never mutate
			// the source fixture or turn a prior failure into a later case.
			state := original
			state.Receipts = make(map[string]syntheticDurableReceipt, len(original.Receipts))
			for k, r := range original.Receipts { state.Receipts[k] = r }
			tc.mutate(&state)
			raw, err := json.Marshal(state)
			if err != nil { t.Fatal(err) }
			if err := os.WriteFile(filepath.Join(root, "state.json"), raw, 0600); err != nil { t.Fatal(err) }
			if _, _, err := syntheticApply(root, syntheticIntent("gamma", 9, 1)); err == nil || !strings.Contains(err.Error(), "SYNTHETIC_LEDGER_UNTRUSTED_DENIED") {
				t.Fatalf("corrupted receipt admitted new budget: %v", err)
			}
			if _, found, err := syntheticReadOnlyReceipt(root, "alpha"); err == nil || found {
				t.Fatalf("corrupt receipt falsely became trusted readback: found=%v err=%v", found, err)
			}
		})
	}
}

func TestSyntheticReceiverMissingJournalCannotResetCommittedEffect(t *testing.T) {
	root := t.TempDir()
	intent := syntheticIntent("fictional-persisted-effect", 7, 2)
	if _, _, err := syntheticApply(root, intent); err == nil || !strings.Contains(err.Error(), "SYNTHETIC_LEDGER_MISSING_DENIED") {
		t.Fatalf("implicit empty-ledger bootstrap must deny: %v", err)
	}
	if _, found, err := syntheticReadOnlyReceipt(root, intent.EffectID); err == nil || found {
		t.Fatalf("read-only missing-ledger result must be untrusted: found=%v err=%v", found, err)
	}
	if err := syntheticBootstrap(root); err != nil {
		t.Fatal(err)
	}
	if err := syntheticBootstrap(root); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second bootstrap overwrote active ledger: %v", err)
	}
	if _, replay, err := syntheticApply(root, intent); err != nil || replay {
		t.Fatalf("first explicit-bootstrap commit failed: replay=%v err=%v", replay, err)
	}
	if err := os.Remove(filepath.Join(root, "state.json")); err != nil {
		t.Fatal(err)
	}
	if err := syntheticBootstrap(root); !errors.Is(err, os.ErrExist) {
		t.Fatalf("lost-ledger bootstrap must not reset committed state: %v", err)
	}
	for _, attempt := range []syntheticDurableIntent{intent, syntheticIntent("fictional-new-after-loss", 8, 1)} {
		if _, _, err := syntheticApply(root, attempt); err == nil || !strings.Contains(err.Error(), "SYNTHETIC_LEDGER_MISSING_DENIED") {
			t.Fatalf("lost ledger improperly reset dedupe or budget: intent=%+v err=%v", attempt, err)
		}
	}
	if _, found, err := syntheticReadOnlyReceipt(root, intent.EffectID); err == nil || found {
		t.Fatalf("lost ledger falsely recovered a receipt: found=%v err=%v", found, err)
	}
	if _, err := os.Stat(filepath.Join(root, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("denied requests unexpectedly recreated a journal: %v", err)
	}
}

func TestSyntheticReceiverNoImplicitBudgetExpansion(t *testing.T) {
	root := t.TempDir()
	if err := syntheticBootstrap(root); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < int(syntheticBudgetCeiling); i++ {
		id := "synth-" + strconv.Itoa(i)
		if _, _, err := syntheticApply(root, syntheticIntent(id, 1, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := syntheticApply(root, syntheticIntent("extra", 2, 1)); err == nil {
		t.Fatal("receiver accepted unbudgeted new effect")
	}
}
