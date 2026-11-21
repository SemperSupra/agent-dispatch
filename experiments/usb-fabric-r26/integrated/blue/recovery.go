package blue

// R27-O: a conservative startup API for a durable USB/IP broker.
// The legacy New constructor does NOT inspect persistent state; callers that
// manage a real host device must migrate to this recovered startup contract.
//
// This is not distributed fencing: the host must ALSO enforce one live owner,
// exclusive journal directory ACLs, and independent device isolation proofs.
import (
 "os"
 "example.org/usb-fabric-r26-integrated/heldledger"
)

// NewAfterJournalRecovery refuses to advertise a reservable device after a
// restart unless a preexisting regular authoritative journal is already in a
// fully cleared state. Missing, corrupt, HELD, release-intent, or unverified
// bootstrap state is quarantined. This method NEVER clears HELD.
// A first-boot device requires separately authorized initialization; treating
// a missing file as clean would reintroduce a crash/restart ABA bypass.
func NewAfterJournalRecovery(device,port string,exec Executor,store heldledger.Store)(*Manager,error) {
 m:=New(device,port,exec)
 // Check file existence separately: Store.Read returns a default clean
 // zero-sequence State on absent files for legacy initialization semantics.
 // That default MUST NOT authorize startup after an unrecognized restart.
 if store.Path=="" {
  m.Offline()
  return m,ErrQuarantined
 }
 info,err:=os.Lstat(store.Path)
 if err!=nil || !info.Mode().IsRegular(){
  m.Offline()
  return m,ErrQuarantined
 }
 state,err:=store.Read()
 if err!=nil || state.Held || state.AdmissionIntent || state.ReleasePhase!="" ||
  state.Sequence<2 || state.Sequence%2!=0 {
  m.Offline()
  return m,ErrQuarantined
 }
 // New already generates a fresh unique epoch and starts Available only
 // after entropy succeeds. Preserve any entropy fail-closed quarantine.
 if m.state==Quarantined{return m,ErrQuarantined}
 return m,nil
}
