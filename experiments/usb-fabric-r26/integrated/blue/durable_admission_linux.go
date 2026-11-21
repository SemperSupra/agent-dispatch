//go:build linux

package blue

// R27-S: compose original R27-Q Linux host-local single owner and R27-O
// persistent startup verification with ORIGINAL heldledger admission fsync.
// This is a distinct, opt-in safe candidate: legacy New and prior recovered
// constructors are NOT production-safe after SIGKILL without this write-ahead.
import (
 "example.org/usb-fabric-r26-integrated/heldledger"
)

// NewAfterExclusiveDurableAdmission performs: OS lock -> clean ledger check ->
// persisted admission-intent fsync -> return original Go Manager.
// A crash after return but before any guest key-down must remain quarantined.
func NewAfterExclusiveDurableAdmission(device,port string,exec Executor,
 store heldledger.Store)(*Manager,*USBIPRecoveredOwner,error){
 m,owner,err:=NewAfterExclusiveJournalRecovery(device,port,exec,store)
 if err!=nil{return m,owner,err}
 st,err:=store.Read()
 if err!=nil{
  _=owner.Close()
  return nil,nil,ErrQuarantined
 }
 if _,err=store.BeginAdmission(st.Sequence);err!=nil{
  _=owner.Close()
  return nil,nil,ErrQuarantined
 }
 return m,owner,nil
}
