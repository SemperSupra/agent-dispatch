package heldledger

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

// RED hypothesis: kernel isolation is independently associated with the
// CURRENT VHCI key DOWN at sequence 12 and UP 13. The signed guest release
// claim instead names a DIFFERENT signed older DOWN at 10 but same UP 13.
// Existing R27-C only checked the UP, potentially allowing cross-DOWN splice.
func TestR27DCrossDownEventSpliceMustNeverRelease(t *testing.T) {
 s:=Store{Path:filepath.Join(t.TempDir(),"held.json")}
 if _,err:=s.Transition(0,true);err!=nil{t.Fatal(err)}
 if _,err:=s.RequestRelease(1);err!=nil{t.Fatal(err)}
 k:=r27KernelWitness(1,13)
 k.GuestDownEventSequence=12 // independently observed current DOWN
 host:=func(got KernelIsolationClaim)bool{return got==k}
 if _,err:=s.AcknowledgeKernelIsolation(1,k,host);err!=nil{t.Fatal(err)}
 before,err:=os.ReadFile(s.Path);if err!=nil{t.Fatal(err)}
 staleDown:=claim(1,10,13) // valid test signature, wrong DOWN
 if _,err:=s.ConfirmGuestKernelRelease(1,k,host,staleDown,signed);!errors.Is(err,ErrUnverified){
   t.Fatalf("R27_D_RED validly signed earlier DOWN spliced with current UP: %v",err)
 }
 after,err:=os.ReadFile(s.Path)
 if err!=nil||!bytes.Equal(before,after){t.Fatal("cross-DOWN denial mutated HELD bytes",err)}
 t.Log("R27_D_CURRENT_DOWN_REQUIRED_FOR_SIGNED_UP=PASS")
 valid:=claim(1,12,13)
 state,err:=s.ConfirmGuestKernelRelease(1,k,host,valid,signed)
 if err!=nil||state.Held||state.Sequence!=2{t.Fatalf("genuine same-DOWN UP refused: %+v %v",state,err)}
 t.Log("R27_D_MATCHED_SIGNED_DOWN_UP_FSYNC_AND_RELEASE=PASS")
}
