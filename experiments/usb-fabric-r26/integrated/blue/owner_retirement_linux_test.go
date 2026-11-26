//go:build linux

package blue

import (
 "errors"
 "sync"
 "testing"

 "example.org/usb-fabric-r26-integrated/heldledger"
)

func TestClosedRecoveredOwnerCannotReuseManager(t *testing.T){
 store:=r27QCleanJournal(t)
 old,o,err:=NewAfterExclusiveJournalRecovery("retirement-device","retirement-port",nil,store)
 if err!=nil{t.Fatal(err)}
 if err=o.Close();err!=nil{t.Fatal(err)}
 fresh,f,err:=NewAfterExclusiveJournalRecovery("retirement-device","retirement-port",nil,store)
 if err!=nil{t.Fatal(err)}
 defer f.Close()
 if _,err=old.Reserve("stale","retirement-device","retirement-port");!errors.Is(err,ErrQuarantined){t.Fatalf("closed owner retained reserve: %v",err)}
 if err=old.RestoreAfterVerifiedGuestUp(store,2,heldledger.ReleaseClaim{},nil);!errors.Is(err,ErrDenied){t.Fatalf("retired guest restoration not denied: %v",err)}
 if err=old.RestoreAfterVerifiedKernelUp(store,2,heldledger.KernelIsolationClaim{},nil,heldledger.ReleaseClaim{},nil);!errors.Is(err,ErrDenied){t.Fatalf("retired kernel restoration not denied: %v",err)}
 lease,err:=fresh.Reserve("fresh","retirement-device","retirement-port")
 if err!=nil{t.Fatal(err)}
 if err=fresh.Revoke(lease);err!=nil{t.Fatal(err)}
 t.Log("RETIRED_OWNER_STALE_MANAGER_DENIED=PASS")
}

func TestRecoveredOwnerCloseRacesReserve(t *testing.T){
 for i:=0;i<40;i++{
  store:=r27QCleanJournal(t)
  m,o,err:=NewAfterExclusiveJournalRecovery("retirement-race-device","retirement-race-port",nil,store)
  if err!=nil{t.Fatal(err)}
  start:=make(chan struct{})
  var wg sync.WaitGroup
  var closeErr,reserveErr error
  var lease Lease
  wg.Add(2)
  go func(){defer wg.Done();<-start;closeErr=o.Close()}()
  go func(){defer wg.Done();<-start;lease,reserveErr=m.Reserve("consumer","retirement-race-device","retirement-race-port")}()
  close(start)
  wg.Wait()
  if closeErr==nil{
   if !errors.Is(reserveErr,ErrQuarantined){t.Fatalf("close won but reserve not denied: %v",reserveErr)}
  }else{
   if !errors.Is(closeErr,ErrDenied)||reserveErr!=nil{t.Fatalf("unexpected linearization: close=%v reserve=%v",closeErr,reserveErr)}
   if err=m.Revoke(lease);err!=nil{t.Fatal(err)}
   if err=o.Close();err!=nil{t.Fatal(err)}
  }
  if _,err=m.Reserve("late","retirement-race-device","retirement-race-port");!errors.Is(err,ErrQuarantined){t.Fatalf("late manager reserve: %v",err)}
 }
 t.Log("OWNER_CLOSE_RESERVE_LINEARIZATION_40=PASS")
}
