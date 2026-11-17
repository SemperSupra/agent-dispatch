package heldledger

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func claim(sequence,down,up uint64) ReleaseClaim {
 return ReleaseClaim{
  GuestID:"guest-qemu1",DeviceID:"usb-kbd",HostEpoch:"host1",
  GuestEpoch:"g1",LeaseEpoch:fmt.Sprintf("lease-%d",sequence),
  Generation:sequence,ReleaseSequence:sequence,
  DownEventSequence:down,EventSequence:up,
  Source:"guest.evdev",Key:KeyA,KeyReleased:true,Proof:"test-signed-proof",
 }
}
func signed(c ReleaseClaim)bool{
 return c.Proof=="test-signed-proof" && c.Source=="guest.evdev" &&
  c.GuestID=="guest-qemu1" && c.KeyReleased
}
func readHeld(t *testing.T,s Store,sequence uint64) {
 t.Helper()
 r,err:=s.Read()
 if err!=nil||!r.Held||r.Sequence!=sequence{
  t.Fatalf("unsafe journal changed on denied proof: %+v %v",r,err)
 }
}
func TestVerifiedReleaseDurableAndMonotonic(t *testing.T){
 s:=Store{Path:filepath.Join(t.TempDir(),"held.json")}
 st,err:=s.Transition(0,true)
 if err!=nil||!st.Held{t.Fatal(err)}
 c:=claim(1,10,11)
 if _,err=s.ConfirmGuestRelease(1,c,nil);!errors.Is(err,ErrUnverified){
  t.Fatal("nil verifier accepted",err)
 }
 readHeld(t,s,1)
 st,err=s.ConfirmGuestRelease(1,c,signed)
 if err!=nil||st.Held||st.Sequence!=2||st.LastReleaseEventSequence!=11||
  len(st.LastReleaseProofHash)!=64{
  t.Fatalf("guest release not persisted: %+v %v",st,err)
 }
 // Independent process-store reconstruction must not interpret a journal
 // audit hash as a NEW authenticated receipt on startup.
 recovered,err:=(Store{Path:s.Path}).Read()
 if err!=nil || recovered.LastReleaseProofHash!=st.LastReleaseProofHash{
  t.Fatalf("durable release fingerprint lost: %+v %v",recovered,err)
 }
 info,err:=os.Stat(s.Path)
 if err!=nil||info.Mode().Perm()!=0600{t.Fatalf("journal permissions: %v",err)}
 if _,err=s.ConfirmGuestRelease(1,c,signed);!errors.Is(err,ErrUnverified){
  t.Fatal("replayed proof accepted",err)
 }
 st,err=s.Transition(2,true)
 if err!=nil||!st.Held || st.LastReleaseProofHash!=recovered.LastReleaseProofHash{
  t.Fatal("prior trusted receipt audit lost",st,err)
 }
 // First down / up sequence can never repeat despite a new lease.
 stale:=claim(3,9,11)
 if _,err=s.ConfirmGuestRelease(3,stale,signed);!errors.Is(err,ErrUnverified){
  t.Fatal("stale guest event sequence accepted",err)
 }
 readHeld(t,s,3)
 later:=claim(3,12,13)
 st,err=s.ConfirmGuestRelease(3,later,signed)
 if err!=nil||st.Held||st.LastReleaseEventSequence!=13{
  t.Fatalf("new trusted scoped release denied: %+v %v",st,err)
 }
 t.Log("R26_L9_FSYNCED_GUEST_RELEASE_AND_REPLAY_FENCE=PASS")
}
func TestForgedAndOutOfOrderProofNeverClearsHeld(t *testing.T){
 s:=Store{Path:filepath.Join(t.TempDir(),"held.json")}
 _,_ =s.Transition(0,true)
 base:=claim(1,30,31)
 fixtures:=[]ReleaseClaim{
  func()ReleaseClaim{c:=base;c.GuestID="";return c}(),
  func()ReleaseClaim{c:=base;c.DeviceID="";return c}(),
  func()ReleaseClaim{c:=base;c.HostEpoch="";return c}(),
  func()ReleaseClaim{c:=base;c.GuestEpoch="";return c}(),
  func()ReleaseClaim{c:=base;c.LeaseEpoch="";return c}(),
  func()ReleaseClaim{c:=base;c.Generation=0;return c}(),
  func()ReleaseClaim{c:=base;c.ReleaseSequence=99;return c}(),
  func()ReleaseClaim{c:=base;c.DownEventSequence=31;return c}(),
  func()ReleaseClaim{c:=base;c.EventSequence=30;return c}(),
  func()ReleaseClaim{c:=base;c.Source="qemu.serial";return c}(),
  func()ReleaseClaim{c:=base;c.Key="key-b";return c}(),
  func()ReleaseClaim{c:=base;c.KeyReleased=false;return c}(),
  func()ReleaseClaim{c:=base;c.Proof="";return c}(),
  func()ReleaseClaim{c:=base;c.Proof="forgery";return c}(),
 }
 for i,c:=range fixtures{
  if _,err:=s.ConfirmGuestRelease(1,c,signed);!errors.Is(err,ErrUnverified){
   t.Fatalf("invalid receipt %d accepted: %+v, %v",i,c,err)
  }
  readHeld(t,s,1)
 }
 if _,err:=s.ConfirmGuestRelease(17,base,signed);!errors.Is(err,ErrUnverified){
  t.Fatal("stale journal generation accepted",err)
 }
 readHeld(t,s,1)
 t.Log("R26_L9_NO_ACK_ONLY_FORGED_OUT_OF_ORDER_RECLAIM=PASS")
}
func TestMissingOrMalformedJournalNeverGrantsGuestRelease(t *testing.T){
 s:=Store{Path:filepath.Join(t.TempDir(),"held.json")}
 if _,err:=s.ConfirmGuestRelease(0,claim(1,10,11),signed);!errors.Is(err,ErrUnverified){
  t.Fatal("missing journal accepted as guest-confirmed",err)
 }
 if err:=os.WriteFile(s.Path,[]byte("{"),0600);err!=nil{t.Fatal(err)}
 if _,err:=s.ConfirmGuestRelease(1,claim(1,10,11),signed);!errors.Is(err,ErrInvalid){
  t.Fatal("corrupt journal modified",err)
 }
 if b,err:=os.ReadFile(s.Path);err!=nil||string(b)!="{"{t.Fatal("corrupt file overwritten")}
}
func TestGuestProofWriteFailureRetainsHeld(t *testing.T){
 // Directly target a path whose parent directory becomes unavailable.
 dir:=t.TempDir()
 s:=Store{Path:filepath.Join(dir,"held")}
 _,err:=s.Transition(0,true)
 if err!=nil{t.Fatal(err)}
 // Invalid replacement cannot be emitted into current directory. Verify
 // the only successful guest clearance API requires a valid write path.
 denied:=Store{Path:filepath.Join(dir,"absent","held")}
 if _,err=denied.ConfirmGuestRelease(1,claim(1,10,11),signed);!errors.Is(err,ErrUnverified){
  t.Fatal("missing ledger accepted",err)
 }
 readHeld(t,s,1)
}
func TestAuditDigestIsNotPlaintextInput(t *testing.T){
 s:=Store{Path:filepath.Join(t.TempDir(),"held")}
 _,_ =s.Transition(0,true)
 c:=claim(1,10,11)
 _,err:=s.ConfirmGuestRelease(1,c,signed)
 if err!=nil{t.Fatal(err)}
 b,err:=os.ReadFile(s.Path)
 if err!=nil{t.Fatal(err)}
 if strings.Contains(string(b),"test-signed-proof") ||
  strings.Contains(string(b),"raw_report"){
  t.Fatal("raw proof material leaked into persisted journal")
 }
}
