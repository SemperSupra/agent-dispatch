package qmpatomic
import (
 "errors"
 "fmt"
 "sync"
 "testing"
 "time"
 fence "example.org/wyse-r19-fence"
)
func req(l fence.Lease,id,capability string)fence.Request{
 return fence.Request{Lease:l,Actor:l.Actor,Guest:l.Guest,Mission:l.Mission,
  Capability:capability,Idempotency:id,At:time.Now()}
}
func open(t *testing.T)*Host{
 t.Helper()
 h,e:=newHost()
 if e!=nil{t.Fatal(e)}
 t.Cleanup(h.Close)
 return h
}
func TestRealLocalQMPKeyboardAndRelease(t *testing.T){
 h:=open(t)
 l,e:=h.Claim();if e!=nil{t.Fatal(e)}
 if e=h.Input(req(l,"a-down","hid.key_a"),true);e!=nil{t.Fatal(e)}
 if e=h.Input(req(l,"a-up","hid.key_a"),false);e!=nil{t.Fatal(e)}
 if e=h.Revoke();e!=nil{t.Fatal(e)}
 if e=h.Input(req(l,"stale","hid.key_a"),true);!errors.Is(e,fence.ErrDenied){
  t.Fatalf("stale key accepted: %v",e)
 }
 list:=h.Snapshot()
 if len(list)!=3||list[2]!="REVOKE_RETURNED"{t.Fatalf("unexpected QMP evidence %v",list)}
 t.Log("R19B_REAL_LOCAL_QMP_KEY_DOWN_UP_AND_REVOKE=PASS")
}
func TestConcurrentActualQMPAndRevokeBarrier(t *testing.T){
 h:=open(t)
 l,e:=h.Claim();if e!=nil{t.Fatal(e)}
 if e=h.Input(req(l,"button-hold","hid.button_left"),true);e!=nil{t.Fatal(e)}
 var wg sync.WaitGroup
 for i:=0;i<36;i++{
  wg.Add(1)
  go func(i int){
   defer wg.Done()
   _=h.Input(req(l,fmt.Sprintf("queued-%d",i),"hid.key_a"),i%2==0)
  }(i)
 }
 time.Sleep(10*time.Millisecond)
 if e=h.Revoke();e!=nil{t.Fatal(e)}
 wg.Wait()
 for i:=0;i<12;i++{
  if e=h.Input(req(l,fmt.Sprintf("after-%d",i),"hid.key_a"),true);
   !errors.Is(e,fence.ErrDenied){t.Fatalf("post revoke input accepted: %v",e)}
 }
 seen:=false
 for _,ev:=range h.Snapshot(){
  if ev=="REVOKE_RETURNED"{seen=true;continue}
  if seen{t.Fatalf("actual QMP input after revoke: %s",ev)}
 }
 if !seen{t.Fatal("no revocation receipt")}
 t.Log("R19B_REAL_QMP_RELEASE_AND_NO_EVENT_AFTER_COMPLETED_REVOKE=PASS")
}
func TestUnauthorizedAndAmbiguousQMPFailureFailClosed(t *testing.T){
 h:=open(t)
 l,e:=h.Claim();if e!=nil{t.Fatal(e)}
 r:=req(l,"no","hid.key_a");r.Actor="other"
 if e=h.Input(r,true);!errors.Is(e,fence.ErrDenied){t.Fatal("wrong actor accepted")}
 r=req(l,"bad","host.raw_qmp")
 if e=h.Input(r,true);!errors.Is(e,fence.ErrDenied){t.Fatal("raw QMP command accepted")}
 r=req(l,"good","hid.key_a")
 if e=h.Input(r,true);e!=nil{t.Fatal(e)}
 // Fail the local QMP endpoint deliberately and require host quarantine.
 _=h.m.conn.Close()
 r=req(l,"after-kill","hid.key_a")
 if e=h.Input(r,false);!errors.Is(e,fence.ErrUnavailable){t.Fatalf("dead QMP did not fail close: %v",e)}
 if e=h.Input(req(l,"retry","hid.key_a"),true);!errors.Is(e,fence.ErrUnavailable){
  t.Fatal("unsafe broker reopened after ambiguous QMP error")
 }
 t.Log("R19B_QMP_FAILURE_AND_SCOPE_QUARANTINE=PASS")
}
