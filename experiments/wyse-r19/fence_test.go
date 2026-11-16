package fence

import (
 "errors"
 "fmt"
 "sync"
 "sync/atomic"
 "testing"
 "time"
)
func mustGate(t *testing.T,store *Store)*Gate {
 t.Helper()
 g,e:=NewGate(store)
 if e!=nil{t.Fatal(e)}
 return g
}
func mustLease(t *testing.T,g *Gate)Lease{
 t.Helper()
 l,e:=g.Claim("agent-a","guest-linux","mission-rdte",time.Now().Add(time.Minute))
 if e!=nil{t.Fatal(e)}
 return l
}
func request(l Lease,id string)Request{
 return Request{Lease:l,Actor:l.Actor,Guest:l.Guest,Mission:l.Mission,
  Capability:"hid.key_a",Idempotency:id,At:time.Now()}
}
func TestRaceRevocationLinearization(t *testing.T){
 for attempt:=0;attempt<20;attempt++ {
  g:=mustGate(t,NewStore())
  l:=mustLease(t,g)
  var executed atomic.Int64
  active:=make(chan struct{})
  release:=make(chan struct{})
  firstDone:=make(chan error,1)
  go func(){
   firstDone<-g.Do(request(l,"held"),func()error{
    executed.Add(1)
    close(active)
    <-release
    return nil
   })
  }()
  <-active
  var wg sync.WaitGroup
  outcomes:=make(chan error,64)
  for i:=0;i<64;i++{
   wg.Add(1)
   go func(i int){
    defer wg.Done()
    outcomes<-g.Do(request(l,fmt.Sprintf("parallel-%d",i)),func()error{
     executed.Add(1);return nil
    })
   }(i)
  }
  revDone:=make(chan error,1)
  go func(){revDone<-g.Revoke()}()
  close(release)
  if err:=<-firstDone;err!=nil{t.Fatal(err)}
  if err:=<-revDone;err!=nil{t.Fatal(err)}
  before:=executed.Load()
  if e:=g.Do(request(l,"after-revoke"),func()error{
   executed.Add(1);return nil
  });!errors.Is(e,ErrDenied){t.Fatalf("revoked lease accepted: %v",e)}
  wg.Wait();close(outcomes)
  for e:=range outcomes{if e!=nil && !errors.Is(e,ErrDenied){t.Fatal(e)}}
  if executed.Load()!=before{t.Fatal("effect executed after completed revoke")}
  seenRevoke:=false
  for _,e:=range g.Snapshot(){
   if e.Kind=="REVOKE"{seenRevoke=true}
   if e.Kind=="EXEC"&&seenRevoke{t.Fatal("EXEC occurred after REVOKE barrier")}
  }
  if !seenRevoke{t.Fatal("missing audit revoke")}
 }
 t.Log("R19_RACE_REVOKE_BARRIER=PASS")
}
func TestRestartMonotoneEpochAndFailClose(t *testing.T){
 store:=NewStore()
 one:=mustGate(t,store)
 old:=mustLease(t,one)
 if e:=one.Do(request(old,"before"),func()error{return nil});e!=nil{t.Fatal(e)}
 if e:=one.Revoke();e!=nil{t.Fatal(e)}
 two:=mustGate(t,store)
 if two.epoch<=old.Epoch{t.Fatal("monotone epoch not advanced on owner restart")}
 if e:=two.Do(request(old,"replay"),func()error{t.Fatal("stale replay affected host");return nil});!errors.Is(e,ErrDenied){
  t.Fatalf("stale lease accepted after restart: %v",e)
 }
 store.setAvailable(false)
 if _,e:=NewGate(store);!errors.Is(e,ErrUnavailable){t.Fatal("unavailable epoch store did not fail admission")}
 if e:=two.Do(request(old,"unavailable"),func()error{t.Fatal("effect executed with epoch store unavailable");return nil});!errors.Is(e,ErrUnavailable){
  t.Fatalf("existing gate did not fail close on unavailable store: %v",e)
 }
 t.Log("R19_RESTART_MONOTONE_EPOCH_AND_FAIL_CLOSE=PASS")
}
func TestInvalidScopeIdempotencyAndAmbiguousEffect(t *testing.T){
 g:=mustGate(t,NewStore())
 l:=mustLease(t,g)
 noop:=func()error{return nil}
 r:=request(l,"one")
 r.Actor="other";if !errors.Is(g.Do(r,noop),ErrDenied){t.Fatal("wrong actor admitted")}
 r=request(l,"one");r.Guest="other";if !errors.Is(g.Do(r,noop),ErrDenied){t.Fatal("wrong guest admitted")}
 r=request(l,"one");r.Capability="host.raw_qmp";if !errors.Is(g.Do(r,noop),ErrDenied){t.Fatal("raw QMP allowed")}
 r=request(l,"one");if e:=g.Do(r,noop);e!=nil{t.Fatal(e)}
 if !errors.Is(g.Do(r,noop),ErrDenied){t.Fatal("duplicate idempotency accepted")}
 r=request(l,"two");r.At=l.Expires.Add(time.Second)
 if !errors.Is(g.Do(r,noop),ErrDenied){t.Fatal("expired lease accepted")}
 r=request(l,"ambiguous")
 if !errors.Is(g.Do(r,func()error{return errors.New("mock transport ambiguity")}),ErrUnavailable){t.Fatal("ambiguous effect accepted")}
 r=request(l,"after-error")
 if !errors.Is(g.Do(r,noop),ErrUnavailable){t.Fatal("ambiguous effect not quarantined")}
 t.Log("R19_INVALID_SCOPE_IDEMPOTENCY_FAIL_CLOSE=PASS")
}
