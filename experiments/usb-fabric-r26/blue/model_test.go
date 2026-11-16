package blue

import (
 "errors"
 "sync"
 "testing"
)

type fake struct {
 mu sync.Mutex
 inputs []string
 releases int
 releaseErr error
}

func (f *fake) Input(c string) error {
 f.mu.Lock();defer f.mu.Unlock()
 f.inputs=append(f.inputs,c)
 return nil
}
func (f *fake) ReleaseAll() error {
 f.mu.Lock();defer f.mu.Unlock()
 f.releases++
 return f.releaseErr
}
func (f *fake) count()(int,int) {
 f.mu.Lock();defer f.mu.Unlock()
 return len(f.inputs),f.releases
}
func newAttached(t *testing.T)(*Manager,*fake,Lease){
 t.Helper()
 f:=&fake{}
 m:=New("keyboard","xhci0/3",f)
 l,e:=m.Reserve("actor-a","keyboard","xhci0/3");if e!=nil{t.Fatal(e)}
 if e=m.Attach(l);e!=nil{t.Fatal(e)}
 return m,f,l
}
func TestExclusiveLeaseAndScope(t *testing.T){
 m,_,l:=newAttached(t)
 if _,e:=m.Reserve("actor-b","keyboard","xhci0/3");!errors.Is(e,ErrUnavailable){t.Fatalf("concurrent ownership: %v",e)}
 forged:=l;forged.Actor="actor-b"
 if e:=m.Input(forged,"key-a-down");!errors.Is(e,ErrDenied){t.Fatalf("forged actor: %v",e)}
 if e:=m.Input(l,"raw-qmp");!errors.Is(e,ErrDenied){t.Fatalf("raw command: %v",e)}
}
func TestRevokeBarrierAndStaleEpoch(t *testing.T){
 m,f,l:=newAttached(t)
 var wg sync.WaitGroup
 for i:=0;i<40;i++{
  wg.Add(1)
  go func(){defer wg.Done();_ = m.Input(l,"key-a-down")}()
 }
 wg.Add(1)
 go func(){defer wg.Done();_ = m.Revoke(l)}()
 wg.Wait()
 // A competing input may precede revoke, but none may pass afterwards.
 n,_:=f.count()
 if e:=m.Input(l,"key-a-down");!errors.Is(e,ErrDenied){t.Fatalf("post-revoke input: %v",e)}
 after,_:=f.count()
 if after!=n{t.Fatal("input leaked after completed revocation")}
 state,_,_:=m.Snapshot()
 if state!=Available{t.Fatalf("state not released: %s",state)}
 l2,e:=m.Reserve("actor-b","keyboard","xhci0/3");if e!=nil{t.Fatal(e)}
 if l2.Generation<=l.Generation{t.Fatal("generation not advanced")}
}
func TestReleaseFailureQuarantines(t *testing.T){
 m,f,l:=newAttached(t)
 f.releaseErr=errors.New("backend unavailable")
 if e:=m.Revoke(l);e==nil{t.Fatal("release failure must be observed")}
 state,active,_:=m.Snapshot()
 if state!=Quarantined || active!= (Lease{}){t.Fatalf("unsafe state=%s lease=%v",state,active)}
 if _,e:=m.Reserve("actor-b","keyboard","xhci0/3");!errors.Is(e,ErrQuarantined){t.Fatalf("unsafe reassignment: %v",e)}
 if e:=m.Input(l,"key-a-down");!errors.Is(e,ErrDenied){t.Fatal("old lease still valid")}
}
func TestOfflineFencesWithoutReassignment(t *testing.T){
 m,_,l:=newAttached(t)
 m.Offline()
 if e:=m.Input(l,"key-a-down");!errors.Is(e,ErrDenied){t.Fatal("offline input allowed")}
 if _,e:=m.Reserve("actor-b","keyboard","xhci0/3");!errors.Is(e,ErrQuarantined){t.Fatal("offline allowed new owner")}
}
