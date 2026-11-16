package blue

import (
 "bytes"
 "errors"
 "io"
 "testing"
)

type counter struct {sent int; released int}
func(c *counter) Input(command string)error {c.sent++;return nil}
func(c *counter) ReleaseAll()error{c.released++;return nil}

// This regression intentionally starts RED against the previously passing
// synthetic model: every new manager starts with generation 1.
func TestOldLeaseCannotOperateAfterManagerRestart(t *testing.T){
 oldExecutor:=&counter{}
 first:=New("keyboard","xhci0/auto",oldExecutor)
 stale,err:=first.Reserve("approved-agent","keyboard","xhci0/auto")
 if err!=nil{t.Fatal(err)}
 if err=first.Attach(stale);err!=nil{t.Fatal(err)}

 secondExecutor:=&counter{}
 restart:=New("keyboard","xhci0/auto",secondExecutor)
 fresh,err:=restart.Reserve("approved-agent","keyboard","xhci0/auto")
 if err!=nil{t.Fatal(err)}
 if err=restart.Attach(fresh);err!=nil{t.Fatal(err)}
 if stale.Generation!=fresh.Generation {
  t.Fatalf("counterexample precondition missing: stale %d fresh %d",stale.Generation,fresh.Generation)
 }
 if stale.Epoch==fresh.Epoch {t.Fatal("restarted manager reused the same incarnation epoch")}
 if err=restart.Input(stale,"key-a-down");!errors.Is(err,ErrDenied){
  t.Fatalf("P0 ABA: old process lease accepted by new owner: error=%v stale=%+v fresh=%+v",err,stale,fresh)
 }
 if secondExecutor.sent!=0{t.Fatal("replayed USB input reached restarted executor")}
}

func TestSameIncarnationStillOperates(t *testing.T){
 c:=&counter{}
 m:=New("keyboard","xhci0/auto",c)
 l,e:=m.Reserve("approved-agent","keyboard","xhci0/auto")
 if e!=nil{t.Fatal(e)}
 if e=m.Attach(l);e!=nil{t.Fatal(e)}
 if e=m.Input(l,"key-a-down");e!=nil{t.Fatal(e)}
 if c.sent!=1{t.Fatal("valid lease failed")}
 if e=m.Revoke(l);e!=nil{t.Fatal(e)}
 if c.released!=1{t.Fatal("failed release-all")}
 if e=m.Input(l,"key-a-down");!errors.Is(e,ErrDenied){t.Fatal("post-revoke retry accepted")}
}

type failedEntropy struct{}
func (failedEntropy) Read([]byte)(int,error){return 0,errors.New("synthetic entropy failure")}

func TestEntropyFailureAndZeroEpochQuarantine(t *testing.T){
 readers:=[]io.Reader{failedEntropy{},bytes.NewReader(make([]byte,16))}
 for _,reader:=range readers {
  m:=newWithEntropy("keyboard","xhci0/auto",&counter{},reader)
  state,_,_:=m.Snapshot()
  if state!=Quarantined{t.Fatalf("nonfailclosed entropy: %s",state)}
  _,err:=m.Reserve("approved-agent","keyboard","xhci0/auto")
  if !errors.Is(err,ErrQuarantined){t.Fatalf("entropy failure permitted lease: %v",err)}
 }
}
