package scheduler

import (
 "context"
 "errors"
 "sync/atomic"
 "testing"
 "time"
)

// R26-P7 RED: accepted background-context operations must never be
// abandoned with uncompleted receipt channels after Close. This test
// intentionally fails on the P4 baseline scheduler; preserve the CI RED.
func TestCloseDrainsQueuedReceipts(t *testing.T) {
 s:=New()
 release:=make(chan struct{})
 started:=make(chan struct{})
 active:=make(chan error,1)
 go func(){
  _,e:=s.Submit(context.Background(),Work{Class:Storage,Execute:func(context.Context)error{
   close(started)
   <-release
   return nil
  }})
  active<-e
 }()
 select{case <-started:case <-time.After(time.Second):t.Fatal("active operation did not start")}
 const pending=12
 receipt:=make([]chan error,pending)
 var executed atomic.Int32
 for i:=0;i<pending;i++{
  receipt[i]=make(chan error,1)
  dest:=receipt[i]
  go func(){
   _,e:=s.Submit(context.Background(),Work{Class:Network,Execute:func(context.Context)error{
    executed.Add(1)
    return nil
   }})
   dest<-e
  }()
 }
 until:=time.Now().Add(time.Second)
 for s.Snapshot().Accepted<uint64(pending+1) && time.Now().Before(until){
  time.Sleep(time.Millisecond)
 }
 if s.Snapshot().Accepted!=pending+1{
  close(release)
  t.Fatal("unable to enqueue bounded test operations")
 }
 done:=make(chan struct{})
 go func(){s.Close();close(done)}()
 select{case <-s.stop:case <-time.After(time.Second):close(release);t.Fatal("Close did not fence admission")}
 close(release)
 select{case <-done:case <-time.After(1500*time.Millisecond):t.Fatal("Close hung with released active task")}
 select{case e:=<-active:if e!=nil{t.Fatalf("already-active work failed: %v",e)}
 case <-time.After(time.Second):t.Fatal("active work lost receipt")}
 for i,ch:=range receipt{
  select{
  case e:=<-ch:
   if !errors.Is(e,ErrClosed){t.Fatalf("queued task %d ran after shutdown rather than ErrClosed: %v",i,e)}
  case <-time.After(120*time.Millisecond):
   t.Fatalf("R26_P7_ACCEPTED_BACKGROUND_RECEIPT_DROPPED=RED pending_index=%d",i)
  }
 }
 if n:=executed.Load();n!=0{t.Fatalf("queued actions performed after close: %d",n)}
 if n:=s.Snapshot().MaxInflight;n>145{t.Fatal("queue exceeded bound")}
 if _,e:=s.Submit(context.Background(),Work{Class:HID,Execute:func(context.Context)error{return nil}});!errors.Is(e,ErrClosed){
  t.Fatalf("post-close new admission allowed: %v",e)
 }
 t.Log("R26_P7_ALL_ACCEPTED_RECEIPTS_SETTLED_AND_NEW_ACTUATION_FENCED=PASS")
}
