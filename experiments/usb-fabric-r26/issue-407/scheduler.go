// Package scheduler is a bounded, device-class-aware synthetic actuator
// dispatcher. The wire protocol/physical USB backend is intentionally absent.
// Emergency release cannot be rejected by bulk queue saturation.
package scheduler

import(
 "context"
 "errors"
 "sync"
 "sync/atomic"
 "time"
)
type Class uint8
const(
 Emergency Class=iota
 HID
 CAC
 Storage
 Network
 Audio
 Optical
)
var(
 ErrOverload=errors.New("usb fabric: bounded queue saturated")
 ErrClosed=errors.New("usb fabric: scheduler closed")
)
type Work struct{
 Class Class
 DataBytes int
 Execute func(context.Context)error
}
type receipt struct {wait time.Duration;err error}
type task struct{
 work Work
 enqueue time.Time
 done chan receipt
}
type Stats struct{
 Cancelled uint64
 Accepted uint64
 Rejected uint64
 Completed uint64
 EmergencyCompleted uint64
 MaxInflight int64
}
type Scheduler struct{
 urgent chan task
 interactive chan task
 bulk chan task
 stop chan struct{}
 ended chan struct{}
 closeOnce sync.Once
 admissionMu sync.Mutex
 closed bool
 cancelled atomic.Uint64
 accepted atomic.Uint64
 rejected atomic.Uint64
 completed atomic.Uint64
 emergencyCompleted atomic.Uint64
 inflight atomic.Int64
 maxInflight atomic.Int64
}
func New()*Scheduler{
 s:=&Scheduler{urgent:make(chan task,16),interactive:make(chan task,64),
  bulk:make(chan task,64),stop:make(chan struct{}),ended:make(chan struct{})}
 go s.loop()
 return s
}
func (s *Scheduler) Submit(ctx context.Context,w Work)(time.Duration,error){
 if ctx==nil || w.Execute==nil || w.DataBytes<0 || w.DataBytes>64*1024*1024 || w.Class>Optical {
  return 0,ErrOverload
 }
 if e:=ctx.Err();e!=nil{return 0,e}
 t:=task{work:w,enqueue:time.Now(),done:make(chan receipt,1)}
 var q chan task
 switch w.Class{
 case Emergency:q=s.urgent
 case HID,CAC:q=s.interactive
 default:q=s.bulk
 }
 // Admission is a single critical section shared with Close. No send can
 // occur after Close closes stop, even when called by another goroutine.
 s.admissionMu.Lock()
 if s.closed{
  s.admissionMu.Unlock()
  return 0,ErrClosed
 }
 select{
 case q<-t:
  s.accepted.Add(1)
  n:=s.inflight.Add(1)
  for{
   prev:=s.maxInflight.Load()
   if n<=prev || s.maxInflight.CompareAndSwap(prev,n){break}
  }
 case <-ctx.Done():
  s.admissionMu.Unlock()
  return 0,ctx.Err()
 default:
  s.rejected.Add(1)
  s.admissionMu.Unlock()
  return 0,ErrOverload
 }
 s.admissionMu.Unlock()
 // A background-context caller is guaranteed a receipt even if Close
 // happens while its task waits in a bounded class queue.
 select{
 case r:=<-t.done:return r.wait,r.err
 case <-ctx.Done():return 0,ctx.Err()
 }
}
// abort settles accepted but not actuated work, counting it separately
// from Completed. Calls occur only once per task, on the worker or after
// it exits. The buffered receipt never blocks the sole serialized worker.
func (s *Scheduler) abort(t task){
 s.inflight.Add(-1)
 s.cancelled.Add(1)
 t.done<-receipt{wait:time.Since(t.enqueue),err:ErrClosed}
}
func(s *Scheduler) process(t task){
 s.admissionMu.Lock()
 closed:=s.closed
 s.admissionMu.Unlock()
 if closed{s.abort(t);return}
 waited:=time.Since(t.enqueue)
 ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
 err:=t.work.Execute(ctx)
 cancel()
 s.inflight.Add(-1)
 s.completed.Add(1)
 if t.work.Class==Emergency{s.emergencyCompleted.Add(1)}
 t.done<-receipt{wait:waited,err:err}
}
func(s *Scheduler) loop(){
 defer close(s.ended)
 var round uint64
 for{
  // A pending emergency release wins before every next command.
  select{
  case <-s.stop:return
  case t:=<-s.urgent:s.process(t);continue
  default:
  }
  round++
  // Interactive gets 3 of 4 opportunities; bulk progresses
  // without starvation when HID/CAC is constantly active.
  if round%4!=0{
   select{case t:=<-s.interactive:s.process(t);continue;default:}
  }
  select{
  case t:=<-s.bulk:s.process(t);continue
  default:
  }
  select{
  case t:=<-s.interactive:s.process(t);continue
  default:
  }
  select{
  case <-s.stop:return
  case t:=<-s.urgent:s.process(t)
  case t:=<-s.interactive:s.process(t)
  case t:=<-s.bulk:s.process(t)
  }
 }
}
func(s *Scheduler) Snapshot()Stats{
 return Stats{Cancelled:s.cancelled.Load(),Accepted:s.accepted.Load(),Rejected:s.rejected.Load(),
 Completed:s.completed.Load(),EmergencyCompleted:s.emergencyCompleted.Load(),
 MaxInflight:s.maxInflight.Load()}
}
func(s *Scheduler) Close(){
 s.closeOnce.Do(func(){
  s.admissionMu.Lock()
  s.closed=true
  close(s.stop)
  s.admissionMu.Unlock()
  // Do not start another queued actuation. Wait for any already executing
  // callback to finish. A handler that ignores its cancellation remains
  // UNKNOWN/quarantined; we do not spawn concurrent QMP calls to bypass it.
  <-s.ended
  // No new queue writers can exist once admission was fenced, and the
  // worker is stopped. Drain every accepted pending request to a receipt.
  for _,q:=range []chan task{s.urgent,s.interactive,s.bulk}{
   for len(q)>0{s.abort(<-q)}
  }
 })
}
