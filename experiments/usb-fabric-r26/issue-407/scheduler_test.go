package scheduler

import(
 "context"
 "errors"
 "fmt"
 "sort"
 "sync"
 "sync/atomic"
 "testing"
 "time"
)
func TestBoundedQueueAndEmergencyRelease(t *testing.T){
 s:=New();defer s.Close()
 blocker:=make(chan struct{})
 started:=make(chan struct{})
 go func(){
  _,_ =s.Submit(context.Background(),Work{Class:Storage,Execute:func(context.Context)error{
   close(started);<-blocker;return nil
  }})
 }()
 <-started
 // Saturate bulk with waiters, with no unbounded enqueue.
 var wg sync.WaitGroup
 for i:=0;i<128;i++{
  wg.Add(1)
  go func(){defer wg.Done();ctx,cancel:=context.WithTimeout(context.Background(),400*time.Millisecond);defer cancel()
   _,_=s.Submit(ctx,Work{Class:Network,Execute:func(context.Context)error{return nil}})
  }()
 }
 time.Sleep(25*time.Millisecond)
 if s.Snapshot().MaxInflight>145{t.Fatalf("queue exceeded static bound %+v",s.Snapshot())}
 releaseDone:=make(chan error,1)
 go func(){_,e:=s.Submit(context.Background(),Work{Class:Emergency,Execute:func(context.Context)error{return nil}});releaseDone<-e}()
 time.Sleep(10*time.Millisecond)
 close(blocker)
 select{
 case e:=<-releaseDone:if e!=nil{t.Fatal(e)}
 case <-time.After(900*time.Millisecond):t.Fatal("emergency release starved behind bulk")
 }
 wg.Wait()
 st:=s.Snapshot()
 if st.EmergencyCompleted!=1{t.Fatalf("emergency loss %+v",st)}
 if st.Rejected==0{t.Fatalf("expected queue backpressure rather than unbounded buffer %+v",st)}
}
func TestClassFairnessAndNoUnauthorizedRawWork(t *testing.T){
 s:=New();defer s.Close()
 if _,e:=s.Submit(context.Background(),Work{Class:255,Execute:func(context.Context)error{return nil}});!errors.Is(e,ErrOverload){t.Fatal("invalid operation allowed")}
 if _,e:=s.Submit(context.Background(),Work{Class:HID,DataBytes:1<<30,Execute:func(context.Context)error{return nil}});!errors.Is(e,ErrOverload){t.Fatal("unbounded body allowed")}
 count:=map[Class]int{}
 var mu sync.Mutex
 for _,c:=range []Class{HID,CAC,Storage,Network,Audio,Optical,Emergency}{
  c:=c
  _,e:=s.Submit(context.Background(),Work{Class:c,Execute:func(context.Context)error{
   mu.Lock();count[c]++;mu.Unlock();return nil
  }})
  if e!=nil{t.Fatal(e)}
 }
 if len(count)!=7{t.Fatalf("missing classes: %+v",count)}
}
func TestSustainedStressMetrics(t *testing.T){
 s:=New();defer s.Close()
 const workers=8
 const perWorker=160
 classes:=[]Class{HID,CAC,Storage,Network,Audio,Optical}
 var wg sync.WaitGroup
 var latencyMu sync.Mutex
 waits:=make([]time.Duration,0,workers*perWorker)
 var good atomic.Int64
 for id:=0;id<workers;id++{
  id:=id;wg.Add(1)
  go func(){
   defer wg.Done()
   for j:=0;j<perWorker;j++{
    class:=classes[(id+j)%len(classes)]
    ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
    waited,e:=s.Submit(ctx,Work{Class:class,DataBytes:(j%8+1)*512,
     Execute:func(context.Context)error{time.Sleep(150*time.Microsecond);return nil}})
    cancel()
    if e==nil{
     good.Add(1);latencyMu.Lock();waits=append(waits,waited);latencyMu.Unlock()
    } else if !errors.Is(e,ErrOverload){t.Errorf("unexpected submission error: %v",e)}
   }
  }()
 }
 wg.Wait()
 if good.Load()<150{t.Fatalf("insufficient completion under bounded load: %d",good.Load())}
 sort.Slice(waits,func(i,j int)bool{return waits[i]<waits[j]})
 pct:=func(q float64)time.Duration{return waits[int(float64(len(waits)-1)*q)]}
 stats:=s.Snapshot()
 t.Logf("R26_P4_CROSS_CLASS_STRESS=PASS workers=%d completed=%d rejected=%d max_inflight=%d p50_ms=%.2f p95_ms=%.2f p99_ms=%.2f",
  workers,stats.Completed,stats.Rejected,stats.MaxInflight,
  float64(pct(.5))/float64(time.Millisecond),float64(pct(.95))/float64(time.Millisecond),float64(pct(.99))/float64(time.Millisecond))
 if stats.MaxInflight>145{t.Fatal(fmt.Sprintf("queue exceeds emergency+interactive+bulk: %+v",stats))}
}
