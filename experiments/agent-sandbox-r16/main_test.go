package main
import ("sync";"testing";"time")
func TestExclusiveLeaseRaceAndRevocation(t *testing.T){
 g:=newGateway()
 now:=time.Unix(1770000000,0)
 var wg sync.WaitGroup
 answers:=make(chan Reply,24)
 for i:=0;i<24;i++{
  wg.Add(1)
  go func(i int){
   defer wg.Done()
   answers<-g.execute(Command{Action:"claim",Device:"kbd-1",Actor:"actor",
    Guest:"guest",Mission:"mission",Generation:1,TTLSeconds:10},false,now)
  }(i)
 }
 wg.Wait();close(answers)
 accepted:=0
 for a:=range answers{if a.Accepted{accepted++}}
 if accepted!=1{t.Fatalf("exclusive race accepted %d leases",accepted)}
 g.mu.Lock()
 current:=g.ports[0].Generation
 g.mu.Unlock()
 if a:=g.execute(Command{Action:"revoke",Device:"kbd-1",Generation:current},false,now);a.Accepted{
  t.Fatal("non-owner revoked")
 }
 if a:=g.execute(Command{Action:"revoke",Device:"kbd-1",Generation:current},true,now);!a.Accepted{
  t.Fatal("authorized revoke failed")
 }
}
func TestUnknownAndExpiryFailClosed(t *testing.T){
 g:=newGateway();now:=time.Unix(1770000000,0)
 if r:=g.execute(Command{Action:"claim",Device:"host-real-device",Actor:"agent",
  Guest:"guest",Mission:"rdte",Generation:1,TTLSeconds:3},false,now);r.Accepted {
   t.Fatal("unknown physical device granted")
 }
 c:=Command{Action:"claim",Device:"kbd-1",Actor:"agent",Guest:"guest",
 Mission:"rdte",Generation:1,TTLSeconds:1}
 r:=g.execute(c,false,now)
 if !r.Accepted {t.Fatal("valid synthetic lease refused")}
 c.Action="attach";c.Lease=r.Lease;c.Generation=r.Generation
 if a:=g.execute(c,false,now.Add(2*time.Second));a.Accepted{t.Fatal("expired lease attached")}
 if a:=g.execute(c,false,now.Add(2*time.Second));a.Accepted{t.Fatal("expired lease replay attached")}
}
func TestLabelsAndLeaseScope(t *testing.T) {
 g:=newGateway();now:=time.Unix(1770000000,0)
 c:=Command{Action:"claim",Device:"kbd-1",Actor:"actor",Guest:"guest",
 Mission:"rdte",Generation:1,TTLSeconds:30}
 r:=g.execute(c,false,now)
 if !r.Accepted{t.Fatal("cannot lease")}
 bad:=Command{Action:"attach",Device:"kbd-1",Actor:"another",
  Guest:"guest",Mission:"rdte",Generation:r.Generation,Lease:r.Lease}
 if ans:=g.execute(bad,false,now);ans.Accepted{t.Fatal("wrong actor attached")}
 bad.Actor="actor";bad.Guest="other"
 if ans:=g.execute(bad,false,now);ans.Accepted{t.Fatal("wrong guest attached")}
 bad.Guest="guest";bad.Mission="other"
 if ans:=g.execute(bad,false,now);ans.Accepted{t.Fatal("wrong mission attached")}
 bad.Mission="rdte";bad.Lease="bad"
 if ans:=g.execute(bad,false,now);ans.Accepted{t.Fatal("invalid token attached")}
}
