package trace

import (
 "encoding/hex"
 "testing"
 "time"
)
func raw(s string)[]byte{b,e:=hex.DecodeString(s);if e!=nil{panic(e)};return b}
func TestDecode(t *testing.T){
 r,e:=Decode("request",raw("80010000000a0000017b"));if e!=nil||r.Name!="GetRandom"{t.Fatalf("request: %+v %v",r,e)}
 s,e:=Decode("response",raw("80010000000a00000000"));if e!=nil||s.Name!="Success"{t.Fatalf("response: %+v %v",s,e)}
}
func TestMalformedFailClosed(t *testing.T){
 for _,v:=range []string{"","80010000000a","80010000000b0000017b","80030000000a0000017b"}{
  if _,e:=Decode("request",raw(v));e==nil{t.Fatalf("accepted malformed %q",v)}
 }
 if _,e:=Decode("other",raw("80010000000a0000017b"));e==nil{t.Fatal("accepted direction")}
}
func TestPairingAndUnknownCaller(t *testing.T){
 var c Correlator;now:=time.Unix(100,0)
 a,e:=c.Observe("request",raw("80010000000a0000017b"),now)
 if e!=nil||a.Caller!="UNKNOWN"||a.Sequence!=1{t.Fatalf("request %+v %v",a,e)}
 if _,e:=c.Observe("request",raw("80010000000a0000017b"),now);e==nil{t.Fatal("accepted overlap")}
 b,e:=c.Observe("response",raw("80010000000a00000000"),now.Add(1250*time.Microsecond))
 if e!=nil||b.RequestCode!=0x17b||b.LatencyMicros!=1250||c.Pending(){t.Fatalf("response %+v %v",b,e)}
 if _,e:=c.Observe("response",raw("80010000000a00000000"),now);e==nil{t.Fatal("accepted orphan response")}
}
func TestTimestampOrdering(t *testing.T){
 var c Correlator;now:=time.Unix(100,0)
 _,_=c.Observe("request",raw("80010000000a0000017b"),now)
 if _,e:=c.Observe("response",raw("80010000000a00000000"),now.Add(-time.Second));e==nil{t.Fatal("accepted backwards clock")}
 if !c.Pending(){t.Fatal("discarded unresolved request")}
}
