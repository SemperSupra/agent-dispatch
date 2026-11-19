package trace

import (
 "bytes"
 "encoding/json"
 "strings"
 "testing"
)

func TestSyntheticMultipleCopiesAndRedaction(t *testing.T) {
 value:=[]byte("SYNTHETIC-KEY-MATERIAL-TEST-123456")
 region:=make([]byte,240)
 copy(region[17:],value)
 copy(region[100:],value)
 hits,err:=FindExactMemoryMatches(
  []Probe{{ID:"lab-key-1",VMID:"test-vm",Epoch:"boot-1",Value:value}},
  []MemoryRegion{{VMID:"test-vm",Epoch:"boot-1",SnapshotID:"snap-1",RegionID:"ram0",BaseGPA:0x2000,Bytes:region}},
 )
 if err!=nil||len(hits)!=2||hits[0].GuestPhysicalAddress!=0x2011||hits[1].GuestPhysicalAddress!=0x2064 {
  t.Fatalf("incorrect matches: %+v, %v",hits,err)
 }
 data,_:=json.Marshal(hits)
 if bytes.Contains(data,value)||!strings.Contains(string(data),`"attribution":"UNKNOWN"`)||!strings.Contains(string(data),`"use_inferred":false`){
  t.Fatal("leak or unsupported attribution claim")
 }
}

func TestScopeIsolationAndNonMatchingValue(t *testing.T) {
 key:=[]byte("SYNTHETIC-KEY-MATERIAL-TEST-123456")
 differ:=append([]byte{},key...)
 differ[len(differ)-1]^=1
 p:=Probe{ID:"key",VMID:"vmA",Epoch:"boot1",Value:key}
 r:=MemoryRegion{VMID:"vmA",Epoch:"boot1",SnapshotID:"snap1",RegionID:"ram0",Bytes:differ}
 for _,test:=range []MemoryRegion{
  r,
  {VMID:"vmB",Epoch:"boot1",SnapshotID:"snap1",RegionID:"ram0",Bytes:key},
  {VMID:"vmA",Epoch:"boot2",SnapshotID:"snap1",RegionID:"ram0",Bytes:key},
 } {
  hits,err:=FindExactMemoryMatches([]Probe{p},[]MemoryRegion{test})
  if err!=nil||len(hits)!=0{t.Fatalf("false positive: %+v %v",hits,err)}
 }
}

func TestFailsClosedOnInvalidAndOversizedInput(t *testing.T) {
 p:=Probe{ID:"key",VMID:"vm",Epoch:"epoch",Value:[]byte("too-short")}
 r:=MemoryRegion{VMID:"vm",Epoch:"epoch",SnapshotID:"snap",RegionID:"ram",Bytes:[]byte("0123456789012345")}
 if _,err:=FindExactMemoryMatches([]Probe{p},[]MemoryRegion{r});err==nil{t.Fatal("short probe accepted")}
 p.Value=[]byte("SYNTHETIC-KEY-MATERIAL-TEST-123456")
 if _,err:=FindExactMemoryMatches([]Probe{p,p},[]MemoryRegion{r});err==nil{t.Fatal("duplicate probe accepted")}
 r.BaseGPA=^uint64(0)-5
 if _,err:=FindExactMemoryMatches([]Probe{p},[]MemoryRegion{r});err==nil{t.Fatal("address overflow accepted")}
}
