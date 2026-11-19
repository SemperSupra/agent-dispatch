package trace

import (
 "bytes"
 "errors"
 "fmt"
 "math"
)

// Probe is a known synthetic value, scoped to one lab VM and boot epoch.
// Never log or publish the bytes of Value.
type Probe struct {
 ID string
 VMID string
 Epoch string
 Value []byte
}

type MemoryRegion struct {
 VMID string
 Epoch string
 SnapshotID string
 RegionID string
 BaseGPA uint64
 Bytes []byte
}

type MemoryHit struct {
 ProbeID string `json:"probe_id"`
 VMID string `json:"vm_id"`
 Epoch string `json:"epoch"`
 SnapshotID string `json:"snapshot_id"`
 RegionID string `json:"region_id"`
 GuestPhysicalAddress uint64 `json:"guest_physical_address"`
 Evidence string `json:"evidence"`
 Attribution string `json:"attribution"`
 UseInferred bool `json:"use_inferred"`
}

const (
 minProbeSize = 16
 maxProbeSize = 4096
 maxRegionSize = 64 << 20
 maxHits = 4096
)

// FindExactMemoryMatches returns only metadata of direct byte matches.
// A match does NOT demonstrate current key use, original caller or ownership.
func FindExactMemoryMatches(probes []Probe, regions []MemoryRegion) ([]MemoryHit,error) {
 ids:=make(map[string]bool,len(probes))
 for _,p:=range probes {
  if p.ID==""||p.VMID==""||p.Epoch==""||len(p.Value)<minProbeSize||len(p.Value)>maxProbeSize {
   return nil,errors.New("invalid probe identity, scope, or length")
  }
  if ids[p.ID]{return nil,fmt.Errorf("duplicate probe id %q",p.ID)}
  ids[p.ID]=true
 }
 out:=[]MemoryHit{}
 for _,r:=range regions {
  if r.VMID==""||r.Epoch==""||r.SnapshotID==""||r.RegionID==""||len(r.Bytes)>maxRegionSize {
   return nil,errors.New("invalid memory region identity or size")
  }
  if uint64(len(r.Bytes))>math.MaxUint64-r.BaseGPA{return nil,errors.New("memory region address overflow")}
  for _,p:=range probes {
   if p.VMID!=r.VMID||p.Epoch!=r.Epoch||len(p.Value)>len(r.Bytes){continue}
   for cursor:=0;cursor<=len(r.Bytes)-len(p.Value);{
    offset:=bytes.Index(r.Bytes[cursor:],p.Value)
    if offset<0{break}
    addr:=cursor+offset
    if len(out)==maxHits{return nil,errors.New("too many exact matches; refuse partial report")}
    out=append(out,MemoryHit{
     ProbeID:p.ID, VMID:r.VMID, Epoch:r.Epoch,
     SnapshotID:r.SnapshotID,RegionID:r.RegionID,
     GuestPhysicalAddress:r.BaseGPA+uint64(addr),
     Evidence:"EXACT_BYTES_AT_SNAPSHOT",Attribution:"UNKNOWN",UseInferred:false,
    })
    cursor=addr+1
   }
  }
 }
 return out,nil
}
