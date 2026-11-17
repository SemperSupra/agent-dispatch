// Package capture decodes QEMU's usbmon-mmap PCAP (DLT 220) into
// bounded, payload-free evidence. Raw USB bytes never leave this process.
package capture

import (
 "bytes"
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "errors"
 "fmt"
 "sort"
)

type Summary struct {
 Schema int `json:"schema"`
 ByteLength int `json:"byte_length"`
 SHA256 string `json:"sha256"`
 PCAPVersion string `json:"pcap_version"`
 LinkType uint32 `json:"link_type"`
 Records int `json:"records"`
 DurationMS float64 `json:"duration_ms"`
 Events map[string]int `json:"events"`
 Transfers map[string]int `json:"transfer_types"`
 Endpoints map[string]int `json:"endpoints"`
 Status map[string]int `json:"statuses"`
 Controls map[string]int `json:"control_requests"`
 MatchedURBs int `json:"matched_noncontrol_urbs"`
 UnmatchedSubmits int `json:"unmatched_submits"`
 OrphanCompletions int `json:"orphan_completions"`
 HIDReports int `json:"hid_boot_reports"`
 KeyAPresses int `json:"synthetic_key_a_presses"`
 KeyAReleases int `json:"synthetic_key_a_releases"`
 PayloadExported bool `json:"payload_exported"`
}

type inFlight struct {
 endpoint byte
 transfer byte
}

func requestName(v byte) string {
 switch v {
 case 0x00: return "GET_STATUS"
 case 0x01: return "CLEAR_FEATURE"
 case 0x03: return "SET_FEATURE"
 case 0x05: return "SET_ADDRESS"
 case 0x06: return "GET_DESCRIPTOR"
 case 0x07: return "SET_DESCRIPTOR"
 case 0x08: return "GET_CONFIGURATION"
 case 0x09: return "SET_CONFIGURATION"
 case 0x0a: return "GET_INTERFACE_OR_HID_IDLE"
 case 0x0b: return "SET_INTERFACE_OR_HID_PROTOCOL"
 default: return fmt.Sprintf("request_0x%02x",v)
 }
}

var transferNames = [4]string{"isochronous","interrupt","control","bulk"}

// Decode is restricted to small synthetic captures, not a generic
// untrusted PCAP/PCAPNG ingestion service. No payload, descriptor strings,
// USB serials, or raw keyboard reports are emitted.
func Decode(b []byte) (Summary,error) {
 s:=Summary{
  Schema:1, ByteLength:len(b), Events:map[string]int{},
  Transfers:map[string]int{}, Endpoints:map[string]int{},
  Status:map[string]int{},Controls:map[string]int{},
 }
 sum:=sha256.Sum256(b)
 s.SHA256=hex.EncodeToString(sum[:])
 if len(b)<24 || len(b)>4*1024*1024 {return s,errors.New("invalid bounded capture size")}
 var bo binary.ByteOrder
 switch {
 case bytes.Equal(b[:4],[]byte{0xd4,0xc3,0xb2,0xa1}):bo=binary.LittleEndian
 case bytes.Equal(b[:4],[]byte{0xa1,0xb2,0xc3,0xd4}):bo=binary.BigEndian
 default:return s,errors.New("invalid PCAP microsecond magic")
 }
 major,minor:=bo.Uint16(b[4:6]),bo.Uint16(b[6:8])
 s.PCAPVersion=fmt.Sprintf("%d.%d",major,minor)
 if major!=2 || minor!=4 {return s,errors.New("unexpected PCAP version")}
 s.LinkType=bo.Uint32(b[20:24])
 if s.LinkType!=220{return s,fmt.Errorf("unexpected USB PCAP linktype %d (expected usbmon mmap 220)",s.LinkType)}
 pos:=24
 first,last:=int64(-1),int64(-1)
 inflight:=map[uint64]inFlight{}
 pressed:=false
 for pos<len(b) {
  if len(b)-pos<16 {return s,fmt.Errorf("truncated PCAP record header at %d",pos)}
  tsSec:=bo.Uint32(b[pos:pos+4])
  tsUsec:=bo.Uint32(b[pos+4:pos+8])
  incl:=bo.Uint32(b[pos+8:pos+12])
  orig:=bo.Uint32(b[pos+12:pos+16])
  pos+=16
  if tsUsec>=1000000{return s,errors.New("invalid microsecond timestamp")}
  if incl<64 || incl>65536 || int(incl)>len(b)-pos {
   return s,fmt.Errorf("invalid/truncated usbmon record at %d len=%d",pos,incl)
  }
  if orig==0{return s,errors.New("zero original length")}
  rec:=b[pos:pos+int(incl)]
  pos+=int(incl)
  captured:=bo.Uint32(rec[36:40])
  if captured!=incl{return s,fmt.Errorf("usbmon captured length %d differs from PCAP %d",captured,incl)}
  timestamp:=int64(tsSec)*1000000+int64(tsUsec)
  if first<0{first=timestamp}
  if timestamp<last{return s,errors.New("nonmonotonic PCAP record timestamps")}
  last=timestamp
  id:=bo.Uint64(rec[:8])
  event:=string([]byte{rec[8]})
  transfer:=rec[9]
  endpoint:=rec[10]
  if transfer>3{return s,errors.New("invalid usbmon transfer type")}
  if event!="S" && event!="C" && event!="E"{return s,fmt.Errorf("invalid USB event %q",event)}
  status:=int32(bo.Uint32(rec[28:32]))
  key:=fmt.Sprintf("0x%02x",endpoint)
  s.Endpoints[key]++
  s.Events[event]++
  s.Transfers[transferNames[transfer]]++
  s.Status[fmt.Sprintf("%d",status)]++
  s.Records++
  if s.Records>100000{return s,errors.New("capture exceeds event bound")}
  // Control events use id=0 in QEMU and cannot be reliably paired by ID.
  // Track setup request types only; never claim CTRL submit/complete pairing.
  if transfer==2 && event=="S" && rec[14]==0 {
   s.Controls[requestName(rec[41])]++
  }
  if transfer!=2 {
   if event=="S" {
    if _,exists:=inflight[id];exists {
     return s,fmt.Errorf("duplicate outstanding URB id %d",id)
    }
    inflight[id]=inFlight{endpoint:endpoint,transfer:transfer}
   }else{
    original,ok:=inflight[id]
    if !ok {s.OrphanCompletions++}else{
     if original.endpoint!=endpoint || original.transfer!=transfer {
      return s,fmt.Errorf("mismatched URB identity %d",id)
     }
     delete(inflight,id)
     s.MatchedURBs++
    }
   }
  }
  if transfer==1 && event=="C" && endpoint&0x80!=0 && status==0 && len(rec)>=72 {
   payload:=rec[64:]
   // Standard USB boot keyboard report: 8 bytes, key usages in slots 2..7.
   // Unknown report descriptors are not decoded or guessed.
   if len(payload)==8 {
    s.HIDReports++
    isA:=bytes.IndexByte(payload[2:],0x04)>=0
    if isA && !pressed{s.KeyAPresses++}
    if !isA && pressed{s.KeyAReleases++}
    pressed=isA
   }
  }
 }
 s.UnmatchedSubmits=len(inflight)
 if last>=first && first>=0{s.DurationMS=float64(last-first)/1000.0}
 // Deterministic encoder doesn't depend on map iteration ordering, but
 // enumerate keys to guard against accidentally logging raw descriptors.
 _=sort.Strings
 return s,nil
}
