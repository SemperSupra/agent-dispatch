// Package trace decodes TPM2 wire headers and emits privacy-preserving RDTE events.
package trace

import (
 "encoding/binary"
 "errors"
 "fmt"
 "time"
)

const maxFrame = 1 << 20

// Frame excludes TPM parameter bytes; those may contain guest secrets.
type Frame struct {
 Tag uint16 `json:"tag"`
 Size uint32 `json:"size"`
 Code uint32 `json:"code"`
 Name string `json:"name"`
}

var names = map[uint32]string{
 0x00000144:"Startup", 0x00000145:"Shutdown", 0x0000017b:"GetRandom",
 0x0000017e:"PCR_Read", 0x00000182:"PCR_Extend",
 0x00000169:"NV_ReadPublic", 0x0000014e:"NV_Read", 0x00000137:"NV_Write",
 0x0000012a:"NV_DefineSpace", 0x00000122:"NV_UndefineSpace",
 0x00000158:"Quote", 0x0000017a:"GetCapability",
}
func Decode(direction string, wire []byte) (Frame,error) {
 if direction!="request" && direction!="response" {return Frame{},errors.New("invalid direction")}
 if len(wire)<10 || len(wire)>maxFrame {return Frame{},fmt.Errorf("invalid TPM2 frame length %d",len(wire))}
 tag:=binary.BigEndian.Uint16(wire[:2])
 if tag!=0x8001 && tag!=0x8002 {return Frame{},fmt.Errorf("invalid TPM2 tag 0x%04x",tag)}
 size:=binary.BigEndian.Uint32(wire[2:6])
 if size!=uint32(len(wire)) {return Frame{},fmt.Errorf("TPM2 declared size %d differs from observed %d",size,len(wire))}
 code:=binary.BigEndian.Uint32(wire[6:10])
 name:="UnknownCommand"
 if direction=="response" {name="ErrorOrSuccessCode";if code==0{name="Success"}} else if v,ok:=names[code];ok{name=v}
 return Frame{tag,size,code,name},nil
}

type Event struct {
 Schema string `json:"schema"`
 Sequence uint64 `json:"sequence"`
 TimeUTC time.Time `json:"time_utc"`
 Direction string `json:"direction"`
 Frame Frame `json:"frame"`
 Origin string `json:"origin"`
 Caller string `json:"caller"`
 Attribution string `json:"attribution"`
 RequestCode uint32 `json:"request_code,omitempty"`
 LatencyMicros int64 `json:"latency_us,omitempty"`
}

// Correlator supports a single serialized TPM command channel. It never guesses.
type Correlator struct {seq uint64;pending *Frame;start time.Time}
func (c *Correlator) Observe(direction string,raw []byte,at time.Time)(Event,error){
 f,err:=Decode(direction,raw);if err!=nil{return Event{},err}
 ev:=Event{Schema:"tpm-workbench.trace.v1",TimeUTC:at.UTC(),Direction:direction,Frame:f,
  Origin:"TPM2_HEADER_ONLY",Caller:"UNKNOWN",Attribution:"UNKNOWN"}
 if direction=="request" {
  if c.pending!=nil{return Event{},errors.New("second request before response; uncertain pairing")}
  c.seq++;c.pending=&f;c.start=at;ev.Sequence=c.seq;return ev,nil
 }
 if c.pending==nil{return Event{},errors.New("response without prior request")}
 if at.Before(c.start){return Event{},errors.New("response precedes request timestamp")}
 ev.Sequence=c.seq;ev.RequestCode=c.pending.Code;ev.LatencyMicros=at.Sub(c.start).Microseconds()
 c.pending=nil;return ev,nil
}
func(c *Correlator)Pending()bool{return c.pending!=nil}
