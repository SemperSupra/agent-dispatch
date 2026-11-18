// Package usbipcontrol parses only bounded USB/IP control-plane discovery frames.
// It does not start a USB/IP daemon, perform URBs, attach devices, or authorize leases.
package usbipcontrol

import (
 "encoding/binary"
 "errors"
 "fmt"
 "io"
 "strings"
)

const (
 Version = uint16(0x0111)
 ReqDevlist = uint16(0x8005)
 RepDevlist = uint16(0x0005)
 ReqImport = uint16(0x8003)
 MaxDevices = 32
 MaxInterfaces = 16
 deviceDescriptorBytes = 312
)

type Header struct { Version uint16; Command uint16; Status uint32 }
type Interface struct { Class, Subclass, Protocol byte }
type Device struct {
 Path string
 BusID string
 Busnum uint32
 Devnum uint32
 Speed uint32
 Vendor uint16
 Product uint16
 BCDDevice uint16
 Class byte
 Subclass byte
 Protocol byte
 Configuration byte
 NumConfigurations byte
 Interfaces []Interface
}

func EncodeRequest(command uint16, busID string) ([]byte,error) {
 if command!=ReqDevlist && command!=ReqImport { return nil,errors.New("unsupported USB/IP request command") }
 if command==ReqImport && (len(busID)==0 || len(busID)>31 || strings.IndexByte(busID,0)>=0) {return nil,errors.New("invalid USB/IP import busid")}
 if command==ReqDevlist && busID!="" {return nil,errors.New("devlist cannot contain busid")}
 size:=8; if command==ReqImport {size+=32}
 b:=make([]byte,size)
 binary.BigEndian.PutUint16(b[0:2],Version)
 binary.BigEndian.PutUint16(b[2:4],command)
 if command==ReqImport {copy(b[8:],busID)}
 return b,nil
}
func readHeader(r io.Reader,expected uint16)(Header,error) {
 var b [8]byte
 if _,err:=io.ReadFull(r,b[:]);err!=nil{return Header{},fmt.Errorf("truncated USB/IP header: %w",err)}
 h:=Header{binary.BigEndian.Uint16(b[:2]),binary.BigEndian.Uint16(b[2:4]),binary.BigEndian.Uint32(b[4:8])}
 if h.Version!=Version{return Header{},fmt.Errorf("unsupported USB/IP version: %#x",h.Version)}
 if h.Command!=expected{return Header{},fmt.Errorf("unexpected USB/IP opcode: %#x",h.Command)}
 if h.Status!=0{return Header{},fmt.Errorf("USB/IP status: %d",h.Status)}
 return h,nil
}
func nulString(b []byte)(string,error){
 n:=len(b)
 for i,v:=range b {if v==0 {n=i;for _,rest:=range b[i:] {if rest!=0{return "",errors.New("nonzero trailing bytes after NUL")}};break}}
 if n==0{return "",errors.New("empty descriptor identifier")}
 s:=string(b[:n])
 for _,v:=range s {if v<32||v>126 {return "",errors.New("invalid non-printable descriptor identifier")}}
 return s,nil
}
// ParseDevlistResponse parses a single successful USB/IP OP_REP_DEVLIST response.
// The caller owns transport authentication, request correlation and leases.
func ParseDevlistResponse(r io.Reader)([]Device,error) {
 if _,err:=readHeader(r,RepDevlist);err!=nil{return nil,err}
 var count [4]byte
 if _,err:=io.ReadFull(r,count[:]);err!=nil{return nil,fmt.Errorf("missing device count: %w",err)}
 n:=binary.BigEndian.Uint32(count[:])
 if n>MaxDevices{return nil,fmt.Errorf("device count %d exceeds bound %d",n,MaxDevices)}
 devices:=make([]Device,0,n)
 seen:=make(map[string]bool,int(n))
 for i:=uint32(0);i<n;i++ {
  var b [deviceDescriptorBytes]byte
  if _,err:=io.ReadFull(r,b[:]);err!=nil{return nil,fmt.Errorf("device %d truncated: %w",i,err)}
  path,err:=nulString(b[0:256]);if err!=nil{return nil,fmt.Errorf("device %d path: %w",i,err)}
  busid,err:=nulString(b[256:288]);if err!=nil{return nil,fmt.Errorf("device %d busid: %w",i,err)}
  if seen[busid]{return nil,fmt.Errorf("duplicate busid %q",busid)};seen[busid]=true
  count:=int(b[311]);if count>MaxInterfaces{return nil,fmt.Errorf("device %d excessive interfaces %d",i,count)}
  d:=Device{Path:path,BusID:busid,Busnum:binary.BigEndian.Uint32(b[288:292]),Devnum:binary.BigEndian.Uint32(b[292:296]),Speed:binary.BigEndian.Uint32(b[296:300]),Vendor:binary.BigEndian.Uint16(b[300:302]),Product:binary.BigEndian.Uint16(b[302:304]),BCDDevice:binary.BigEndian.Uint16(b[304:306]),Class:b[306],Subclass:b[307],Protocol:b[308],Configuration:b[309],NumConfigurations:b[310]}
  d.Interfaces=make([]Interface,0,count)
  for j:=0;j<count;j++ {
    var f [4]byte
    if _,err:=io.ReadFull(r,f[:]);err!=nil{return nil,fmt.Errorf("device %d interface %d truncated: %w",i,j,err)}
    if f[3]!=0{return nil,errors.New("interface reserved byte must be zero")}
    d.Interfaces=append(d.Interfaces,Interface{f[0],f[1],f[2]})
  }
  devices=append(devices,d)
 }
 return devices,nil
}
