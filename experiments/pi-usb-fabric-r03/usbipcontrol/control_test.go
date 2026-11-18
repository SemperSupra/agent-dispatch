package usbipcontrol

import (
 "bytes"
 "encoding/binary"
 "strings"
 "testing"
)

func golden(deviceCount uint32)([]byte) {
 b:=make([]byte,12)
 binary.BigEndian.PutUint16(b[:2],Version)
 binary.BigEndian.PutUint16(b[2:4],RepDevlist)
 binary.BigEndian.PutUint32(b[8:12],deviceCount)
 for i:=uint32(0);i<deviceCount;i++{
  d:=make([]byte,312)
  copy(d[:256],"/sys/devices/platform/synthetic")
  if i==0{copy(d[256:288],"1-2")}else{copy(d[256:288],"1-3")}
  binary.BigEndian.PutUint32(d[288:292],1)
  binary.BigEndian.PutUint32(d[292:296],i+1)
  binary.BigEndian.PutUint16(d[300:302],0x1d6b)
  binary.BigEndian.PutUint16(d[302:304],0x0104)
  d[311]=1
  b=append(b,d...)
  b=append(b,[]byte{3,1,1,0}...)
 }
 return b
}
func TestGoldenDeviceList(t *testing.T){
 devices,err:=ParseDevlistResponse(bytes.NewReader(golden(2)))
 if err!=nil{t.Fatal(err)}
 if len(devices)!=2||devices[0].BusID!="1-2"||devices[1].BusID!="1-3"||len(devices[0].Interfaces)!=1||devices[0].Interfaces[0].Class!=3 {t.Fatalf("unexpected decoded devices %+v",devices)}
}
func TestEmptyDevlist(t *testing.T){d,err:=ParseDevlistResponse(bytes.NewReader(golden(0)));if err!=nil||len(d)!=0{t.Fatalf("%v %+v",err,d)}}
func TestNegativeFrames(t *testing.T){
 good:=golden(1)
 cases:=map[string]func([]byte)[]byte{
  "empty":func(b []byte)[]byte{return nil},
  "shortheader":func(b []byte)[]byte{return b[:7]},
  "badversion":func(b []byte)[]byte{b[0]=0;return b},
  "badopcode":func(b []byte)[]byte{b[3]=0x03;return b},
  "errorstatus":func(b []byte)[]byte{b[7]=1;return b},
  "hugecount":func(b []byte)[]byte{binary.BigEndian.PutUint32(b[8:12],1000000);return b},
  "shortdevice":func(b []byte)[]byte{return b[:20]},
  "shortinterface":func(b []byte)[]byte{return b[:len(b)-2]},
  "tooManyInterfaces":func(b []byte)[]byte{b[12+311]=17;return b},
  "emptyBusID":func(b []byte)[]byte{clear(b[12+256:12+288]);return b},
  "nonzeroAfterNUL":func(b []byte)[]byte{b[12+256+5]=0x41;return b},
  "reservedInterface":func(b []byte)[]byte{b[len(b)-1]=1;return b},
 }
 for name,change:=range cases {t.Run(name,func(t *testing.T){
  b:=change(bytes.Clone(good));if _,err:=ParseDevlistResponse(bytes.NewReader(b));err==nil{t.Fatal("malformed USB/IP control response accepted")}
 })}
 b:=golden(2);copy(b[12+312+4+256:12+312+4+288],[]byte("1-2"))
 if _,err:=ParseDevlistResponse(bytes.NewReader(b));err==nil{t.Fatal("duplicate busid accepted")}
}
func TestRequests(t *testing.T){
 d,err:=EncodeRequest(ReqDevlist,"");if err!=nil||!bytes.Equal(d,[]byte{1,17,128,5,0,0,0,0}){t.Fatalf("%x %v",d,err)}
 b,err:=EncodeRequest(ReqImport,"1-2");if err!=nil||len(b)!=40||string(b[8:11])!="1-2" {t.Fatalf("%x %v",b,err)}
 for _,tc:=range []struct{op uint16;id string}{{1,""},{ReqDevlist,"1-2"},{ReqImport,""},{ReqImport,strings.Repeat("a",32)},{ReqImport,"a\x00b"}} {
  if _,err:=EncodeRequest(tc.op,tc.id);err==nil{t.Fatalf("accepted invalid request %#x %q",tc.op,tc.id)}
 }
}
func FuzzDevlistResponse(f *testing.F){
 f.Add(golden(0));f.Add(golden(1));f.Add([]byte{});f.Add([]byte{1,17,0,5})
 f.Fuzz(func(t *testing.T,blob []byte){
  if len(blob)>8192 {t.Skip()}
  devices,err:=ParseDevlistResponse(bytes.NewReader(blob))
  if err==nil && len(devices)>MaxDevices {t.Fatal("exceeded device maximum")}
 })
}
