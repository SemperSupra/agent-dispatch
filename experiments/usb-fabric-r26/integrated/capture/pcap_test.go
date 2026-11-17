package capture

import (
 "encoding/binary"
 "encoding/json"
 "testing"
 "strings"
)

func header(bo binary.ByteOrder)[]byte{
 b:=make([]byte,24)
 bo.PutUint32(b[:4],0xa1b2c3d4)
 bo.PutUint16(b[4:6],2);bo.PutUint16(b[6:8],4)
 bo.PutUint32(b[16:20],4160)
 bo.PutUint32(b[20:24],220)
 return b
}
func record(bo binary.ByteOrder, ts uint32, event byte, transfer byte,endpoint byte,id uint64,payload []byte)[]byte{
 b:=make([]byte,16+64+len(payload))
 bo.PutUint32(b[0:4],ts);bo.PutUint32(b[4:8],100)
 bo.PutUint32(b[8:12],uint32(64+len(payload)))
 bo.PutUint32(b[12:16],uint32(64+len(payload)))
 p:=b[16:]
 bo.PutUint64(p[0:8],id)
 p[8]=event;p[9]=transfer;p[10]=endpoint;p[11]=1
 bo.PutUint16(p[12:14],1)
 p[14]='-';p[15]='='
 bo.PutUint32(p[32:36],uint32(len(payload)))
 bo.PutUint32(p[36:40],uint32(64+len(payload)))
 copy(p[64:],payload)
 return b
}
func goodFixture(bo binary.ByteOrder)[]byte{
 b:=header(bo)
 b=append(b,record(bo,1,'S',1,0x81,101,nil)...)
 b=append(b,record(bo,2,'C',1,0x81,101,[]byte{0,0,4,0,0,0,0,0})...)
 b=append(b,record(bo,3,'S',1,0x81,102,nil)...)
 b=append(b,record(bo,4,'C',1,0x81,102,[]byte{0,0,0,0,0,0,0,0})...)
 return b
}
func TestSyntheticHIDPressReleaseAndPairing(t *testing.T){
 for _,bo:=range []binary.ByteOrder{binary.LittleEndian,binary.BigEndian}{
  got,e:=Decode(goodFixture(bo));if e!=nil{t.Fatal(e)}
  if got.Records!=4 || got.MatchedURBs!=2 || got.KeyAPresses!=1 || got.KeyAReleases!=1 || got.HIDReports!=2 {t.Fatalf("unexpected USB decoding: %+v",got)}
  if got.LinkType!=220 || got.Status["0"]!=4 || got.Events["S"]!=2 || got.Events["C"]!=2 {t.Fatalf("wrong USB metadata %+v",got)}
  wire,_:=json.Marshal(got)
  if strings.Contains(string(wire),"payload") && !strings.Contains(string(wire),"\"payload_exported\":false") {t.Fatal("unexpected payload leak")}
 }
}
func TestTruncatedRecordDenied(t *testing.T){
 b:=goodFixture(binary.LittleEndian)
 _,e:=Decode(b[:len(b)-5]);if e==nil{t.Fatal("truncated record accepted")}
}
func TestWrongLinktypeDenied(t *testing.T){
 b:=goodFixture(binary.LittleEndian)
 binary.LittleEndian.PutUint32(b[20:24],1)
 if _,e:=Decode(b);e==nil{t.Fatal("Ethernet PCAP wrongly parsed as USB")}
}
func TestOrphanCompletionReported(t *testing.T){
 bo:=binary.LittleEndian
 b:=append(header(bo),record(bo,1,'C',1,0x81,18,[]byte{0,0,0,0,0,0,0,0})...)
 got,e:=Decode(b);if e!=nil{t.Fatal(e)}
 if got.OrphanCompletions!=1{t.Fatalf("lost unmatched marker: %+v",got)}
}
func TestControlSetupClassification(t *testing.T){
 bo:=binary.LittleEndian
 b:=append(header(bo),record(bo,1,'S',2,0x80,0,nil)...)
 b[24+16+14]=0
 b[24+16+41]=6
 got,e:=Decode(b);if e!=nil{t.Fatal(e)}
 if got.Controls["GET_DESCRIPTOR"]!=1 {t.Fatalf("lost setup classification %+v",got.Controls)}
}
func TestMismatchedURBEndpointDenied(t *testing.T){
 bo:=binary.LittleEndian
 b:=header(bo)
 b=append(b,record(bo,1,'S',1,0x81,37,nil)...)
 b=append(b,record(bo,2,'C',1,0x82,37,nil)...)
 if _,e:=Decode(b);e==nil{t.Fatal("identity mismatch accepted")}
}
func TestRepeatedSameURBSubmitIsNAKRetry(t *testing.T){
 bo:=binary.LittleEndian
 b:=header(bo)
 b=append(b,record(bo,1,'S',1,0x81,37,nil)...)
 b=append(b,record(bo,2,'S',1,0x81,37,nil)...)
 b=append(b,record(bo,3,'C',1,0x81,37,[]byte{0,0,0,0,0,0,0,0})...)
 got,e:=Decode(b);if e!=nil{t.Fatal(e)}
 if got.RepeatedSubmits!=1 || got.MatchedURBs!=1 || got.UnmatchedSubmits!=0 {
  t.Fatalf("NAK retry not modeled %+v",got)
 }
}
func TestConflictingInFlightURBDenied(t *testing.T){
 bo:=binary.LittleEndian
 b:=header(bo)
 b=append(b,record(bo,1,'S',1,0x81,37,nil)...)
 b=append(b,record(bo,2,'S',1,0x82,37,nil)...)
 if _,e:=Decode(b);e==nil{t.Fatal("conflicting outstanding URB accepted")}
}
