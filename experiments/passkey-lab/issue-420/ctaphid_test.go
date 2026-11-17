package ctaphid
import(
 "bytes"
 "errors"
 "testing"
)
func TestCTAPHIDRoundtripAcrossBoundaries(t *testing.T){
 for _,n:=range []int{0,1,56,57,58,59,116,117,118,1024,MaxMessage}{
  payload:=bytes.Repeat([]byte{0x5a},n)
  frames,e:=Encode(Message{CID:0x01020304,Command:CmdCbor,Payload:payload})
  if e!=nil{t.Fatalf("len %d: %v",n,e)}
  for i,r:=range frames{
   if len(r)!=ReportSize{t.Fatalf("invalid report width %d",i)}
  }
  round,e:=Decode(frames)
  if e!=nil || round.CID!=0x01020304 || round.Command!=CmdCbor || !bytes.Equal(round.Payload,payload){
   t.Fatalf("len %d, frames %d, decoded %+v: %v",n,len(frames),round,e)
  }
 }
 t.Log("PASSKEY_R1_CTAPHID_HID_REPORT_BOUNDARIES_AND_MAX_PAYLOAD=PASS")
}
func TestWrongCIDSequenceAndIncompleteFailClosed(t *testing.T){
 frames,e:=Encode(Message{CID:0x10203040,Command:CmdCbor,Payload:bytes.Repeat([]byte{1},140)})
 if e!=nil || len(frames)!=3{t.Fatal(e)}
 mutated:=append([][ReportSize]byte(nil),frames...)
 mutated[1][3]^=1
 if _,e=Decode(mutated);!errors.Is(e,ErrChannel){t.Fatalf("wrong CID accepted: %v",e)}
 mutated=append([][ReportSize]byte(nil),frames...)
 mutated[1][4]=127
 if _,e=Decode(mutated);!errors.Is(e,ErrSequence){t.Fatalf("wrong sequence accepted: %v",e)}
 if _,e=Decode(frames[:2]);!errors.Is(e,ErrLength){t.Fatalf("truncation accepted: %v",e)}
 mutated=append([][ReportSize]byte(nil),frames...)
 mutated=append(mutated,[ReportSize]byte{})
 if _,e=Decode(mutated);!errors.Is(e,ErrLength){t.Fatalf("extra packet accepted: %v",e)}
 t.Log("PASSKEY_R1_CTAPHID_WRONG_CID_SEQUENCE_TRUNCATED_OR_EXTRA=DENIED")
}
func TestInvalidInputRejected(t *testing.T){
 if _,e:=Encode(Message{CID:1,Command:0x55});!errors.Is(e,ErrFrame){t.Fatal("unknown command accepted")}
 if _,e:=Encode(Message{CID:0,Command:CmdInit});!errors.Is(e,ErrLength){t.Fatal("CID=0 accepted")}
 if _,e:=Encode(Message{CID:1,Command:CmdCbor,Payload:make([]byte,MaxMessage+1)});!errors.Is(e,ErrLength){t.Fatal("oversize accepted")}
 if _,e:=Decode(nil);!errors.Is(e,ErrLength){t.Fatal("empty frames accepted")}
 t.Log("PASSKEY_R1_CTAPHID_INVALID_COMMAND_CHANNEL_LENGTH=DENIED")
}
