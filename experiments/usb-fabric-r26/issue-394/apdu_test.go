package card

import ("errors";"testing")
func TestVirtualCACReadOnlyPolicy(t *testing.T){
 aid:=[]byte{0xa0,0x00,0x00,0x01,0x16}
 real:=Policy{Card:GovernmentCAC,Read:true,Write:true,TestAID:aid}
 if e:=real.Permit(INSSelect,aid);e!=nil{t.Fatal(e)}
 if e:=real.Permit(INSReadBinary,aid);e!=nil{t.Fatal(e)}
 if _,e:=UpdateBinary(real,aid,0,[]byte("test"));!errors.Is(e,ErrDenied){t.Fatal("official CAC write unexpectedly permitted")}
}
func TestSyntheticWritableApplet(t *testing.T){
 aid:=[]byte{0xf0,0x00,0x00,0x01,0x23}
 p:=Policy{Card:TestCard,Read:true,Write:true,TestAID:aid}
 selectApdu,e:=SelectAID(aid);if e!=nil||selectApdu[1]!=INSSelect{t.Fatal(e)}
 read:=ReadBinary(10,16);if read[1]!=INSReadBinary||read[3]!=10{t.Fatal("read APDU encoding")}
 write,e:=UpdateBinary(p,aid,11,[]byte("TEST ONLY"))
 if e!=nil||write[1]!=INSUpdateBinary||write[3]!=11{t.Fatal(e)}
 if _,e=UpdateBinary(p,[]byte{1,2,3,4,5},0,[]byte("mismatch"));!errors.Is(e,ErrDenied){t.Fatal("wrong test AID allowed")}
}
func TestAPDUResponseStatusNoSensitiveData(t *testing.T){
 good,e:=ParseResponse([]byte{1,2,3,0x90,0x00})
 if e!=nil||!good.Success||good.DataLength!=3{t.Fatal(e)}
 for _,tc:=range []struct{frame []byte;expected string}{
  {[]byte{0x69,0x82},"security-status-not-satisfied"},
  {[]byte{0x6A,0x82},"file-not-found"},
  {[]byte{0x63,0xc2},"verification-failed"},
 }{
  r,e:=ParseResponse(tc.frame);if e!=nil||r.Success||r.Diagnostic!=tc.expected{t.Fatalf("%v %v",r,e)}
 }
 if _,e=ParseResponse([]byte{0x90});!errors.Is(e,ErrMalformed){t.Fatal("truncated APDU response accepted")}
}
func TestGenericAPDUAndUnboundedPayloadRejected(t *testing.T){
 p:=Policy{Card:TestCard,Read:true,Write:true,TestAID:[]byte{1,2,3,4,5}}
 if e:=p.Permit(0x20,p.TestAID);!errors.Is(e,ErrDenied){t.Fatal("VERIFY PIN operation admitted")}
 if _,e:=UpdateBinary(p,p.TestAID,0,make([]byte,256));!errors.Is(e,ErrMalformed){t.Fatal("oversized APDU accepted")}
}
