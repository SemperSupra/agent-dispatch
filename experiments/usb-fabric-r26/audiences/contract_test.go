package audiences

import (
 "encoding/json"
 "errors"
 "testing"
)

func principal(a Audience)Principal{
 return Principal{
  Subject:"synthetic-"+string(a),Audience:a,
  Permissions:map[Operation]bool{
   Discover:true,Reserve:true,Attach:true,Input:true,Revoke:true,
   StartCapture:true,Watch:true,
  },
  GuestScopes:map[string]bool{"synthetic-linux":true},
 }
}
func TestAudienceParity(t *testing.T){
 req:=Request{Action:Input,GuestID:"synthetic-linux",
  DeviceID:"synthetic-kbd",PortID:"xhci0/1",
  LeaseEpoch:"synthetic-epoch",LeaseGeneration:3,
  IdempotencyKey:"op-001",InputKind:"key-a-down"}
 for _,a:=range []Audience{Human,Automation,Agent}{
  p:=principal(a)
  if err:=Validate(p,req);err!=nil{t.Fatalf("%s parity: %v",a,err)}
  b,err:=json.Marshal(req);if err!=nil{t.Fatal(err)}
  var again Request
  if err=json.Unmarshal(b,&again);err!=nil || again!=req{t.Fatalf("%s wire mismatch %v",a,err)}
 }
}
func TestNoRawQMPOrUnauthenticatedCapture(t *testing.T){
 p:=principal(Agent)
 req:=Request{Action:Input,GuestID:"synthetic-linux",
  DeviceID:"synthetic-kbd",PortID:"xhci0/1",LeaseEpoch:"epoch",LeaseGeneration:1,
  IdempotencyKey:"op-002",InputKind:"raw-qmp"}
 if e:=Validate(p,req);!errors.Is(e,ErrDenied){t.Fatalf("raw QMP allowed %v",e)}
 req.Action=StartCapture;req.CaptureMode="payload"
 if e:=Validate(p,req);!errors.Is(e,ErrDenied){t.Fatalf("unapproved payload capture allowed %v",e)}
 req.CaptureMode="metadata"
 if e:=Validate(p,req);e!=nil{t.Fatal(e)}
}
func TestScopeEpochAndIdempotencyRequired(t *testing.T){
 p:=principal(Human)
 req:=Request{Action:Attach,GuestID:"synthetic-linux",DeviceID:"kbd",
  PortID:"xhci0/1",LeaseEpoch:"epoch",LeaseGeneration:2,
  IdempotencyKey:"id-1"}
 if e:=Validate(p,req);e!=nil{t.Fatal(e)}
 bad:=req;bad.GuestID="untrusted-guest"
 if e:=Validate(p,bad);!errors.Is(e,ErrDenied){t.Fatal("cross-guest allowed")}
 bad=req;bad.LeaseEpoch=""
 if e:=Validate(p,bad);!errors.Is(e,ErrDenied){t.Fatal("epoch absent")}
 bad=req;bad.IdempotencyKey=""
 if e:=Validate(p,bad);!errors.Is(e,ErrDenied){t.Fatal("non-idempotent write")}
 p.Permissions[Attach]=false
 if e:=Validate(p,req);!errors.Is(e,ErrDenied){t.Fatal("permission bypass")}
}
func TestReceiptStagesDistinct(t *testing.T){
 if GuestConfirmed==Completed || Requested==Admitted || Failed==Quarantined {
  t.Fatal("observations and accepted operation state collapsed")
 }
 receipt:=Receipt{OperationID:"test-1",State:GuestConfirmed,
  PolicyDecision:"admitted",DesiredState:"attached",
  ObservedState:"usb-keyboard/evdev",EvidenceRefs:[]string{"synthetic-log-sha"}}
 b,e:=json.Marshal(receipt);if e!=nil{t.Fatal(e)}
 var copy Receipt
 if e=json.Unmarshal(b,&copy);e!=nil{t.Fatal(e)}
 if copy.State!=GuestConfirmed || len(copy.EvidenceRefs)!=1{t.Fatal("lost guest evidence")}
}
