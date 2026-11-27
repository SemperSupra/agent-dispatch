package proof
import ("strings";"testing")
func goodReceipt()Receipt{
 r:=Receipt{Schema:"public-guest-service-rdte/v1",Classification:"PUBLIC_SYNTHETIC_SERVICE_GUEST_ONLY",RunID:"12345",SourceSHA:strings.Repeat("a",40),Runner:"windows-2025",
  OfficialISOHashMatched:true,WimlibHashMatched:true,ExactOwnedDisk:true,EFINTFSFormatted:true,WindowsImageApplied:true,
  UEFIBoot:true,OwnedVM:true,GuestStarted:true,GuestHeartbeat:true,FirstLogon:true,PowerShellDirect:true,OOBEStaged:true,
  PublicBinaryPrepared:true,GuestServiceCleanup:true,CleanupComplete:true,ServiceBinarySHA:strings.Repeat("b",64)}
 r.Events=events()
 return r
}
func TestQualifiedReceipt(t *testing.T){r:=goodReceipt();if e:=VerifyReceipt(r,"12345",r.SourceSHA);e!=nil{t.Fatal(e)}}
func TestFailClosedFields(t *testing.T){
 switches:=[]struct{name string;change func(*Receipt)}{
  {"source",func(r *Receipt){r.SourceSHA=strings.Repeat("f",40)}},
  {"run",func(r *Receipt){r.RunID="999"}},
  {"service-hash",func(r *Receipt){r.ServiceBinarySHA="not-a-digest"}},
  {"iso",func(r *Receipt){r.OfficialISOHashMatched=false}},
  {"guest-not-booted",func(r *Receipt){r.GuestHeartbeat=false}},
  {"first-logon",func(r *Receipt){r.FirstLogon=false}},
  {"powershell-direct",func(r *Receipt){r.PowerShellDirect=false}},
  {"product-claim",func(r *Receipt){r.ProductInstalled=true}},
  {"guest-network",func(r *Receipt){r.GuestNetworkAttached=true}},
  {"guest-cleanup",func(r *Receipt){r.GuestServiceCleanup=false}},
  {"vm-cleanup",func(r *Receipt){r.CleanupComplete=false}},
  {"failure",func(r *Receipt){s:="fail";r.FirstFailure=&s}},
  {"service-failure",func(r *Receipt){s:="fail";r.GuestServiceFailure=&s}},
  {"missing-events",func(r *Receipt){r.Events=r.Events[:3]}},
  {"wrong-event",func(r *Receipt){r.Events[4].Success=false}},
 }
 for _,s:=range switches{t.Run(s.name,func(t *testing.T){r:=goodReceipt();s.change(&r);if e:=VerifyReceipt(r,"12345",strings.Repeat("a",40));e==nil{t.Fatal("invalid witness accepted")}})}
}
