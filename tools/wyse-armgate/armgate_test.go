package armgate

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "strings"
 "sync"
 "testing"
 "time"

 modeplan "github.com/SemperSupra/agent-dispatch/tools/wyse-modeplan/modeplan"
 planpermit "github.com/SemperSupra/agent-dispatch/tools/wyse-planpermit"
)

type oneUse struct {mu sync.Mutex;used map[string]bool}
func (x *oneUse)ConsumeOnce(ctx context.Context,key string)error{
 if err:=ctx.Err();err!=nil{return err}
 x.mu.Lock();defer x.mu.Unlock()
 if x.used==nil{x.used=map[string]bool{}}
 if x.used[key]{return errors.New("replayed permit")}
 x.used[key]=true
 return nil
}
func prepared(t *testing.T)(modeplan.Node,modeplan.Plan,planpermit.Permit,*planpermit.Verifier,time.Time){
 t.Helper()
 n:=modeplan.Node{ID:"synthetic-wyse-controller-node",Revision:19,Enrollment:modeplan.Enrolled,
  Presence:modeplan.Present,Admission:modeplan.Drained,Power:modeplan.PowerOn,Network:modeplan.LANSSHOnly,
  TrustVerified:true,RecoveryVerified:true,BackupCustodyVerified:true,HardwareNestedVerified:true,
  ObservedBoot:modeplan.RecoveryEMMC,GARMHold:true}
 p:=modeplan.Plan{DeviceID:n.ID,ExpectedRevision:n.Revision,
  TargetProfile:modeplan.DisposableHosted,TargetBoot:modeplan.HypervisorSSD,
  SSDDeviceIdentity:"synthetic-sata-identified-01",EMMCDeviceIdentity:"synthetic-emmc-identified-01",
  ArtifactSHA256:strings.Repeat("a",64),ArtifactSigned:true,RightToInstall:true,
  NestedRequirement:modeplan.NestedKVM,ApprovedChangeID:"synthetic-approved-change-01",SignedMutationGate:true,
  Stage:modeplan.Proposed}
 for _,phase:=range []modeplan.Stage{modeplan.Preflighted,modeplan.Staged,modeplan.Verified}{
  var fail []string;p,fail=modeplan.AdvanceInstall(n,p,phase);if len(fail)>0{t.Fatalf("%s: %v",phase,fail)}
 }
 if len(p.IntentSHA256)!=64{t.Fatal("intent not sealed")}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 v,err:=planpermit.NewVerifier(map[string]ed25519.PublicKey{"test-issuer-01":pub});if err!=nil{t.Fatal(err)}
 at:=time.Unix(1800000000,0)
 token:=planpermit.Permit{Schema:planpermit.Schema,KeyID:"test-issuer-01",Claims:planpermit.Claims{
  Target:planpermit.Target{DeviceID:p.DeviceID,Revision:p.ExpectedRevision,
   SSDByID:p.SSDDeviceIdentity,EMMCByID:p.EMMCDeviceIdentity,
   ArtifactSHA256:p.ArtifactSHA256,PlanIntentSHA256:p.IntentSHA256},
  Action:"HOST_INSTALL",Nonce:"synthetic-single-use-000123",IssuedAtUnix:at.Add(-time.Second).Unix(),
  ExpiresAtUnix:at.Add(time.Minute).Unix(),
 }}
 token,err=planpermit.Sign(priv,token);if err!=nil{t.Fatal(err)}
 return n,p,token,v,at
}
func TestExactPurePolicySignedPermitAndOneUseJoin(t *testing.T){
 n,p,token,verifier,now:=prepared(t)
 state:=&oneUse{}
 next,err:=AuthorizeSyntheticArm(context.Background(),n,p,token,verifier,state,now)
 if err!=nil||next.Stage!=modeplan.Armed||next.IntentSHA256!=p.IntentSHA256{t.Fatalf("valid exact synthetic approval failed: %v %v",next,err)}
 if !n.GARMHold{t.Fatal("synthetic test cleared GARM hold")}
 if _,err:=AuthorizeSyntheticArm(context.Background(),n,p,token,verifier,state,now);err==nil{t.Fatal("replayed signed permit admitted")}
}
func TestNoScopeRetargetAndOriginalAuthorizationDenial(t *testing.T){
 n,p,token,v,now:=prepared(t)
 for _,tc:=range []struct{name string;change func(*modeplan.Node,*modeplan.Plan)}{
  {"swap-disk",func(_ *modeplan.Node,p *modeplan.Plan){p.SSDDeviceIdentity=p.EMMCDeviceIdentity}},
  {"approval-id",func(_ *modeplan.Node,p *modeplan.Plan){p.ApprovedChangeID="other-approved-change"}},
  {"signed-bit",func(_ *modeplan.Node,p *modeplan.Plan){p.SignedMutationGate=false}},
  {"trust-revoked",func(n *modeplan.Node,_ *modeplan.Plan){n.TrustVerified=false}},
  {"wrong-device",func(n *modeplan.Node,_ *modeplan.Plan){n.ID="different-device"}},
  {"stale-revision",func(n *modeplan.Node,_ *modeplan.Plan){n.Revision++}},
  {"recovery-missing",func(n *modeplan.Node,_ *modeplan.Plan){n.RecoveryVerified=false}},
  {"offline",func(n *modeplan.Node,_ *modeplan.Plan){n.Presence=modeplan.Offline}},
  {"wrong-stage",func(_ *modeplan.Node,p *modeplan.Plan){p.Stage=modeplan.Staged}},
 }{
  t.Run(tc.name,func(t *testing.T){nn,pp:=n,p;tc.change(&nn,&pp)
   reservations:=&oneUse{}
   if _,err:=AuthorizeSyntheticArm(context.Background(),nn,pp,token,v,reservations,now);err==nil{t.Fatal("unsafe scope admitted")}
   if len(reservations.used)!=0{t.Fatal("nonce consumed for denied stage")}
  })
 }
}
func TestUnrelatedSignedPermitCannotArmAndDoesNotConsume(t *testing.T){
 n,p,token,v,now:=prepared(t)
 mutated:=token
 mutated.Claims.Target.SSDByID="synthetic-other-ssd"
 if _,err:=AuthorizeSyntheticArm(context.Background(),n,p,mutated,v,&oneUse{},now);err==nil{t.Fatal("wrong signed device binding admitted")}
 if _,err:=AuthorizeSyntheticArm(context.Background(),n,p,token,v,&oneUse{},now.Add(6*time.Minute));err==nil{t.Fatal("expired permit admitted")}
 if _,err:=AuthorizeSyntheticArm(context.Background(),n,p,token,v,nil,now);err==nil{t.Fatal("missing durable store accepted")}
}
