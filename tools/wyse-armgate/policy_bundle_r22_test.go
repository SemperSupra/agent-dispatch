package armgate

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/tls"
 "errors"
 "sync"
 "testing"
 "time"

 modeplan "github.com/SemperSupra/agent-dispatch/tools/wyse-modeplan/modeplan"
)

type ephemeralPolicyEpoch struct{
 mu sync.Mutex
 versions map[string]struct{epoch uint64; digest string}
 unavailable bool
}
func(e *ephemeralPolicyEpoch)AdmitPolicyVersion(ctx context.Context,id string,epoch uint64,digest string)error{
 if err:=ctx.Err();err!=nil{return err}
 e.mu.Lock();defer e.mu.Unlock()
 if e.unavailable{return errors.New("external policy epoch witness offline")}
 if e.versions==nil{e.versions=map[string]struct{epoch uint64;digest string}{}}
 old,ok:=e.versions[id]
 if ok&&(epoch<old.epoch||epoch==old.epoch&&digest!=old.digest){
  return errors.New("policy epoch rollback or equivocation")
 }
 if !ok||epoch>old.epoch{e.versions[id]=struct{epoch uint64;digest string}{epoch,digest}}
 return nil
}
func signedBundleFixture(t *testing.T)(modeplan.Node,modeplan.Plan,
 tls.ConnectionState,Audience,GrantBundle,*GrantRootVerifier,
 *ephemeralPolicyEpoch,time.Time,ed25519.PrivateKey){
 t.Helper()
 n,p,peer,grant,audience,now:=scopedFixture(t)
 _,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 roots,err:=NewGrantRootVerifier(map[string]ed25519.PublicKey{"policy-root-01":private.Public().(ed25519.PublicKey)})
 if err!=nil{t.Fatal(err)}
 bundle:=GrantBundle{Schema:GrantPolicySchema,PolicyID:"wyse-test-controller-policy",Epoch:10,
  RootKeyID:"policy-root-01",NotBeforeUnix:now.Add(-time.Minute).Unix(),ExpiresUnix:now.Add(time.Minute).Unix(),
  Grants:[]IssuerCapability{grant},
 }
 bundle,err=SignGrantBundle(private,bundle);if err!=nil{t.Fatal(err)}
 return n,p,peer,audience,bundle,roots,&ephemeralPolicyEpoch{},now,private
}
func TestR22SignedGrantProvenanceControlsAllAudiences(t *testing.T){
 n,p,peer,audience,bundle,roots,witness,now,key:=signedBundleFixture(t)
 _,_,token,verifier,_:=prepared(t)
 for _,role:=range []Audience{Human,Automation,Agent}{
  t.Run(string(role),func(t *testing.T){
   selected:=bundle
   selected.Grants=append([]IssuerCapability(nil),bundle.Grants...)
   selected.Grants[0].Audience=role
   var err error;selected,err=SignGrantBundle(key,selected);if err!=nil{t.Fatal(err)}
   // One signed version can authorize different roles; only the digest
   // of that SAME version may be replayed. Keep one epoch witness per
   // independent policy source in this role-positive unit test.
   next,err:=AuthorizeSignedGrantArm(context.Background(),n,p,token,verifier,&oneUse{},now,
    peer,role,selected,roots,&ephemeralPolicyEpoch{})
   if err!=nil||next.Stage!=modeplan.Armed{t.Fatalf("signed grant denied role: %v",err)}
  })
 }
 _=audience;_=witness
}
func TestR22GrantTamperRevocationAndPolicyRollbackRejectedBeforeNonce(t *testing.T){
 n,p,peer,audience,bundle,roots,witness,now,key:=signedBundleFixture(t)
 _,_,token,verifier,_:=prepared(t)
 for _,tc:=range []struct{name string; mutate func(*GrantBundle)}{
  {"forged-grant",func(b *GrantBundle){b.Grants[0].DeviceID="attacker-device"}},
  {"forged-audience",func(b *GrantBundle){b.Grants[0].Audience=Agent}},
  {"forged-expiry",func(b *GrantBundle){b.ExpiresUnix+=60}},
  {"wrong-policy-keyid",func(b *GrantBundle){b.RootKeyID="unknown-root"}},
  {"unknown-signature",func(b *GrantBundle){b.Signature[0]^=1}},
  {"future-policy",func(b *GrantBundle){b.NotBeforeUnix=now.Add(time.Minute).Unix()}},
 }{
  t.Run(tc.name,func(t *testing.T){
   changed:=bundle
   changed.Grants=append([]IssuerCapability(nil),bundle.Grants...)
   changed.Signature=append([]byte(nil),bundle.Signature...)
   tc.mutate(&changed)
   ledger:=&oneUse{}
   if _,err:=AuthorizeSignedGrantArm(context.Background(),n,p,token,verifier,ledger,now,
    peer,audience,changed,roots,&ephemeralPolicyEpoch{});err==nil{t.Fatal("unsigned/invalid policy admitted")}
   if len(ledger.used)>0{t.Fatal("invalid policy consumed permit nonce")}
  })
 }
 // A signed revocation overrides a still-valid existing permit signature.
 revoked:=bundle
 revoked.RevokedIssuerKeyIDs=[]string{token.KeyID}
 revoked.Epoch=11
 var err error;revoked,err=SignGrantBundle(key,revoked);if err!=nil{t.Fatal(err)}
 ledger:=&oneUse{}
 if _,err:=AuthorizeSignedGrantArm(context.Background(),n,p,token,verifier,ledger,now,
  peer,audience,revoked,roots,witness);err==nil{t.Fatal("revoked issuer accepted")}
 if len(ledger.used)>0{t.Fatal("revoked issuer spent nonce")}
 // Admit newer version first, then prove an older signed version cannot
 // be replayed (and same-epoch conflicting content fails).
 newer:=bundle
 newer.Epoch=12
 newer,err=SignGrantBundle(key,newer);if err!=nil{t.Fatal(err)}
 if err=witness.AdmitPolicyVersion(context.Background(),newer.PolicyID,newer.Epoch,"newer-digest");err!=nil{t.Fatal(err)}
 ledger=&oneUse{}
 if _,err:=AuthorizeSignedGrantArm(context.Background(),n,p,token,verifier,ledger,now,
  peer,audience,bundle,roots,witness);err==nil{t.Fatal("signed policy downgrade accepted")}
 if len(ledger.used)>0{t.Fatal("downgrade spent nonce")}
 if err=witness.AdmitPolicyVersion(context.Background(),newer.PolicyID,12,"different-digest");err==nil{
  t.Fatal("same-epoch equivocation accepted")
 }
 // Offline epoch fence is fail-closed; old signed grants are not trusted.
 offline:=&ephemeralPolicyEpoch{unavailable:true}
 if _,err:=AuthorizeSignedGrantArm(context.Background(),n,p,token,verifier,&oneUse{},now,
  peer,audience,bundle,roots,offline);err==nil{t.Fatal("unavailable witness accepted")}
}
func TestR22TrustedPolicyRootRotationIsExplicit(t *testing.T){
 n,p,peer,audience,bundle,_,_,now,_:=signedBundleFixture(t)
 _,_,token,verifier,_:=prepared(t)
 other,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 rotated,err:=NewGrantRootVerifier(map[string]ed25519.PublicKey{"policy-root-02":other})
 if err!=nil{t.Fatal(err)}
 if _,err:=AuthorizeSignedGrantArm(context.Background(),n,p,token,verifier,&oneUse{},now,
  peer,audience,bundle,rotated,&ephemeralPolicyEpoch{});err==nil{t.Fatal("removed root admitted")}
 changed:=bundle;changed.RootKeyID="policy-root-02"
 changed,err=SignGrantBundle(priv,changed);if err!=nil{t.Fatal(err)}
 if _,err:=AuthorizeSignedGrantArm(context.Background(),n,p,token,verifier,&oneUse{},now,
  peer,audience,changed,rotated,&ephemeralPolicyEpoch{});err!=nil{t.Fatalf("new trusted root denied: %v",err)}
}
