// Package armgate authenticates machine-independent Wyse admission policy.
// This file adds signed issuer-grant provenance. It is NOT a signer service,
// production registry, trusted monotonic clock, disk actuator or HIL evidence.
package armgate

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "crypto/tls"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "time"

 modeplan "github.com/SemperSupra/agent-dispatch/tools/wyse-modeplan/modeplan"
 planpermit "github.com/SemperSupra/agent-dispatch/tools/wyse-planpermit"
)

const GrantPolicySchema = "wyse-issuer-grants/v1"
const grantPolicyDomain = "WYSE-ISSUER-GRANT-POLICY/v1\x00"

// GrantBundle is a signed snapshot of independently approved authorizations.
// Roots are NOT supplied by this bundle. Bundles can revoke a permit issuer
// even when the issuer's Ed25519 permit signature remains cryptographically
// valid, and an epoch witness rejects old signed bundle replay.
type GrantBundle struct {
 Schema string `json:"schema"`
 PolicyID string `json:"policy_id"`
 Epoch uint64 `json:"epoch"`
 RootKeyID string `json:"root_key_id"`
 NotBeforeUnix int64 `json:"not_before_unix"`
 ExpiresUnix int64 `json:"expires_unix"`
 RevokedIssuerKeyIDs []string `json:"revoked_issuer_key_ids"`
 Grants []IssuerCapability `json:"grants"`
 Signature []byte `json:"signature"`
}

// PolicyEpochWitness MUST be independent, durable, atomic and outside the
// replay domain. The same epoch and SAME digest is okay, but a lower epoch
// or same-epoch different digest MUST be refused. A local test double alone
// does not establish the durable property.
type PolicyEpochWitness interface {
 AdmitPolicyVersion(context.Context,string,uint64,string)error
}

type GrantRootVerifier struct{ keys map[string]ed25519.PublicKey }
func NewGrantRootVerifier(keys map[string]ed25519.PublicKey)(*GrantRootVerifier,error){
 if len(keys)==0{return nil,errors.New("no trusted policy signing root")}
 out:=make(map[string]ed25519.PublicKey,len(keys))
 for id,key:=range keys{
  if id==""||len(id)>64||len(key)!=ed25519.PublicKeySize{return nil,errors.New("invalid trusted root")}
  out[id]=append(ed25519.PublicKey(nil),key...)
 }
 return &GrantRootVerifier{keys:out},nil
}
func grantPolicyBody(b GrantBundle)([]byte,error){
 if b.Schema!=GrantPolicySchema||b.PolicyID==""||len(b.PolicyID)>128||
    b.Epoch==0||b.RootKeyID==""||len(b.RootKeyID)>64||
    b.NotBeforeUnix<=0||b.ExpiresUnix<=b.NotBeforeUnix||
    b.ExpiresUnix-b.NotBeforeUnix>24*60*60||
    len(b.Grants)==0||len(b.Grants)>64||len(b.RevokedIssuerKeyIDs)>64 {
  return nil,errors.New("invalid issuer policy envelope")
 }
 for _,g:=range b.Grants{
  if !knownAudience(g.Audience)||g.IssuerKeyID==""||
     g.DeviceID==""||g.ClientSPKISHA256==""||g.Action!="HOST_INSTALL"||
     g.NotBeforeUnix<b.NotBeforeUnix||g.ExpiresUnix>b.ExpiresUnix||
     g.ExpiresUnix<=g.NotBeforeUnix {
   return nil,errors.New("invalid or unconstrained signed grant")
  }
 }
 for _,key:=range b.RevokedIssuerKeyIDs{if key==""{return nil,errors.New("empty revoked issuer")}}
 unsigned:=struct{
  Schema string
  PolicyID string
  Epoch uint64
  RootKeyID string
  NotBeforeUnix int64
  ExpiresUnix int64
  RevokedIssuerKeyIDs []string
  Grants []IssuerCapability
 }{b.Schema,b.PolicyID,b.Epoch,b.RootKeyID,b.NotBeforeUnix,b.ExpiresUnix,b.RevokedIssuerKeyIDs,b.Grants}
 payload,err:=json.Marshal(unsigned)
 if err!=nil{return nil,err}
 return append([]byte(grantPolicyDomain),payload...),nil
}
// SignGrantBundle is pure Ed25519 signing; possession of a private key does
// not convey registry/policy owner authorization. Use test ephemeral keys only.
func SignGrantBundle(key ed25519.PrivateKey,b GrantBundle)(GrantBundle,error){
 if len(key)!=ed25519.PrivateKeySize{return GrantBundle{},errors.New("invalid root signing key")}
 payload,err:=grantPolicyBody(b);if err!=nil{return GrantBundle{},err}
 b.Signature=ed25519.Sign(key,payload)
 return b,nil
}

// AuthorizeSignedGrantArm verifies issuer registry provenance and an external
// monotonic policy epoch BEFORE entering the already-qualified TLS-scoped
// signed one-use permit gate. This is purely a state transition, not a disk
// authorization or deployment of a trusted registry/epoch service.
func AuthorizeSignedGrantArm(
 ctx context.Context,n modeplan.Node,p modeplan.Plan,
 permit planpermit.Permit,permitVerifier *planpermit.Verifier,
 nonceStore planpermit.NonceStore,now time.Time,
 peer tls.ConnectionState,audience Audience,
 policy GrantBundle,roots *GrantRootVerifier,epochStore PolicyEpochWitness,
)(modeplan.Plan,error){
 if roots==nil||epochStore==nil{return p,errors.New("trusted root and external epoch witness required")}
 if err:=ctx.Err();err!=nil{return p,err}
 peerID,err:=verifiedSPKI(peer)
 if err!=nil{return p,err}
 payload,err:=grantPolicyBody(policy)
 if err!=nil{return p,err}
 if now.Unix()<policy.NotBeforeUnix||now.Unix()>=policy.ExpiresUnix{
  return p,errors.New("signed issuer policy expired or not yet valid")
 }
 trusted,ok:=roots.keys[policy.RootKeyID]
 if !ok||len(policy.Signature)!=ed25519.SignatureSize||
    !ed25519.Verify(trusted,payload,policy.Signature){
  return p,errors.New("untrusted or invalid issuer policy signature")
 }
 for _,revoked:=range policy.RevokedIssuerKeyIDs{
  if revoked==permit.KeyID{return p,errors.New("permit signer revoked by signed policy")}
 }
 var selected *IssuerCapability
 for i:=range policy.Grants{
  g:=&policy.Grants[i]
  if g.ClientSPKISHA256!=peerID||g.Audience!=audience||
     g.IssuerKeyID!=permit.KeyID||g.DeviceID!=p.DeviceID||
     g.ApprovedChangeID!=p.ApprovedChangeID||
     g.PlanIntentSHA256!=p.IntentSHA256||
     g.TargetProfile!=p.TargetProfile||g.Action!="HOST_INSTALL" {continue}
  if selected!=nil {return p,errors.New("ambiguous duplicate policy grants")}
  selected=g
 }
 if selected==nil{return p,errors.New("no exact signed grant for TLS principal")}
 dig:=sha256.Sum256(payload)
 digest:=hex.EncodeToString(dig[:])
 if err=epochStore.AdmitPolicyVersion(ctx,policy.PolicyID,policy.Epoch,digest);err!=nil{
  return p,fmt.Errorf("policy rollback/equivocation witness denied: %w",err)
 }
 // Reuse the same exact-scope TLS role and signed permit verification. Never
 // trust caller-supplied unverified grants or root keys at this call boundary.
 next,e:=AuthorizeTLSScopedArm(ctx,n,p,permit,permitVerifier,nonceStore,now,peer,audience,*selected)
 if e!=nil{return p,e}
 if !bytes.Equal([]byte(next.IntentSHA256),[]byte(p.IntentSHA256)){
  return p,errors.New("result changed immutable plan intent")
 }
 return next,nil
}
