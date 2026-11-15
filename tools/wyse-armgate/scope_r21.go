package armgate

import (
 "context"
 "crypto/sha256"
 "crypto/tls"
 "encoding/hex"
 "errors"
 "time"

 modeplan "github.com/SemperSupra/agent-dispatch/tools/wyse-modeplan/modeplan"
 planpermit "github.com/SemperSupra/agent-dispatch/tools/wyse-planpermit"
)

type Audience string
const (
 Human Audience = "HUMAN"
 Automation Audience = "AUTOMATION"
 Agent Audience = "AGENT"
)

// IssuerCapability is a policy grant supplied by an external trusted,
// versioned/approved grant registry. Caller-provided or permit-provided
// grants are NOT trusted. This type does not manage issuance or revocation.
type IssuerCapability struct {
 IssuerKeyID string
 ClientSPKISHA256 string
 Audience Audience
 Action string
 DeviceID string
 TargetProfile modeplan.Profile
 ApprovedChangeID string
 PlanIntentSHA256 string
 NotBeforeUnix int64
 ExpiresUnix int64
}

func knownAudience(a Audience)bool{return a==Human||a==Automation||a==Agent}

func verifiedSPKI(s tls.ConnectionState)(string,error){
 if !s.HandshakeComplete||s.Version!=tls.VersionTLS13||
    len(s.PeerCertificates)==0||len(s.VerifiedChains)==0||len(s.VerifiedChains[0])==0 {
  return "",errors.New("verified mutual TLS 1.3 client chain required")
 }
 leaf:=s.PeerCertificates[0]
 if leaf==nil||s.VerifiedChains[0][0]==nil||len(leaf.Raw)==0||
    string(leaf.Raw)!=string(s.VerifiedChains[0][0].Raw){
  return "",errors.New("peer certificate differs from verified TLS chain")
 }
 if len(leaf.RawSubjectPublicKeyInfo)==0{return "",errors.New("missing client public key")}
 digest:=sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
 return hex.EncodeToString(digest[:]),nil
}

// AuthorizeTLSScopedArm is a PURE state transition. It requires a verified
// mTLS peer and an independently authorized issuer grant for this exact
// approval, device, profile, action, signer and human/automation/agent role.
// No server, cert authority, operator policy signer, persistence, UEFI,
// TPM or physical disk mutation is provided.
func AuthorizeTLSScopedArm(
 ctx context.Context,n modeplan.Node,p modeplan.Plan,
 permit planpermit.Permit, verifier *planpermit.Verifier,
 store planpermit.NonceStore, now time.Time,
 state tls.ConnectionState, audience Audience, grant IssuerCapability,
)(modeplan.Plan,error){
 peerID,err:=verifiedSPKI(state)
 if err!=nil{return p,err}
 if !knownAudience(audience)||!knownAudience(grant.Audience)||audience!=grant.Audience {
  return p,errors.New("principal audience denied")
 }
 if grant.NotBeforeUnix<=0||grant.ExpiresUnix<=grant.NotBeforeUnix||
    now.Unix()<grant.NotBeforeUnix||now.Unix()>=grant.ExpiresUnix {
  return p,errors.New("issuer capability grant not current")
 }
 if grant.ClientSPKISHA256!=peerID||grant.IssuerKeyID==""||
    grant.IssuerKeyID!=permit.KeyID||grant.DeviceID!=p.DeviceID||
    grant.PlanIntentSHA256==""||grant.PlanIntentSHA256!=p.IntentSHA256||
    grant.ApprovedChangeID==""||grant.ApprovedChangeID!=p.ApprovedChangeID||
    grant.TargetProfile!=p.TargetProfile||grant.Action!="HOST_INSTALL" {
  return p,errors.New("mTLS principal or issuer capability out of scope")
 }
 // External trust boundary: grant must originate from a versioned,
 // authenticated, non-client-controlled policy source. This routine only
 // checks its exact supplied scope and delegates cryptographic anti-replay.
 return AuthorizeSyntheticArm(ctx,n,p,permit,verifier,store,now)
}
